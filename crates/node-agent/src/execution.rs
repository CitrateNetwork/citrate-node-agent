//! `execution` — SELL-S2 job-execution orchestration.
//!
//! Composes the three SELL-S2 crates into one step the daemon runs for a won
//! job: read the job's on-chain state, and either run the executor
//! (provision → infer → prove) or emit the next unsigned write via the
//! [`lifecycle`] planner + the [`JobSigner`] seam. Driving is **one step per
//! call** — the daemon re-reads the chain between steps and calls again, so the
//! planner always reacts to fresh state.
//!
//! Ordering for a Commitment job (asserted end-to-end in the tests):
//! ```text
//! Assigned  → Sign(startExecution)
//! Executing → RunInference (provision+infer+proof, cache artifacts+nonce)
//! Executing → Sign(submitCommitment)        // commitment recorded, mark committed
//! Executing → Sign(submitResult)            // reveals output+nonce; verifies inline
//! Verifying → Sign(completeJob)             // releases payment
//! Completed → Done
//! ```
//!
//! No keys (ADR-agent-signing / TD-17): every write is an unsigned
//! [`lifecycle::SignatureRequest`] handed to the signer. The `committed` flag is
//! set optimistically once the commitment request is emitted; with the real
//! signing relay it would flip only after the broadcast is observed (the
//! broadcast/observe + relay is the cross-repo TD-17 follow-up).

use std::path::PathBuf;

use chainio::abi::Address;
use chainio::marketplace::{Job, JobState};
use executor::{provision, CommitmentProver, Inference, ProofMaker, WeightSource};
use lifecycle::{
    plan, AbortReason, CommitmentArtifacts, JobSigner, LifecycleAction, PlanInput, WriteIntent,
};
use supervision::SharedState;

/// Per-job state the daemon carries across steps (the planner needs it because
/// the on-chain `JobState` stays `Executing` across commitment → result).
#[derive(Debug, Default, Clone)]
pub struct JobProgress {
    /// Set once the `submitCommitment` request has been emitted.
    pub committed: bool,
    /// The executor's output for this job, once inference has run.
    pub artifacts: Option<CommitmentArtifacts>,
    /// The nonce committed for this job — kept stable across commitment → result.
    pub nonce: Option<[u8; 32]>,
}

/// Everything one step needs, resolved by the daemon from `getJob` + `getModel`
/// before the call.
pub struct JobContext {
    /// The job as freshly decoded from `getJob`.
    pub job: Job,
    /// The current chain head (block height) for the deadline guard.
    pub current_block: u128,
    /// The marketplace contract (the `to` of lifecycle writes).
    pub marketplace: Address,
    /// Chain id (40204).
    pub chain_id: u64,
    /// This provider's address.
    pub me: Address,
    /// The model's IPFS CID (from `ModelRegistry.getModel`).
    pub ipfs_cid: String,
    /// Whether the model is active (`getModel`).
    pub is_active: bool,
    /// The model size for the integrity cross-check, if known.
    pub expected_size: Option<u64>,
    /// The job input to run inference on.
    pub input: Vec<u8>,
    /// Where to cache provisioned weights.
    pub cache_dir: PathBuf,
}

/// What one [`drive_job`] step did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    /// Emitted an unsigned request for this write.
    Signed(WriteIntent),
    /// Provisioned + ran inference + built the proof this step.
    RanInference,
    /// Job reached terminal success.
    Done,
    /// Not our turn (Posted/Bidding, or the job isn't assigned to us).
    Idle,
    /// The job is ours + Executing but the off-chain input has not arrived yet
    /// (`Job.inputHash` is only a hash; the requester delivers the data
    /// off-chain). Hold and retry next tick.
    AwaitingInput,
    /// Job can't proceed (deadline/failed/expired/disputed/not-ours).
    Aborted(AbortReason),
    /// Provisioning / inference / signing errored this step (recorded, retryable).
    Error(String),
}

/// Drive one step of a won job. Updates `progress`, reflects the in-flight count
/// in `state`, and returns what happened.
///
/// `nonce_seed` is the daemon-supplied per-job nonce (unpredictable; generated
/// once when the job is first executed and stable thereafter via `progress.nonce`).
pub async fn drive_job<W, I, S>(
    ctx: &JobContext,
    progress: &mut JobProgress,
    state: &SharedState,
    weights: &W,
    inference: &I,
    signer: &S,
    nonce_seed: [u8; 32],
) -> StepOutcome
where
    W: WeightSource + Sync,
    I: Inference + Sync,
    S: JobSigner + Sync,
{
    let action = plan(&PlanInput {
        job: &ctx.job,
        me: ctx.me,
        current_block: ctx.current_block,
        marketplace: ctx.marketplace,
        chain_id: ctx.chain_id,
        committed: progress.committed,
        artifacts: progress.artifacts.as_ref(),
    });

    match action {
        LifecycleAction::RunInference => {
            state.write().await.set_active_jobs(1);
            let model = match provision(
                ctx.job.model_hash,
                &ctx.ipfs_cid,
                ctx.is_active,
                ctx.expected_size,
                &ctx.cache_dir,
                weights,
            )
            .await
            {
                Ok(m) => m,
                Err(e) => return record_error(state, format!("provision: {e}")).await,
            };
            let output = match inference.run(&model, &ctx.input).await {
                Ok(o) => o,
                Err(e) => return record_error(state, format!("inference: {e}")).await,
            };
            let nonce = progress.nonce.unwrap_or(nonce_seed);
            progress.nonce = Some(nonce);
            progress.artifacts = Some(CommitmentProver.build(&output.bytes, nonce));
            StepOutcome::RanInference
        }

        LifecycleAction::Sign(req) => {
            state.write().await.set_active_jobs(1);
            let intent = req.intent;
            match signer.request(req).await {
                Ok(_) => {
                    // Optimistic: the on-chain state stays Executing across
                    // commitment → result, so we track locally that we've sent it.
                    if intent == WriteIntent::SubmitCommitment {
                        progress.committed = true;
                    }
                    StepOutcome::Signed(intent)
                }
                Err(e) => record_error(state, format!("sign {}: {e}", intent.label())).await,
            }
        }

        LifecycleAction::Done => {
            state.write().await.set_active_jobs(0);
            StepOutcome::Done
        }
        LifecycleAction::Idle => StepOutcome::Idle,
        LifecycleAction::Abort(reason) => {
            // The job is off our plate; release the in-flight slot + surface why.
            let mut w = state.write().await;
            w.set_active_jobs(0);
            w.set_last_error(Some(format!("job {} aborted: {reason:?}", ctx.job.id)));
            StepOutcome::Aborted(reason)
        }
    }
}

async fn record_error(state: &SharedState, msg: String) -> StepOutcome {
    state.write().await.set_last_error(Some(msg.clone()));
    StepOutcome::Error(msg)
}

// ── live-loop integration ───────────────────────────────────────────────────

/// A job resolved from chain reads (everything the executor needs except the
/// off-chain input): the decoded job, its model location/activeness, an optional
/// size for the integrity cross-check, and the current chain head.
#[derive(Debug, Clone)]
pub struct ResolvedJob {
    pub job: Job,
    pub ipfs_cid: String,
    pub is_active: bool,
    pub expected_size: Option<u64>,
    pub current_block: u128,
}

/// Reads a job's on-chain state + model location. The live impl does
/// `getJob` + `getModel` + `eth_blockNumber`; tests fake it.
pub trait JobView {
    fn resolve(
        &self,
        job_id: u128,
    ) -> impl std::future::Future<Output = Result<ResolvedJob, String>> + Send;
}

/// Supplies a job's **off-chain** input. `Job.inputHash` is only a hash — the
/// actual input bytes are delivered to the assigned provider off-chain (by the
/// requester / gateway), so this is a distinct channel. Returns `None` when the
/// input hasn't arrived yet (the executor holds and retries).
pub trait InputSource {
    fn input_for(
        &self,
        job_id: u128,
    ) -> impl std::future::Future<Output = Result<Option<Vec<u8>>, String>> + Send;
}

/// Drives ONE configured job through its lifecycle, one step per [`tick`], by
/// composing a [`JobView`] + [`InputSource`] + the executor traits + a
/// [`JobSigner`]. Single-job MVP (TD-17: one `job_id`/tick; multi-job is a
/// follow-on). Holds the per-job progress (and the committed flag) across ticks.
pub struct JobExecutor<V, In, W, I, S> {
    /// The job this executor is responsible for.
    pub job_id: u128,
    /// This provider's address (drive only jobs assigned to us).
    pub me: Address,
    /// The marketplace contract (the `to` of lifecycle writes).
    pub marketplace: Address,
    /// Chain id (40204).
    pub chain_id: u64,
    /// Where to cache provisioned weights.
    pub cache_dir: PathBuf,
    /// The per-job commitment nonce (unpredictable; generated once at startup).
    pub nonce: [u8; 32],
    pub view: V,
    pub input: In,
    pub weights: W,
    pub inference: I,
    pub signer: S,
    /// Per-job state carried across ticks (commitment flag + cached artifacts).
    pub progress: tokio::sync::Mutex<JobProgress>,
}

impl<V, In, W, I, S> JobExecutor<V, In, W, I, S>
where
    V: JobView + Sync,
    In: InputSource + Sync,
    W: WeightSource + Sync,
    I: Inference + Sync,
    S: JobSigner + Sync,
{
    /// Resolve the configured job and advance it one step. Public for tests; the
    /// loop calls [`TickExecutor::tick`].
    pub async fn step(&self, state: &SharedState) -> StepOutcome {
        let resolved = match self.view.resolve(self.job_id).await {
            Ok(r) => r,
            Err(e) => return record_error(state, format!("resolve job {}: {e}", self.job_id)).await,
        };

        // Only drive jobs assigned to us; otherwise it's not our turn.
        if resolved.job.assigned_provider != self.me {
            return StepOutcome::Idle;
        }

        let mut progress = self.progress.lock().await;

        // The RunInference step needs the off-chain input; nothing else does. If
        // we're about to run inference and the input hasn't arrived, hold.
        let need_input = resolved.job.state == JobState::Executing && progress.artifacts.is_none();
        let input = if need_input {
            match self.input.input_for(self.job_id).await {
                Ok(Some(bytes)) => bytes,
                Ok(None) => return StepOutcome::AwaitingInput,
                Err(e) => {
                    return record_error(state, format!("input for job {}: {e}", self.job_id)).await
                }
            }
        } else {
            Vec::new() // unused for non-inference steps
        };

        let ctx = JobContext {
            job: resolved.job,
            current_block: resolved.current_block,
            marketplace: self.marketplace,
            chain_id: self.chain_id,
            me: self.me,
            ipfs_cid: resolved.ipfs_cid,
            is_active: resolved.is_active,
            expected_size: resolved.expected_size,
            input,
            cache_dir: self.cache_dir.clone(),
        };

        drive_job(
            &ctx,
            &mut progress,
            state,
            &self.weights,
            &self.inference,
            &self.signer,
            self.nonce,
        )
        .await
    }
}

/// A per-tick driver the loop runs after bidding. [`NoExecutor`] is the bid-only
/// no-op; [`JobExecutor`] drives a won job.
pub trait TickExecutor {
    fn tick(&self, state: &SharedState) -> impl std::future::Future<Output = ()> + Send;
}

/// No-op executor for the bid-only loop (no SELL-S2 job configured).
pub struct NoExecutor;

impl TickExecutor for NoExecutor {
    async fn tick(&self, _state: &SharedState) {}
}

impl<V, In, W, I, S> TickExecutor for JobExecutor<V, In, W, I, S>
where
    V: JobView + Sync,
    In: InputSource + Sync,
    W: WeightSource + Sync,
    I: Inference + Sync,
    S: JobSigner + Sync,
{
    async fn tick(&self, state: &SharedState) {
        // The outcome is already recorded into shared state (errors/aborts) and
        // the signer (emitted requests); a tick just advances one step.
        let _ = self.step(state).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chainio::marketplace::{JobState, VerificationTier};
    use executor::{InferenceError, InferenceOutput, ProvisionError, ProvisionedModel};
    use lifecycle::UnsignedJobSigner;
    use std::sync::Arc;
    use supervision::AgentState;
    use tokio::sync::RwLock;

    const ME: Address = [0xab; 20];
    const OTHER: Address = [0xcd; 20];
    const MARKETPLACE: Address = [0x11; 20];

    fn shared() -> SharedState {
        Arc::new(RwLock::new(AgentState::new()))
    }

    fn job(state: JobState) -> Job {
        Job {
            id: 7,
            requester: [0x01; 20],
            model_hash: [0x02; 32],
            max_price_wei: 4 * 10u128.pow(18),
            tier: VerificationTier::Commitment,
            state,
            assigned_provider: ME,
            escrow_wei: 4 * 10u128.pow(18),
            bid_deadline_block: 100,
            execution_deadline_block: 1_000,
            created_at_block: 50,
            bid_count: 1,
        }
    }

    /// `cache` names a per-test cache dir + the model hash, so parallel tests
    /// never share a cache file (a stray cache hit would mask a fetch failure).
    fn ctx(state: JobState, cache: &str) -> JobContext {
        let dir = std::env::temp_dir().join(format!("citrate-exec-drive-{cache}"));
        let _ = std::fs::remove_dir_all(&dir);
        let mut model_hash = [0x02; 32];
        model_hash[0] = cache.len() as u8; // distinct per test
        let mut j = job(state);
        j.model_hash = model_hash;
        JobContext {
            job: j,
            current_block: 200,
            marketplace: MARKETPLACE,
            chain_id: 40204,
            me: ME,
            ipfs_cid: "bafycid".into(),
            is_active: true,
            expected_size: Some(7),
            input: b"the prompt".to_vec(),
            cache_dir: dir,
        }
    }

    /// Fake weight source: serves 7 bytes (matches expected_size).
    struct Weights;
    impl WeightSource for Weights {
        async fn fetch(&self, _cid: &str) -> Result<Vec<u8>, ProvisionError> {
            Ok(b"weights".to_vec())
        }
    }

    /// Deterministic echo engine.
    struct Echo;
    impl Inference for Echo {
        async fn run(
            &self,
            _m: &ProvisionedModel,
            input: &[u8],
        ) -> Result<InferenceOutput, InferenceError> {
            let mut bytes = b"out:".to_vec();
            bytes.extend_from_slice(input);
            Ok(InferenceOutput { bytes })
        }
    }

    #[tokio::test]
    async fn drives_a_won_job_through_to_completion_in_order() {
        let state = shared();
        let signer = UnsignedJobSigner::new();
        let mut progress = JobProgress::default();
        let nonce = [0x42u8; 32];

        // 1. Assigned → startExecution.
        let mut c = ctx(JobState::Assigned, "complete");
        let o = drive_job(&c, &mut progress, &state, &Weights, &Echo, &signer, nonce).await;
        assert_eq!(o, StepOutcome::Signed(WriteIntent::StartExecution));

        // 2. Executing, no artifacts → run inference.
        c.job.state = JobState::Executing;
        let o = drive_job(&c, &mut progress, &state, &Weights, &Echo, &signer, nonce).await;
        assert_eq!(o, StepOutcome::RanInference);
        assert!(progress.artifacts.is_some());
        assert_eq!(progress.nonce, Some(nonce));
        // active_jobs is reflected while executing.
        assert_eq!(state.read().await.health_at(0).active_jobs, 1);

        // 3. Executing, artifacts, not committed → submitCommitment.
        let o = drive_job(&c, &mut progress, &state, &Weights, &Echo, &signer, nonce).await;
        assert_eq!(o, StepOutcome::Signed(WriteIntent::SubmitCommitment));
        assert!(progress.committed);

        // 4. Executing, committed → submitResult.
        let o = drive_job(&c, &mut progress, &state, &Weights, &Echo, &signer, nonce).await;
        assert_eq!(o, StepOutcome::Signed(WriteIntent::SubmitResult));

        // 5. Verifying → completeJob.
        c.job.state = JobState::Verifying;
        let o = drive_job(&c, &mut progress, &state, &Weights, &Echo, &signer, nonce).await;
        assert_eq!(o, StepOutcome::Signed(WriteIntent::CompleteJob));

        // 6. Completed → Done; slot released.
        c.job.state = JobState::Completed;
        let o = drive_job(&c, &mut progress, &state, &Weights, &Echo, &signer, nonce).await;
        assert_eq!(o, StepOutcome::Done);
        assert_eq!(state.read().await.health_at(0).active_jobs, 0);

        // The signer saw exactly the four writes, in order.
        let recorded = signer.recorded();
        let intents: Vec<_> = recorded.iter().map(|r| r.intent).collect();
        assert_eq!(
            intents,
            vec![
                WriteIntent::StartExecution,
                WriteIntent::SubmitCommitment,
                WriteIntent::SubmitResult,
                WriteIntent::CompleteJob,
            ]
        );

        // The submitResult carried the real proof artifacts.
        let art = progress.artifacts.unwrap();
        let result_req = recorded
            .iter()
            .find(|r| r.intent == WriteIntent::SubmitResult)
            .unwrap();
        assert_eq!(
            result_req.calldata,
            chainio::marketplace::encode_submit_result(7, &art.output_hash, &art.proof)
        );
    }

    #[tokio::test]
    async fn provision_failure_is_recorded_and_retryable() {
        struct FailWeights;
        impl WeightSource for FailWeights {
            async fn fetch(&self, _cid: &str) -> Result<Vec<u8>, ProvisionError> {
                Err(ProvisionError::Fetch("gateway down".into()))
            }
        }
        let state = shared();
        let signer = UnsignedJobSigner::new();
        let mut progress = JobProgress::default();
        let c = ctx(JobState::Executing, "failwrite");
        let o = drive_job(&c, &mut progress, &state, &FailWeights, &Echo, &signer, [0u8; 32]).await;
        match o {
            StepOutcome::Error(m) => assert!(m.contains("provision")),
            other => panic!("expected Error, got {other:?}"),
        }
        // No artifacts produced; the step can be retried next tick.
        assert!(progress.artifacts.is_none());
        assert!(signer.recorded().is_empty());
        assert!(state
            .read()
            .await
            .health_at(0)
            .last_error
            .unwrap()
            .contains("provision"));
    }

    #[tokio::test]
    async fn past_deadline_result_aborts_and_releases_slot() {
        let state = shared();
        let signer = UnsignedJobSigner::new();
        // Already committed + have artifacts, but the deadline has passed.
        let mut progress = JobProgress {
            committed: true,
            artifacts: Some(CommitmentProver.build(b"out", [0x1; 32])),
            nonce: Some([0x1; 32]),
        };
        let mut c = ctx(JobState::Executing, "deadline");
        c.current_block = 2_000; // > execution_deadline_block (1000)
        let o = drive_job(&c, &mut progress, &state, &Weights, &Echo, &signer, [0u8; 32]).await;
        assert_eq!(o, StepOutcome::Aborted(AbortReason::ExecutionDeadlinePassed));
        assert_eq!(state.read().await.health_at(0).active_jobs, 0);
        assert!(signer.recorded().is_empty());
    }

    // ── JobExecutor (live-loop orchestration) ───────────────────────────────

    fn resolved(state: JobState, assigned: Address) -> ResolvedJob {
        let mut j = job(state);
        j.assigned_provider = assigned;
        ResolvedJob {
            job: j,
            ipfs_cid: "bafycid".into(),
            is_active: true,
            expected_size: Some(7),
            current_block: 200,
        }
    }

    struct FakeView(ResolvedJob);
    impl JobView for FakeView {
        async fn resolve(&self, _id: u128) -> Result<ResolvedJob, String> {
            Ok(self.0.clone())
        }
    }

    struct HasInput;
    impl InputSource for HasInput {
        async fn input_for(&self, _id: u128) -> Result<Option<Vec<u8>>, String> {
            Ok(Some(b"the prompt".to_vec()))
        }
    }
    struct NoInput;
    impl InputSource for NoInput {
        async fn input_for(&self, _id: u128) -> Result<Option<Vec<u8>>, String> {
            Ok(None)
        }
    }

    fn executor<In: InputSource>(
        rj: ResolvedJob,
        input: In,
        cache: &str,
    ) -> JobExecutor<FakeView, In, Weights, Echo, UnsignedJobSigner> {
        let dir = std::env::temp_dir().join(format!("citrate-jobexec-{cache}"));
        let _ = std::fs::remove_dir_all(&dir);
        JobExecutor {
            job_id: 7,
            me: ME,
            marketplace: MARKETPLACE,
            chain_id: 40204,
            cache_dir: dir,
            nonce: [0x42; 32],
            view: FakeView(rj),
            input,
            weights: Weights,
            inference: Echo,
            signer: UnsignedJobSigner::new(),
            progress: tokio::sync::Mutex::new(JobProgress::default()),
        }
    }

    #[tokio::test]
    async fn executor_idle_when_job_not_assigned_to_us() {
        let state = shared();
        let exec = executor(resolved(JobState::Assigned, OTHER), NoInput, "notassigned");
        assert_eq!(exec.step(&state).await, StepOutcome::Idle);
        assert!(exec.signer.recorded().is_empty());
    }

    #[tokio::test]
    async fn executor_awaits_off_chain_input_before_inference() {
        let state = shared();
        let exec = executor(resolved(JobState::Executing, ME), NoInput, "awaitinput");
        assert_eq!(exec.step(&state).await, StepOutcome::AwaitingInput);
        // No artifacts produced, no writes emitted — purely holds.
        assert!(exec.progress.lock().await.artifacts.is_none());
        assert!(exec.signer.recorded().is_empty());
    }

    #[tokio::test]
    async fn executor_signs_start_execution_when_assigned() {
        let state = shared();
        // Assigned doesn't need input.
        let exec = executor(resolved(JobState::Assigned, ME), NoInput, "start");
        assert_eq!(
            exec.step(&state).await,
            StepOutcome::Signed(WriteIntent::StartExecution)
        );
    }

    #[tokio::test]
    async fn executor_runs_inference_when_executing_with_input() {
        let state = shared();
        let exec = executor(resolved(JobState::Executing, ME), HasInput, "infer");
        assert_eq!(exec.step(&state).await, StepOutcome::RanInference);
        assert!(exec.progress.lock().await.artifacts.is_some());
        let _ = std::fs::remove_dir_all(std::env::temp_dir().join("citrate-jobexec-infer"));
    }

    #[tokio::test]
    async fn no_executor_tick_is_a_noop() {
        let state = shared();
        NoExecutor.tick(&state).await;
        // Nothing recorded — purely a no-op for the bid-only loop.
        assert_eq!(state.read().await.health_at(0).active_jobs, 0);
    }
}
