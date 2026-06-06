//! `lifecycle` — drive a *won* `ComputeMarketplace` job through its on-chain
//! state machine to payout, one signed write at a time.
//!
//! The bidder wins a job; this crate then decides, from the job's current
//! [`JobState`] (decoded by `chainio`) plus the executor's proof artifacts, the
//! **next write** the agent must perform:
//!
//! ```text
//! Assigned  ──startExecution────────────────────────────▶ Executing
//! Executing ──submitCommitment(jobId, SHA3(in‖out‖nonce))▶ (commitment recorded)
//! Executing ──submitResult(jobId, outputHash, proof)─────▶ Verifying  (verifies inline)
//! Verifying ──completeJob(jobId)────────────────────────▶ Completed  (releases payment)
//! ```
//!
//! Two non-negotiables baked in here:
//! - **No keys (ADR-agent-signing / TD-17).** Every step is emitted as an
//!   unsigned [`SignatureRequest`]; a signing relay / gui-native surface signs
//!   it and the daemon observes the broadcast. This crate never holds a key.
//! - **Anti-slash discipline.** `submitResult` is refused past the job's
//!   `executionDeadline` (a late result is a slashable timeout — better to abort
//!   cleanly). The deadline is compared in *block height* (no wall-clock /
//!   `SECS_PER_BLOCK` guess — TD-10 stays out of the critical path).
//!
//! The transitions mirror `ComputeMarketplace.sol`: `startExecution` (Assigned →
//! Executing, caller = assignedProvider), `submitCommitment` (Assigned||Executing;
//! commitment must precede result), `submitResult` (Executing, caller = provider,
//! `block <= executionDeadline`; verifies the Commitment tier inline), `completeJob`
//! (Verifying && Valid → pays out).

use chainio::abi::{Address, Word};
use chainio::marketplace::{
    encode_complete_job, encode_start_execution, encode_submit_commitment, encode_submit_result,
    Job, JobState,
};

/// A concrete chain write the agent wants performed, as an **unsigned** request.
/// The daemon hands this to the signing relay / gui-native; the user signs on a
/// surface and the daemon observes the broadcast. The node-agent holds no keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureRequest {
    /// Which lifecycle write this is (for the signer UI + the daemon's tracking).
    pub intent: WriteIntent,
    /// Target contract (the marketplace).
    pub to: Address,
    /// ABI calldata (built by `chainio`).
    pub calldata: Vec<u8>,
    /// Wei to send — always 0 for these (all four writes are non-payable).
    pub value_wei: u128,
    /// Chain id the tx must be signed for (40204).
    pub chain_id: u64,
    /// Human-readable description for the signing surface, e.g. `"submitResult job 7"`.
    pub context: String,
    /// Advisory block height past which signing is pointless (the on-chain call
    /// would revert / be slashable). `0` means no deadline. For execution-phase
    /// writes this is the job's `executionDeadline`.
    pub expires_block: u128,
}

/// An on-chain write the node-agent emits (unsigned) for a signing surface.
/// The four `*Job`/`*Execution`/`*Commitment`/`*Result` variants walk a won job
/// to payout (driven by [`plan`]); `ClaimRewards` is the earnings sweep (built by
/// the `earnings` crate). One enum so the daemon has a single signer seam for
/// every write it requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteIntent {
    StartExecution,
    SubmitCommitment,
    SubmitResult,
    CompleteJob,
    /// `ContributionAccounting.claimRewards()` — sweep accrued earnings.
    ClaimRewards,
}

impl WriteIntent {
    /// The Solidity function name, for the signing-surface label.
    pub fn label(self) -> &'static str {
        match self {
            WriteIntent::StartExecution => "startExecution",
            WriteIntent::SubmitCommitment => "submitCommitment",
            WriteIntent::SubmitResult => "submitResult",
            WriteIntent::CompleteJob => "completeJob",
            WriteIntent::ClaimRewards => "claimRewards",
        }
    }
}

/// The Commitment-tier artifacts the executor (WP-B) produces for one job.
/// Built so the proof bytes match exactly what `ComputeVerifier._verifyCommitment`
/// decodes on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentArtifacts {
    /// `SHA3(input ‖ output ‖ nonce)` as a `bytes32` — what `submitCommitment` records.
    pub commitment: Word,
    /// `keccak256(output)` — the `outputHash` arg of `submitResult`.
    pub output_hash: [u8; 32],
    /// Commitment-tier `proofData = commitment(32) ‖ nonce(32) ‖ output` — the
    /// `proof` arg of `submitResult`, decoded by `_verifyCommitment`.
    pub proof: Vec<u8>,
}

/// Everything [`plan`] needs to choose the next action for one job.
pub struct PlanInput<'a> {
    /// The job as decoded from `getJob` (carries state, assignedProvider,
    /// executionDeadline, id).
    pub job: &'a Job,
    /// This provider's address.
    pub me: Address,
    /// The current chain head (block height) — for the deadline guard.
    pub current_block: u128,
    /// The marketplace contract address (the `to` of every write).
    pub marketplace: Address,
    /// Chain id (40204).
    pub chain_id: u64,
    /// Whether the agent has already broadcast `submitCommitment` for this job
    /// (the on-chain `JobState` stays `Executing` across commitment → result, so
    /// the daemon tracks this locally).
    pub committed: bool,
    /// The executor's output for this job, once inference has run. `None` until
    /// then (the planner asks for [`LifecycleAction::RunInference`]).
    pub artifacts: Option<&'a CommitmentArtifacts>,
}

/// What the daemon should do next for a job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleAction {
    /// Emit this unsigned request to the signer/relay.
    Sign(SignatureRequest),
    /// The job is ours and Executing but we have no result yet — run the executor.
    RunInference,
    /// Not our turn (Posted/Bidding — the bidder owns these phases).
    Idle,
    /// The job reached a terminal success state; nothing more to do.
    Done,
    /// The job cannot proceed; give up safely (and surface the reason).
    Abort(AbortReason),
}

/// Why a job can't be driven further.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortReason {
    /// We are not the job's `assignedProvider` (defensive — should not happen if
    /// the daemon only drives jobs it won).
    NotAssignedProvider,
    /// The execution deadline has passed; submitting now would be a slashable
    /// late result. Abort instead.
    ExecutionDeadlinePassed,
    /// The job expired before assignment/execution.
    JobExpired,
    /// The job timed out on-chain.
    JobTimedOut,
    /// The job is marked Failed on-chain.
    JobFailedOnChain,
    /// The job is under dispute; completion is blocked.
    JobDisputed,
}

/// Decide the next action for one won job.
///
/// Pure and deterministic — the daemon feeds it the freshly-read job, the chain
/// head, and (once inference has run) the proof artifacts; it returns the next
/// unsigned write, a request to run inference, or a terminal/abort signal.
pub fn plan(input: &PlanInput) -> LifecycleAction {
    let job = input.job;
    match job.state {
        // The bidder owns these phases; the lifecycle driver stays out.
        JobState::Posted | JobState::Bidding => LifecycleAction::Idle,

        JobState::Assigned => {
            if input.me != job.assigned_provider {
                return LifecycleAction::Abort(AbortReason::NotAssignedProvider);
            }
            sign(WriteIntent::StartExecution, encode_start_execution(job.id), input)
        }

        JobState::Executing => {
            if input.me != job.assigned_provider {
                return LifecycleAction::Abort(AbortReason::NotAssignedProvider);
            }
            let Some(art) = input.artifacts else {
                // We hold the job but haven't produced a result yet.
                return LifecycleAction::RunInference;
            };
            if !input.committed {
                // Commitment must precede the result (ComputeVerifier INV-3/7).
                return sign(
                    WriteIntent::SubmitCommitment,
                    encode_submit_commitment(job.id, art.commitment),
                    input,
                );
            }
            // Result step — refuse past the execution deadline (anti-slash).
            if input.current_block > job.execution_deadline_block {
                return LifecycleAction::Abort(AbortReason::ExecutionDeadlinePassed);
            }
            sign(
                WriteIntent::SubmitResult,
                encode_submit_result(job.id, &art.output_hash, &art.proof),
                input,
            )
        }

        // The Commitment tier verifies inline inside `submitResult`, so by the
        // time the job reads `Verifying` it is already `Valid` — claim payout.
        JobState::Verifying => {
            if input.me != job.assigned_provider {
                return LifecycleAction::Abort(AbortReason::NotAssignedProvider);
            }
            sign(WriteIntent::CompleteJob, encode_complete_job(job.id), input)
        }

        JobState::Completed => LifecycleAction::Done,
        JobState::Expired => LifecycleAction::Abort(AbortReason::JobExpired),
        JobState::Timeout => LifecycleAction::Abort(AbortReason::JobTimedOut),
        JobState::Failed => LifecycleAction::Abort(AbortReason::JobFailedOnChain),
        JobState::Disputed => LifecycleAction::Abort(AbortReason::JobDisputed),
    }
}

/// Wrap a built calldata into an unsigned [`SignatureRequest`] for `intent`.
fn sign(intent: WriteIntent, calldata: Vec<u8>, input: &PlanInput) -> LifecycleAction {
    let expires_block = match intent {
        // completeJob has no on-chain deadline.
        WriteIntent::CompleteJob => 0,
        // Execution-phase writes are bounded by the job's execution deadline.
        _ => input.job.execution_deadline_block,
    };
    LifecycleAction::Sign(SignatureRequest {
        intent,
        to: input.marketplace,
        calldata,
        value_wei: 0,
        chain_id: input.chain_id,
        context: format!("{} job {}", intent.label(), input.job.id),
        expires_block,
    })
}

// ── signing seam (ADR-agent-signing / TD-17) ────────────────────────────────

/// The result of asking the relay/signer to perform a request: the observed
/// broadcast. `tx_hash` is `None` for the unsigned default (nothing broadcast).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxObserved {
    pub tx_hash: Option<String>,
}

/// Why a signing request failed.
#[derive(Debug)]
pub enum JobSignerError {
    /// The relay/signer surface rejected or failed the request.
    Relay(String),
}

impl core::fmt::Display for JobSignerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            JobSignerError::Relay(m) => write!(f, "job signer relay failed: {m}"),
        }
    }
}

impl std::error::Error for JobSignerError {}

/// Abstracts getting an unsigned [`SignatureRequest`] signed + broadcast. The
/// node-agent binary implements this over the gui-native signer / signing relay
/// (the IDP-adjacent, `sub`-keyed relay from ADR-agent-signing); tests and the
/// default daemon use [`UnsignedJobSigner`].
pub trait JobSigner {
    /// Hand `req` to the signing surface; resolve when the broadcast is observed.
    fn request(
        &self,
        req: SignatureRequest,
    ) -> impl std::future::Future<Output = Result<TxObserved, JobSignerError>> + Send;
}

/// Default, key-less signer: records each request for an external surface to
/// sign, and never broadcasts (mirrors `heartbeat::UnsignedHeartbeatSender`).
/// This is what keeps the daemon honest to ADR-agent-signing by default.
#[derive(Default)]
pub struct UnsignedJobSigner {
    recorded: std::sync::Mutex<Vec<SignatureRequest>>,
}

impl UnsignedJobSigner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of every request recorded so far (in order).
    pub fn recorded(&self) -> Vec<SignatureRequest> {
        self.recorded.lock().unwrap().clone()
    }
}

impl JobSigner for UnsignedJobSigner {
    async fn request(&self, req: SignatureRequest) -> Result<TxObserved, JobSignerError> {
        self.recorded.lock().unwrap().push(req);
        // No key here — the request is queued for a signing surface.
        Ok(TxObserved { tx_hash: None })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chainio::marketplace::VerificationTier;

    const ME: Address = [0xab; 20];
    const OTHER: Address = [0xcd; 20];
    const MARKETPLACE: Address = [0x11; 20];
    const CHAIN_ID: u64 = 40204;

    /// A Commitment-tier job assigned to `assigned`, in `state`, with the given
    /// execution deadline.
    fn job(id: u128, state: JobState, assigned: Address, exec_deadline: u128) -> Job {
        Job {
            id,
            requester: [0x01; 20],
            model_hash: [0x02; 32],
            max_price_wei: 4 * 10u128.pow(18), // < 10 SALT → stays Commitment
            tier: VerificationTier::Commitment,
            state,
            assigned_provider: assigned,
            escrow_wei: 4 * 10u128.pow(18),
            bid_deadline_block: 100,
            execution_deadline_block: exec_deadline,
            created_at_block: 50,
            bid_count: 1,
        }
    }

    fn artifacts() -> CommitmentArtifacts {
        CommitmentArtifacts {
            commitment: [0x33; 32],
            output_hash: [0x44; 32],
            proof: vec![0x55; 69],
        }
    }

    fn input<'a>(
        j: &'a Job,
        current_block: u128,
        committed: bool,
        art: Option<&'a CommitmentArtifacts>,
    ) -> PlanInput<'a> {
        PlanInput {
            job: j,
            me: ME,
            current_block,
            marketplace: MARKETPLACE,
            chain_id: CHAIN_ID,
            committed,
            artifacts: art,
        }
    }

    fn expect_sign(action: LifecycleAction, intent: WriteIntent) -> SignatureRequest {
        match action {
            LifecycleAction::Sign(req) => {
                assert_eq!(req.intent, intent);
                assert_eq!(req.to, MARKETPLACE);
                assert_eq!(req.value_wei, 0);
                assert_eq!(req.chain_id, CHAIN_ID);
                req
            }
            other => panic!("expected Sign({intent:?}), got {other:?}"),
        }
    }

    #[test]
    fn assigned_emits_start_execution() {
        let j = job(7, JobState::Assigned, ME, 200);
        let req = expect_sign(plan(&input(&j, 120, false, None)), WriteIntent::StartExecution);
        assert_eq!(req.calldata, encode_start_execution(7));
        assert_eq!(req.context, "startExecution job 7");
        assert_eq!(req.expires_block, 200);
    }

    #[test]
    fn not_assigned_provider_aborts() {
        let j = job(7, JobState::Assigned, OTHER, 200);
        assert_eq!(
            plan(&input(&j, 120, false, None)),
            LifecycleAction::Abort(AbortReason::NotAssignedProvider)
        );
    }

    #[test]
    fn executing_without_artifacts_runs_inference() {
        let j = job(7, JobState::Executing, ME, 200);
        assert_eq!(plan(&input(&j, 120, false, None)), LifecycleAction::RunInference);
    }

    #[test]
    fn executing_with_artifacts_emits_commitment_first() {
        let j = job(7, JobState::Executing, ME, 200);
        let art = artifacts();
        let req = expect_sign(
            plan(&input(&j, 120, false, Some(&art))),
            WriteIntent::SubmitCommitment,
        );
        assert_eq!(req.calldata, encode_submit_commitment(7, art.commitment));
    }

    #[test]
    fn executing_committed_emits_submit_result_within_deadline() {
        let j = job(7, JobState::Executing, ME, 200);
        let art = artifacts();
        let req = expect_sign(
            plan(&input(&j, 199, true, Some(&art))),
            WriteIntent::SubmitResult,
        );
        assert_eq!(
            req.calldata,
            encode_submit_result(7, &art.output_hash, &art.proof)
        );
        assert_eq!(req.expires_block, 200);
    }

    #[test]
    fn submit_result_past_deadline_aborts() {
        let j = job(7, JobState::Executing, ME, 200);
        let art = artifacts();
        // current_block 201 > deadline 200 → refuse (anti-slash).
        assert_eq!(
            plan(&input(&j, 201, true, Some(&art))),
            LifecycleAction::Abort(AbortReason::ExecutionDeadlinePassed)
        );
    }

    #[test]
    fn submit_result_exactly_at_deadline_is_allowed() {
        let j = job(7, JobState::Executing, ME, 200);
        let art = artifacts();
        // block == deadline is still in-window (contract: block <= deadline).
        expect_sign(
            plan(&input(&j, 200, true, Some(&art))),
            WriteIntent::SubmitResult,
        );
    }

    #[test]
    fn verifying_emits_complete_job() {
        let j = job(7, JobState::Verifying, ME, 200);
        let req = expect_sign(plan(&input(&j, 220, true, None)), WriteIntent::CompleteJob);
        assert_eq!(req.calldata, encode_complete_job(7));
        assert_eq!(req.expires_block, 0); // no deadline on completion
    }

    #[test]
    fn completed_is_done() {
        let j = job(7, JobState::Completed, ME, 200);
        assert_eq!(plan(&input(&j, 300, true, None)), LifecycleAction::Done);
    }

    #[test]
    fn posted_and_bidding_are_idle() {
        for s in [JobState::Posted, JobState::Bidding] {
            let j = job(7, s, ME, 200);
            assert_eq!(plan(&input(&j, 60, false, None)), LifecycleAction::Idle);
        }
    }

    #[test]
    fn terminal_failure_states_abort_with_reason() {
        for (s, r) in [
            (JobState::Expired, AbortReason::JobExpired),
            (JobState::Timeout, AbortReason::JobTimedOut),
            (JobState::Failed, AbortReason::JobFailedOnChain),
            (JobState::Disputed, AbortReason::JobDisputed),
        ] {
            let j = job(7, s, ME, 200);
            assert_eq!(plan(&input(&j, 300, true, None)), LifecycleAction::Abort(r));
        }
    }

    #[tokio::test]
    async fn unsigned_signer_records_request_without_broadcasting() {
        let signer = UnsignedJobSigner::new();
        let j = job(7, JobState::Assigned, ME, 200);
        let LifecycleAction::Sign(req) = plan(&input(&j, 120, false, None)) else {
            panic!("expected a Sign action");
        };
        let observed = signer.request(req.clone()).await.unwrap();
        assert_eq!(observed.tx_hash, None); // nothing broadcast — no key
        let recorded = signer.recorded();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0], req);
        assert_eq!(recorded[0].intent, WriteIntent::StartExecution);
    }
}
