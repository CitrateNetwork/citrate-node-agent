//! Live compatibility check of the settlement gates against the current
//! `ComputeMarketplace` / `ComputeVerifier` / `IPFSIncentivesV2` contracts.
//!
//! Gated: runs only when both env vars are set, otherwise it skips so the
//! default `cargo test` stays offline.
//!
//! - `CITRATE_R2_ANVIL_RPC`   — loopback JSON-RPC of an anvil (or dev node)
//!   with unlocked default accounts (`eth_sendTransaction`, `anvil_mine`).
//! - `CITRATE_R2_ANVIL_ADDRS` — JSON file mapping `ComputeMarketplace`,
//!   `ComputeVerifier`, `IPFSIncentivesV2` to their deployed addresses.
//!
//! The job is driven with the same calldata builders and planner the daemon
//! uses; every write the planner holds back is also shown to revert on chain,
//! and every write it emits is shown to succeed.

use chainio::abi::{self, Address, Word};
use chainio::marketplace::{self as mp, JobState, VerificationTier};
use chainio::rpc::RpcClient;
use lifecycle::{
    plan, AbortReason, ChainGates, LifecycleAction, PlanInput, WaitReason, WriteIntent,
    DISPUTE_WINDOW_BLOCKS,
};
use serde_json::json;
use tiny_keccak::{Hasher, Keccak};

/// anvil default account #1 (provider) and #2 (requester).
const PROVIDER: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const REQUESTER: &str = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";

fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    let mut k = Keccak::v256();
    for p in parts {
        k.update(p);
    }
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

fn sel(sig: &str) -> [u8; 4] {
    let h = keccak(&[sig.as_bytes()]);
    [h[0], h[1], h[2], h[3]]
}

fn env() -> Option<(String, serde_json::Value)> {
    let rpc = std::env::var("CITRATE_R2_ANVIL_RPC").ok()?;
    let path = std::env::var("CITRATE_R2_ANVIL_ADDRS").ok()?;
    let addrs = serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
    Some((rpc, addrs))
}

fn addr(book: &serde_json::Value, name: &str) -> Address {
    abi::address_from_hex(book[name].as_str().expect(name)).expect(name)
}

/// `eth_sendTransaction` from an unlocked account (gas estimated, so a
/// reverting call is refused with its reason); `Err` carries the revert.
/// A mined transaction must also have receipt status 1.
async fn send(
    c: &RpcClient,
    from: &str,
    to: Address,
    data: &[u8],
    value: u128,
) -> Result<(), String> {
    // Simulate against the pending block first so a revert surfaces with its
    // reason instead of as a mined status-0 receipt.
    c.call_raw(
        "eth_call",
        json!([{
            "from": from,
            "to": abi::hex_encode(&to),
            "data": abi::hex_encode(data),
            "value": format!("0x{value:x}"),
        }, "pending"]),
    )
    .await
    .map_err(|e| e.to_string())?;
    let hash = c
        .call_raw(
            "eth_sendTransaction",
            json!([{
                "from": from,
                "to": abi::hex_encode(&to),
                "data": abi::hex_encode(data),
                "value": format!("0x{value:x}"),
            }]),
        )
        .await
        .map_err(|e| e.to_string())?;
    for _ in 0..100 {
        let receipt = c
            .call_raw_value("eth_getTransactionReceipt", json!([hash]))
            .await
            .map_err(|e| e.to_string())?;
        match receipt["status"].as_str() {
            Some("0x1") => return Ok(()),
            Some(other) => return Err(format!("tx {hash} mined with status {other}")),
            None => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
        }
    }
    Err(format!("tx {hash}: no receipt"))
}

async fn mine(c: &RpcClient, n: u128) {
    c.call_raw_value("anvil_mine", json!([format!("0x{n:x}")]))
        .await
        .expect("anvil_mine");
}

async fn u256(c: &RpcClient, to: Address, sig: &str, args: &[Word]) -> u128 {
    let data = c
        .eth_call(to, &abi::encode_call(sel(sig), args))
        .await
        .expect(sig);
    abi::Decoder::new(&data).u128().expect(sig)
}

/// `postJob(bytes32,bytes,uint256,uint8,uint256,uint256)`.
fn encode_post_job(
    model: Word,
    input: &[u8],
    max_price: u128,
    tier: u8,
    bid: u128,
    exec: u128,
) -> Vec<u8> {
    let mut d = sel("postJob(bytes32,bytes,uint256,uint8,uint256,uint256)").to_vec();
    d.extend_from_slice(&model);
    d.extend_from_slice(&abi::word_from_u128(6 * 32));
    d.extend_from_slice(&abi::word_from_u128(max_price));
    d.extend_from_slice(&abi::word_from_u128(tier as u128));
    d.extend_from_slice(&abi::word_from_u128(bid));
    d.extend_from_slice(&abi::word_from_u128(exec));
    d.extend_from_slice(&abi::word_from_u128(input.len() as u128));
    let mut padded = input.to_vec();
    padded.resize(input.len().div_ceil(32) * 32, 0);
    d.extend_from_slice(&padded);
    d
}

struct Ctx {
    c: RpcClient,
    market: Address,
    verifier: Address,
    me: Address,
}

impl Ctx {
    async fn gates(&self, job_id: u128) -> ChainGates {
        ChainGates {
            effective_tier: Some(
                chainio::verifier::live::record_tier(&self.c, self.verifier, job_id)
                    .await
                    .expect("record tier"),
            ),
            commitment_block: chainio::verifier::live::commitment_block(
                &self.c,
                self.verifier,
                job_id,
            )
            .await
            .expect("commitmentBlock"),
            result_verified_at: mp::live::result_verified_at(&self.c, self.market, job_id)
                .await
                .expect("resultVerifiedAt"),
            dispute_resolved_for_provider: mp::live::dispute_resolved_for_provider(
                &self.c,
                self.market,
                job_id,
            )
            .await
            .expect("disputeResolvedForProvider"),
        }
    }

    async fn plan_now(
        &self,
        job_id: u128,
        committed: bool,
        art: Option<&lifecycle::CommitmentArtifacts>,
    ) -> LifecycleAction {
        let job = mp::live::get_job(&self.c, self.market, job_id)
            .await
            .expect("getJob");
        let head = self.c.eth_block_number().await.expect("head");
        plan(&PlanInput {
            job: &job,
            me: self.me,
            current_block: head,
            marketplace: self.market,
            chain_id: 40204,
            committed,
            artifacts: art,
            gates: self.gates(job_id).await,
        })
    }

    async fn post(&self, model: Word, input: &[u8], price: u128, tier: u8) -> u128 {
        let id = u256(&self.c, self.market, "nextJobId()", &[]).await;
        send(
            &self.c,
            REQUESTER,
            self.market,
            &encode_post_job(model, input, price, tier, 5, 200),
            price,
        )
        .await
        .expect("postJob");
        id
    }
}

fn signed(a: LifecycleAction, intent: WriteIntent) -> Vec<u8> {
    match a {
        LifecycleAction::Sign(r) if r.intent == intent => r.calldata,
        other => panic!("expected Sign({intent:?}), got {other:?}"),
    }
}

#[tokio::test]
async fn settlement_gates_match_the_deployed_contracts() {
    let Some((rpc, book)) = env() else {
        eprintln!("skipping: CITRATE_R2_ANVIL_RPC / CITRATE_R2_ANVIL_ADDRS not set");
        return;
    };
    let cx = Ctx {
        c: RpcClient::new(rpc).expect("loopback rpc"),
        market: addr(&book, "ComputeMarketplace"),
        verifier: addr(&book, "ComputeVerifier"),
        me: abi::address_from_hex(PROVIDER).expect("provider"),
    };
    let one = 10u128.pow(18);

    // Provider registration (idempotent across reruns).
    let model = keccak(&[b"r2-compat-model"]);
    let stake = u256(&cx.c, cx.market, "MIN_PROVIDER_STAKE()", &[]).await;
    let _ = send(
        &cx.c,
        PROVIDER,
        cx.market,
        &mp::encode_register_provider(&[model]),
        stake,
    )
    .await;

    // ── Commitment-tier job: 1 SALT, well under the ZK threshold ──
    let input = b"compat input";
    let job_id = cx.post(model, &keccak(&[input]), one, 0).await;
    send(
        &cx.c,
        PROVIDER,
        cx.market,
        &mp::encode_bid_on_job(job_id, one / 2, 1_000),
        0,
    )
    .await
    .expect("bid");
    send(
        &cx.c,
        REQUESTER,
        cx.market,
        &mp::encode_assign_best_bid(job_id),
        0,
    )
    .await
    .expect("assign");
    let start = signed(
        cx.plan_now(job_id, false, None).await,
        WriteIntent::StartExecution,
    );
    send(&cx.c, PROVIDER, cx.market, &start, 0)
        .await
        .expect("startExecution");

    let output = b"compat output";
    let nonce = keccak(&[b"nonce", &job_id.to_be_bytes()]);
    let commitment = keccak(&[output, &nonce]);
    let mut proof = commitment.to_vec();
    proof.extend_from_slice(&nonce);
    proof.extend_from_slice(output);
    let art = lifecycle::CommitmentArtifacts {
        commitment,
        output_hash: keccak(&[output]),
        proof,
    };
    let commit = signed(
        cx.plan_now(job_id, false, Some(&art)).await,
        WriteIntent::SubmitCommitment,
    );
    send(&cx.c, PROVIDER, cx.market, &commit, 0)
        .await
        .expect("submitCommitment");

    // Head == commitment block: the planner holds the reveal one block.
    let g = cx.gates(job_id).await;
    assert_eq!(g.effective_tier, Some(VerificationTier::Commitment));
    assert_eq!(
        g.commitment_block,
        cx.c.eth_block_number().await.expect("head")
    );
    assert_eq!(
        cx.plan_now(job_id, true, Some(&art)).await,
        LifecycleAction::Wait(WaitReason::RevealAfterCommitBlock {
            commit_block: g.commitment_block
        })
    );
    mine(&cx.c, 1).await;
    let reveal = signed(
        cx.plan_now(job_id, true, Some(&art)).await,
        WriteIntent::SubmitResult,
    );
    send(&cx.c, PROVIDER, cx.market, &reveal, 0)
        .await
        .expect("submitResult");
    let job = mp::live::get_job(&cx.c, cx.market, job_id)
        .await
        .expect("getJob");
    assert_eq!(job.state, JobState::Verifying);

    // Dispute window: the planner waits; the contract rejects completeJob.
    let verified_at = cx.gates(job_id).await.result_verified_at;
    assert_ne!(verified_at, 0, "Commitment result must verify Valid");
    let ready = verified_at + DISPUTE_WINDOW_BLOCKS;
    assert_eq!(
        cx.plan_now(job_id, true, None).await,
        LifecycleAction::Wait(WaitReason::DisputeWindow {
            ready_at_block: ready
        })
    );
    let early = send(
        &cx.c,
        PROVIDER,
        cx.market,
        &mp::encode_complete_job(job_id),
        0,
    )
    .await;
    assert!(
        early
            .as_ref()
            .err()
            .is_some_and(|e| e.contains("dispute window open")),
        "completeJob inside the window must revert: {early:?}"
    );
    // Still waiting one block before the window closes.
    let head = cx.c.eth_block_number().await.expect("head");
    mine(&cx.c, ready - 1 - head).await;
    assert!(matches!(
        cx.plan_now(job_id, true, None).await,
        LifecycleAction::Wait(WaitReason::DisputeWindow { .. })
    ));
    mine(&cx.c, 1).await;
    let complete = signed(
        cx.plan_now(job_id, true, None).await,
        WriteIntent::CompleteJob,
    );
    send(&cx.c, PROVIDER, cx.market, &complete, 0)
        .await
        .expect("completeJob after window");
    let job = mp::live::get_job(&cx.c, cx.market, job_id)
        .await
        .expect("getJob");
    assert_eq!(job.state, JobState::Completed);
    assert_eq!(cx.plan_now(job_id, true, None).await, LifecycleAction::Done);

    // ── Commitment request above 10 SALT: verified as ZKProof → refused ──
    let mut zk_model = [0u8; 32];
    zk_model[31] = 2;
    let mut zk_input = [0u8; 32];
    zk_input[31] = 1; // canonical, non-zero field element
    let zk_id = cx.post(zk_model, &zk_input, 11 * one, 0).await;
    assert_eq!(
        cx.gates(zk_id).await.effective_tier,
        Some(VerificationTier::ZKProof)
    );
    // The planner refuses whatever state the job is in once it is ours.
    let mut job = mp::live::get_job(&cx.c, cx.market, zk_id)
        .await
        .expect("getJob");
    job.state = JobState::Assigned;
    job.assigned_provider = cx.me;
    let head = cx.c.eth_block_number().await.expect("head");
    assert_eq!(
        plan(&PlanInput {
            job: &job,
            me: cx.me,
            current_block: head,
            marketplace: cx.market,
            chain_id: 40204,
            committed: false,
            artifacts: None,
            gates: cx.gates(zk_id).await,
        }),
        LifecycleAction::Abort(AbortReason::UnsupportedTier)
    );
}

#[tokio::test]
async fn slot_funding_read_matches_the_deployed_incentives_contract() {
    let Some((rpc, book)) = env() else {
        eprintln!("skipping: CITRATE_R2_ANVIL_RPC / CITRATE_R2_ANVIL_ADDRS not set");
        return;
    };
    let c = RpcClient::new(rpc).expect("loopback rpc");
    let inc = addr(&book, "IPFSIncentivesV2");
    let data = c
        .eth_call(inc, &chainio::pinning::encode_unallocated_slot_funding())
        .await
        .expect("unallocatedSlotFunding");
    let have = chainio::pinning::decode_unallocated_slot_funding(&data).expect("decode");
    // Fresh deploy, governance has not called fund(): no backing.
    assert_eq!(have, 0);
    let quorum = u256(&c, inc, "QUORUM()", &[]).await;
    let reward = u256(&c, inc, "REWARD()", &[]).await;
    assert!(quorum * reward > have, "an unfunded slot cannot be seeded");
}
