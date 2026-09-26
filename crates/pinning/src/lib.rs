//! `pinning` — the PIN-S6 pinning-daemon core (citrate-node-agent).
//!
//! A pinning node earns SALT by **provably storing** a model's weights over
//! time: it seals a unique replica of a ModelRegistry CID, posts a bond, and
//! answers rolling PoSt challenges; the `IPFSIncentives` contract pays per
//! proven round and slashes a missed challenge. This crate is the daemon's
//! decision brain + seams:
//!
//! - [`plan_pin`] — a PURE function from the on-chain pin/slot state to the
//!   next [`PinAction`] (register → seal → challenge → prove → claim →
//!   return-bond). No I/O, fully unit-tested; mirrors `lifecycle::plan`.
//! - [`PinSigner`] — the no-keys signing seam (ADR-agent-signing). The daemon
//!   never holds keys; each write becomes an UNSIGNED [`PinSignatureRequest`]
//!   the relay / gui-native surface signs + broadcasts. The default
//!   [`RecordingPinSigner`] just records, so the flow is offline-testable.
//! - [`Sealer`] — the seam to the heavy reduced-circuit prover. Sealing
//!   (PoRep) and PoSt proving live in `citrate-chain`'s `zkp::halo2` behind the
//!   `halo2-substrate` feature; the production [`Sealer`] adapter drives that as
//!   a **sidecar process** (it must not pull the halo2 stack into the daemon).
//!   That adapter + the daemon run-loop that calls `seal → sealCommit` are the
//!   documented follow-up — they need the sidecar binary, so per the repo's
//!   no-stub rule the daemon can't be *constructed* with a real sealer until it
//!   exists. The `FakeSealer` here is behind `#[cfg(test)]`.
//!
//! **Lane-A seam (SELL-S2):** the stable interface Lane A consumes is
//! [`plan_pin`]'s output + the [`PinSigner`]/[`PinSignatureRequest`] shape —
//! frozen here. See `handoffs/SELL_S2_UNBLOCK_WP.md` and the daemon-API note.
//!
//! **Contract-version note:** this targets the live `IPFSIncentivesV2` ABI. V2
//! is *self-challenge* (the pinner opens its own challenge to vest). PIN-CR-S1's
//! `IPFSIncentivesV3` moves challenge opening to a third-party commit-reveal
//! flow; when V3 deploys, [`plan_pin`]'s `OpenChallenge` branch and the
//! `submitPoSt` calldata swap to the V3 shape (the rest is unchanged).

use chainio::abi::Address;
use chainio::pinning::{PinState, PinStatus, SlotState};

pub use chainio::pinning::{PinState as ChainPinState, SlotState as ChainSlotState};

pub mod runloop;
pub mod sidecar;
pub use sidecar::SidecarSealer;

/// One on-chain write the pinning daemon emits (unsigned) for a signing surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinIntent {
    /// `registerPinner()` — KYC-gated registration (one-time).
    RegisterPinner,
    /// `sealCommit(...)` — post bond + PoRep proof to activate a pin.
    SealCommit,
    /// `challenge(cid, sector)` — open a PoSt challenge (V2 self-challenge).
    Challenge,
    /// `submitPoSt(...)` — answer the open challenge with a PoSt proof.
    SubmitPoSt,
    /// `claim(cid, sector)` — withdraw vested reward.
    Claim,
    /// `returnBond(cid, sector)` — reclaim bond after Done + fully claimed.
    ReturnBond,
}

impl PinIntent {
    /// The Solidity function name, for the signing-surface label.
    pub fn label(self) -> &'static str {
        match self {
            PinIntent::RegisterPinner => "registerPinner",
            PinIntent::SealCommit => "sealCommit",
            PinIntent::Challenge => "challenge",
            PinIntent::SubmitPoSt => "submitPoSt",
            PinIntent::Claim => "claim",
            PinIntent::ReturnBond => "returnBond",
        }
    }
}

/// An UNSIGNED pin-lifecycle write the daemon hands to a signing surface.
/// Mirrors `lifecycle::SignatureRequest` (same shape, pin intents) so the
/// existing relay queue carries both job and pin writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinSignatureRequest {
    pub intent: PinIntent,
    /// Target = the `IPFSIncentives` contract (canonical chain-40204 book).
    pub to: Address,
    /// ABI calldata (built by `chainio::pinning`).
    pub calldata: Vec<u8>,
    /// Wei to send — `BOND` for `sealCommit`, else 0.
    pub value_wei: u128,
    /// Chain id the tx must be signed for (40204).
    pub chain_id: u64,
    /// Human-readable description for the signing surface.
    pub context: String,
    /// Advisory block past which signing is pointless (a challenge response
    /// past `challengeDeadline` is slashable, not just wasted). `0` = none.
    pub expires_block: u128,
}

/// The next thing the daemon should do for one (cid, sector) pin, decided
/// purely from on-chain state. The run-loop turns `Seal`/`Prove` into a
/// [`Sealer`] call then a [`PinSignatureRequest`]; the `Sign` variants are
/// ready-to-enqueue writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinAction {
    /// Nothing to do right now (e.g. challenge open + already answered this
    /// tick, or waiting on the chain to advance).
    Idle,
    /// Not registered yet → emit `registerPinner()` (carried in the request).
    Sign(PinSignatureRequest),
    /// The slot has capacity and we hold no pin here → seal a replica. The loop
    /// calls [`Sealer::seal`] to get CommD/CommR/CommC + PoRep proof, then emits
    /// `sealCommit`. Carries nothing on-chain yet (sealing is off-chain + heavy).
    Seal { cid: [u8; 32], sector: u128 },
    /// An open challenge needs a PoSt answer before `deadline`. The loop calls
    /// [`Sealer::prove_post`] with `nonce`, then emits `submitPoSt`.
    Prove {
        cid: [u8; 32],
        sector: u128,
        nonce: [u8; 32],
        deadline: u128,
    },
    /// The slot is at quorum / not fundable / pin slashed-and-unmanaged, etc. —
    /// a terminal "don't act" with a reason (for `/health` + logs).
    Hold(HoldReason),
}

/// Why [`plan_pin`] declined to act on a pin/slot this tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldReason {
    /// Slot already has `liveCount == quorum` live pins and we hold none —
    /// no room to seal a fresh replica here.
    SlotAtQuorum,
    /// The slot has no budget yet and the contract's unallocated backing
    /// (`unallocatedSlotFunding`, topped up by governance `fund()`) cannot seed
    /// one, so `sealCommit` would revert "Insufficient slot funding". Back off
    /// until governance funds the contract.
    SlotUnfunded,
    /// Pin is `Slashed`; re-entry needs an explicit `clearSlashed` decision
    /// (operator policy — not auto, to avoid burning bond in a loop).
    PinSlashed,
    /// Challenge is open but the response window has already closed — the next
    /// permissionless `slash` will record the miss; nothing to submit.
    ChallengeWindowClosed,
}

impl core::fmt::Display for HoldReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HoldReason::SlotAtQuorum => write!(f, "slot is at its replication quorum"),
            HoldReason::SlotUnfunded => write!(
                f,
                "slot has no reward budget and the incentives contract holds too little \
                 governance backing (fund()) to seed one; sealing would revert \
                 \"{INSUFFICIENT_SLOT_FUNDING_REVERT}\" — backing off until governance funds it"
            ),
            HoldReason::PinSlashed => {
                write!(f, "pin is slashed; re-entry needs an operator decision")
            }
            HoldReason::ChallengeWindowClosed => {
                write!(f, "challenge response window closed; nothing to submit")
            }
        }
    }
}

/// Everything [`plan_pin`] needs to choose the next action for one (cid,sector).
pub struct PinPlanInput {
    /// This pinner's address.
    pub me: Address,
    /// The target content id + sector we want to pin/earn on.
    pub cid: [u8; 32],
    pub sector: u128,
    /// Whether `me` has completed KYC-gated `registerPinner()`.
    pub registered: bool,
    /// Our pin's on-chain state (`getPin(me, cid, sector)`).
    pub pin: PinState,
    /// The slot's on-chain state (`getSlot(cid, sector)`).
    pub slot: SlotState,
    /// Replication target (`QUORUM` immutable; mirror from the contract / config).
    pub quorum: u128,
    /// Total PoSt rounds to fully vest (`ROUNDS` immutable).
    pub rounds: u128,
    /// The reward fully vests `PER_ROUND` per round (`REWARD / ROUNDS`).
    pub per_round: u128,
    /// Current chain head (for the challenge-deadline guard).
    pub current_block: u128,
    /// The `IPFSIncentives` contract address (the `to` of every write).
    pub incentives: Address,
    /// `BOND` (immutable) — the exact wei `sealCommit` requires.
    pub bond_wei: u128,
    /// Chain id (40204).
    pub chain_id: u64,
    /// `QUORUM * REWARD` — the budget the first `sealCommit` on an unfunded
    /// slot draws from the contract's unallocated backing.
    pub slot_seed_wei: u128,
    /// `unallocatedSlotFunding()` — backing deposited by governance `fund()`
    /// and not yet assigned to a slot.
    pub unallocated_slot_funding: u128,
}

/// Revert reason `IPFSIncentivesV2.sealCommit` returns when the contract holds
/// too little governance backing to seed a fresh slot's budget.
pub const INSUFFICIENT_SLOT_FUNDING_REVERT: &str = "Insufficient slot funding";

/// Pure planner: given the on-chain pin/slot state, decide the next action.
///
/// Priority order (each tick acts on the single most-urgent step):
/// 1. **Answer an open challenge** (highest — a missed window is slashable).
/// 2. **Register** if not registered (precondition for sealing).
/// 3. **Seal** if the slot has room and we hold no pin.
/// 4. **Claim** vested-but-unclaimed reward.
/// 5. **Return bond** once Done + fully claimed.
/// 6. **Open a challenge** to vest the next round (V2 self-challenge).
/// 7. Otherwise **Idle**/`Hold`.
pub fn plan_pin(i: &PinPlanInput) -> PinAction {
    let p = &i.pin;

    // 1. Open challenge → answer it before the window closes (anti-slash).
    if p.status == PinStatus::Active && p.challenge_open {
        if i.current_block > p.challenge_deadline {
            return PinAction::Hold(HoldReason::ChallengeWindowClosed);
        }
        return PinAction::Prove {
            cid: i.cid,
            sector: i.sector,
            nonce: p.challenge_nonce,
            deadline: p.challenge_deadline,
        };
    }

    // 2. Slashed pins are an explicit operator decision, never an auto-loop.
    if p.status == PinStatus::Slashed {
        return PinAction::Hold(HoldReason::PinSlashed);
    }

    // 3. No pin here yet → seal if the slot can take us.
    if p.status == PinStatus::None {
        if !i.registered {
            return sign(
                PinIntent::RegisterPinner,
                i.incentives,
                chainio::pinning::encode_register_pinner(),
                0,
                i.chain_id,
                "registerPinner".to_string(),
                0,
            );
        }
        // A slot's budget is created by the first `sealCommit`, which draws
        // `QUORUM * REWARD` from governance backing (`fund()`); without that
        // backing the seal reverts, so hold instead of bonding into a revert.
        if !i.slot.funded && i.unallocated_slot_funding < i.slot_seed_wei {
            return PinAction::Hold(HoldReason::SlotUnfunded);
        }
        if i.slot.live_count >= i.quorum {
            return PinAction::Hold(HoldReason::SlotAtQuorum);
        }
        return PinAction::Seal {
            cid: i.cid,
            sector: i.sector,
        };
    }

    // 4. Claim any vested-but-unclaimed reward (Active or Done).
    let vested = p.round.saturating_mul(i.per_round);
    if (p.status == PinStatus::Active || p.status == PinStatus::Done) && vested > p.claimed {
        return sign(
            PinIntent::Claim,
            i.incentives,
            chainio::pinning::encode_claim(i.cid, i.sector),
            0,
            i.chain_id,
            format!("claim {} vested", vested - p.claimed),
            0,
        );
    }

    // 5. Done + fully claimed + bond still held → reclaim bond.
    if p.status == PinStatus::Done && p.claimed == vested && p.bond_held > 0 {
        return sign(
            PinIntent::ReturnBond,
            i.incentives,
            chainio::pinning::encode_return_bond(i.cid, i.sector),
            0,
            i.chain_id,
            "returnBond".to_string(),
            0,
        );
    }

    // 6. Active, no open challenge, not fully vested → open the next challenge
    //    to keep vesting (V2 self-challenge; V3 makes this third-party).
    if p.status == PinStatus::Active && !p.challenge_open && p.round < i.rounds {
        return sign(
            PinIntent::Challenge,
            i.incentives,
            chainio::pinning::encode_challenge(i.cid, i.sector),
            0,
            i.chain_id,
            format!("challenge round {}", p.round + 1),
            0,
        );
    }

    PinAction::Idle
}

#[allow(clippy::too_many_arguments)]
fn sign(
    intent: PinIntent,
    to: Address,
    calldata: Vec<u8>,
    value_wei: u128,
    chain_id: u64,
    context: String,
    expires_block: u128,
) -> PinAction {
    PinAction::Sign(PinSignatureRequest {
        intent,
        to,
        calldata,
        value_wei,
        chain_id,
        context,
        expires_block,
    })
}

/// Build the `sealCommit` signature request once the [`Sealer`] has produced the
/// seal artifacts. Carries the circuit's `replica_id` + the seal `epoch` (the
/// contract binds them — PIN-S6 finding). Separate from [`plan_pin`] because it
/// needs off-chain output. `value_wei = BOND`.
pub fn seal_commit_request(
    i: &PinPlanInput,
    sealed: &SealArtifacts,
    epoch: u128,
) -> PinSignatureRequest {
    let calldata = chainio::pinning::encode_seal_commit(
        i.cid,
        i.sector,
        sealed.replica_id,
        epoch,
        sealed.comm_d,
        sealed.comm_r,
        sealed.comm_c,
        &sealed.porep_proof,
    );
    PinSignatureRequest {
        intent: PinIntent::SealCommit,
        to: i.incentives,
        calldata,
        value_wei: i.bond_wei,
        chain_id: i.chain_id,
        context: "sealCommit (post bond + PoRep)".to_string(),
        expires_block: 0,
    }
}

/// Build the `submitPoSt` signature request once the [`Sealer`] has produced the
/// PoSt proof for the open challenge (the [`PinAction::Prove`] follow-up).
pub fn submit_post_request(
    i: &PinPlanInput,
    sealed: &SealArtifacts,
    nonce: [u8; 32],
    deadline: u128,
    post_proof: &[u8],
) -> PinSignatureRequest {
    let calldata = chainio::pinning::encode_submit_post(
        i.cid,
        i.sector,
        sealed.comm_r,
        sealed.comm_c,
        nonce,
        post_proof,
    );
    PinSignatureRequest {
        intent: PinIntent::SubmitPoSt,
        to: i.incentives,
        calldata,
        value_wei: 0,
        chain_id: i.chain_id,
        context: "submitPoSt (answer challenge)".to_string(),
        expires_block: deadline,
    }
}

// ───────────────────────────── signing seam ────────────────────────────────

/// Outcome of handing a request to the signing surface (mirrors
/// `lifecycle::TxObserved`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PinTxObserved {
    /// Set once the surface reports the broadcast; `None` while still queued.
    pub tx_hash: Option<String>,
}

/// Errors from the signing seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinSignerError {
    /// No signing surface is attached (no keys; nothing drains the queue).
    NoSigner,
    /// The surface rejected the request (e.g. user declined).
    Declined(String),
    /// The write was broadcast (or simulated) and reverted on chain; carries
    /// the revert reason as reported by the relay.
    Reverted(String),
}

impl core::fmt::Display for PinSignerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PinSignerError::NoSigner => write!(f, "no signing surface attached"),
            PinSignerError::Declined(m) => write!(f, "signing declined: {m}"),
            PinSignerError::Reverted(m) => write!(f, "transaction reverted: {m}"),
        }
    }
}

/// The no-keys signing seam: the daemon requests, a surface signs + broadcasts.
pub trait PinSigner {
    /// Enqueue/observe an unsigned pin write. Implementations must be idempotent
    /// by calldata (the daemon re-emits each tick until the chain advances).
    fn request(
        &self,
        req: PinSignatureRequest,
    ) -> impl std::future::Future<Output = Result<PinTxObserved, PinSignerError>> + Send;
}

// ────────────────────────────── sealer seam ────────────────────────────────

/// The seal artifacts for one (replicaID, sector): the three Merkle roots the
/// `sealCommit` proof binds, plus the PoRep proof bytes the `0x0108` verifier
/// (circuit_version 2) checks. Produced by [`Sealer::seal`], cached by the
/// daemon so PoSt proofs reuse CommR/CommC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealArtifacts {
    /// replicaID = Poseidon(pinnerIdentity ‖ cid ‖ sector) — the proof's public
    /// input; the daemon binds it on-chain (sealCommit derives the same).
    pub replica_id: [u8; 32],
    /// Unsealed data Merkle root (content anchor).
    pub comm_d: [u8; 32],
    /// Sealed replica root (per-pinner).
    pub comm_r: [u8; 32],
    /// Column commitment.
    pub comm_c: [u8; 32],
    /// PoRep proof bytes (Halo2-KZG, circuit_version 2), valid at challenge
    /// index 0 (the contract's sealCommit wire uses challengeNonce=0).
    pub porep_proof: Vec<u8>,
}

/// Everything the [`Sealer`] needs to seal/prove one (pinner, cid, sector).
/// The reduced circuit consumes 4 field elements of content (`data`); for a
/// real CID the daemon derives them from the fetched bytes (testnet-functional
/// reduced instance — real-size sealing is PIN-P1 f.6, same interface).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealInputs {
    /// The private pre-image of replicaID (e.g. the pinner's address, padded).
    pub pinner_identity: [u8; 32],
    pub cid: [u8; 32],
    pub sector: u128,
    /// Epoch bound into the seal (the seal block, typically).
    pub epoch: u128,
    /// The reduced model content (N=4 field elements), 32-byte BE each.
    pub data: [[u8; 32]; 4],
}

/// Errors from the sealer/prover sidecar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealerError {
    /// The replica bytes weren't available / didn't match the CID.
    Replica(String),
    /// The sidecar failed to produce a proof (build/runtime).
    Prove(String),
}

impl core::fmt::Display for SealerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SealerError::Replica(m) => write!(f, "replica unavailable: {m}"),
            SealerError::Prove(m) => write!(f, "proving failed: {m}"),
        }
    }
}

/// The seam to the heavy reduced-circuit prover. The production adapter drives
/// `citrate-chain`'s `zkp::halo2` seal/prove path as a **sidecar process** (it
/// must not link the halo2 stack into the daemon). That adapter + the run-loop
/// that calls `seal → sealCommit` / `prove_post → submitPoSt` are the documented
/// PIN-S6 follow-up — they need the sidecar binary, so no real `Sealer` is
/// wired by default (repo no-stub rule).
pub trait Sealer {
    /// Seal a unique replica + produce the seal-time PoRep proof (index 0).
    fn seal(
        &self,
        inputs: &SealInputs,
    ) -> impl std::future::Future<Output = Result<SealArtifacts, SealerError>> + Send;

    /// Produce a PoSt proof (circuit_version 3) for the contract-derived
    /// challenge index (the on-chain committed nonce, which the reduced
    /// deployment pins so it indexes a real node). Re-seals from `inputs`
    /// internally — no cached `SealArtifacts` needed.
    fn prove_post(
        &self,
        inputs: &SealInputs,
        challenge_index: u64,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, SealerError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    use chainio::pinning::PinStatus;

    const ME: Address = [0xBE; 20];
    const INC: Address = [0x1F; 20];
    const CID: [u8; 32] = [0x11; 32];

    fn none_pin() -> PinState {
        PinState {
            status: PinStatus::None,
            round: 0,
            missed: 0,
            claimed: 0,
            bond_held: 0,
            challenge_open: false,
            challenge_deadline: 0,
            challenge_nonce: [0u8; 32],
        }
    }

    fn slot(funded: bool, budget: u128, live: u128) -> SlotState {
        SlotState {
            funded,
            budget,
            live_count: live,
        }
    }

    fn input(pin: PinState, slot: SlotState, registered: bool, block: u128) -> PinPlanInput {
        PinPlanInput {
            me: ME,
            cid: CID,
            sector: 0,
            registered,
            pin,
            slot,
            quorum: 3,
            rounds: 4,
            per_round: 1_000,
            current_block: block,
            incentives: INC,
            bond_wei: 10_000,
            chain_id: 40204,
            slot_seed_wei: SEED,
            unallocated_slot_funding: 0,
        }
    }

    /// QUORUM(3) * REWARD(4_000).
    const SEED: u128 = 12_000;

    fn backed(mut i: PinPlanInput, unallocated: u128) -> PinPlanInput {
        i.unallocated_slot_funding = unallocated;
        i
    }

    #[test]
    fn unregistered_none_pin_registers_first() {
        let a = plan_pin(&input(none_pin(), slot(true, 9_000, 0), false, 100));
        match a {
            PinAction::Sign(r) => assert_eq!(r.intent, PinIntent::RegisterPinner),
            other => panic!("expected RegisterPinner, got {other:?}"),
        }
    }

    #[test]
    fn registered_none_pin_seals_when_room() {
        let a = plan_pin(&input(none_pin(), slot(true, 9_000, 1), true, 100));
        assert_eq!(a, PinAction::Seal { cid: CID, sector: 0 });
    }

    #[test]
    fn full_slot_holds() {
        let a = plan_pin(&input(none_pin(), slot(true, 9_000, 3), true, 100));
        assert_eq!(a, PinAction::Hold(HoldReason::SlotAtQuorum));
    }

    #[test]
    fn unfunded_slot_holds() {
        let a = plan_pin(&input(none_pin(), slot(false, 0, 0), true, 100));
        assert_eq!(a, PinAction::Hold(HoldReason::SlotUnfunded));
    }

    #[test]
    fn fresh_slot_seals_once_governance_backing_covers_the_seed() {
        // A slot is only marked funded by the first sealCommit, which draws
        // QUORUM*REWARD from unallocatedSlotFunding. Enough backing → seal.
        for have in [SEED, SEED + 1] {
            let a = plan_pin(&backed(
                input(none_pin(), slot(false, 0, 0), true, 100),
                have,
            ));
            assert_eq!(
                a,
                PinAction::Seal {
                    cid: CID,
                    sector: 0
                },
                "backing {have}"
            );
        }
    }

    #[test]
    fn fresh_slot_holds_while_backing_is_short() {
        for have in [0, SEED - 1] {
            let a = plan_pin(&backed(
                input(none_pin(), slot(false, 0, 0), true, 100),
                have,
            ));
            assert_eq!(
                a,
                PinAction::Hold(HoldReason::SlotUnfunded),
                "backing {have}"
            );
        }
    }

    #[test]
    fn funded_slot_does_not_need_backing() {
        let a = plan_pin(&backed(
            input(none_pin(), slot(true, 9_000, 0), true, 100),
            0,
        ));
        assert_eq!(
            a,
            PinAction::Seal {
                cid: CID,
                sector: 0
            }
        );
    }

    fn intent_of(a: PinAction) -> Option<PinIntent> {
        match a {
            PinAction::Sign(r) => Some(r.intent),
            _ => None,
        }
    }

    #[test]
    fn challenge_answered_exactly_at_the_deadline_block() {
        let mut p = none_pin();
        p.status = PinStatus::Active;
        p.challenge_open = true;
        p.challenge_deadline = 200;
        let a = plan_pin(&input(p, slot(true, 9_000, 1), true, 200));
        assert!(matches!(a, PinAction::Prove { deadline: 200, .. }), "{a:?}");
    }

    #[test]
    fn bond_returned_only_when_done_fully_claimed_and_held() {
        // rounds 4 × per_round 1_000 → fully vested at 4_000.
        let done = |claimed: u128, bond: u128| {
            let mut p = none_pin();
            p.status = PinStatus::Done;
            p.round = 4;
            p.claimed = claimed;
            p.bond_held = bond;
            p
        };
        assert_eq!(
            intent_of(plan_pin(&input(
                done(4_000, 10_000),
                slot(true, 9_000, 1),
                true,
                100
            ))),
            Some(PinIntent::ReturnBond)
        );
        // Bond already returned → nothing left to do.
        assert_eq!(
            plan_pin(&input(done(4_000, 0), slot(true, 9_000, 1), true, 100)),
            PinAction::Idle
        );
        // Still Active and fully vested with bond held → no bond return yet.
        let mut active = done(4_000, 10_000);
        active.status = PinStatus::Active;
        assert_eq!(
            plan_pin(&input(active, slot(true, 9_000, 1), true, 100)),
            PinAction::Idle
        );
    }

    #[test]
    fn done_pin_with_unclaimed_vesting_claims_first() {
        let mut p = none_pin();
        p.status = PinStatus::Done;
        p.round = 4;
        p.claimed = 3_000;
        p.bond_held = 10_000;
        assert_eq!(
            intent_of(plan_pin(&input(p, slot(true, 9_000, 1), true, 100))),
            Some(PinIntent::Claim)
        );
    }

    #[test]
    fn challenge_opened_only_while_active_and_not_fully_vested() {
        let mut p = none_pin();
        p.status = PinStatus::Active;
        p.round = 3;
        p.claimed = 3_000;
        p.bond_held = 10_000;
        assert_eq!(
            intent_of(plan_pin(&input(p.clone(), slot(true, 9_000, 1), true, 100))),
            Some(PinIntent::Challenge)
        );
        // Last round reached → no further challenge.
        p.round = 4;
        p.claimed = 4_000;
        assert_eq!(
            plan_pin(&input(p.clone(), slot(true, 9_000, 1), true, 100)),
            PinAction::Idle
        );
        // Done (not Active) with rounds left and nothing owed → no challenge.
        p.status = PinStatus::Done;
        p.round = 2;
        p.claimed = 2_000;
        p.bond_held = 0;
        assert_eq!(
            plan_pin(&input(p, slot(true, 9_000, 1), true, 100)),
            PinAction::Idle
        );
    }

    #[test]
    fn slot_unfunded_hold_message_names_the_governance_step() {
        let m = HoldReason::SlotUnfunded.to_string();
        assert!(m.contains("fund()"), "{m}");
        assert!(m.contains(INSUFFICIENT_SLOT_FUNDING_REVERT), "{m}");
        assert!(m.contains("backing off"), "{m}");
    }

    #[test]
    fn revert_reason_constant_matches_contract() {
        assert_eq!(
            INSUFFICIENT_SLOT_FUNDING_REVERT,
            "Insufficient slot funding"
        );
        assert_eq!(
            PinSignerError::Reverted("x".into()).to_string(),
            "transaction reverted: x"
        );
    }

    #[test]
    fn open_challenge_in_window_proves() {
        let mut p = none_pin();
        p.status = PinStatus::Active;
        p.challenge_open = true;
        p.challenge_deadline = 200;
        let mut nonce = [0u8; 32];
        nonce[31] = 7;
        p.challenge_nonce = nonce;
        let a = plan_pin(&input(p, slot(true, 9_000, 1), true, 150));
        assert_eq!(
            a,
            PinAction::Prove {
                cid: CID,
                sector: 0,
                nonce,
                deadline: 200
            }
        );
    }

    #[test]
    fn open_challenge_past_window_holds() {
        let mut p = none_pin();
        p.status = PinStatus::Active;
        p.challenge_open = true;
        p.challenge_deadline = 200;
        let a = plan_pin(&input(p, slot(true, 9_000, 1), true, 201));
        assert_eq!(a, PinAction::Hold(HoldReason::ChallengeWindowClosed));
    }

    #[test]
    fn active_unvested_opens_challenge() {
        let mut p = none_pin();
        p.status = PinStatus::Active;
        p.round = 1;
        p.claimed = 1_000; // already claimed round 1
        let a = plan_pin(&input(p, slot(true, 9_000, 1), true, 100));
        match a {
            PinAction::Sign(r) => assert_eq!(r.intent, PinIntent::Challenge),
            other => panic!("expected Challenge, got {other:?}"),
        }
    }

    #[test]
    fn active_with_unclaimed_vested_claims_first() {
        let mut p = none_pin();
        p.status = PinStatus::Active;
        p.round = 2;
        p.claimed = 1_000; // vested 2*1000=2000 > claimed 1000 → claim
        let a = plan_pin(&input(p, slot(true, 9_000, 1), true, 100));
        match a {
            PinAction::Sign(r) => assert_eq!(r.intent, PinIntent::Claim),
            other => panic!("expected Claim, got {other:?}"),
        }
    }

    #[test]
    fn done_fully_claimed_returns_bond() {
        let mut p = none_pin();
        p.status = PinStatus::Done;
        p.round = 4;
        p.claimed = 4_000; // fully claimed (4*1000)
        p.bond_held = 10_000;
        let a = plan_pin(&input(p, slot(true, 9_000, 1), true, 100));
        match a {
            PinAction::Sign(r) => assert_eq!(r.intent, PinIntent::ReturnBond),
            other => panic!("expected ReturnBond, got {other:?}"),
        }
    }

    #[test]
    fn slashed_pin_holds() {
        let mut p = none_pin();
        p.status = PinStatus::Slashed;
        let a = plan_pin(&input(p, slot(true, 9_000, 1), true, 100));
        assert_eq!(a, PinAction::Hold(HoldReason::PinSlashed));
    }

    #[test]
    fn challenge_answer_beats_claim_priority() {
        // Active pin that BOTH has an open challenge AND unclaimed vested reward
        // must answer the challenge first (anti-slash priority).
        let mut p = none_pin();
        p.status = PinStatus::Active;
        p.round = 2;
        p.claimed = 0; // 2000 unclaimed
        p.challenge_open = true;
        p.challenge_deadline = 300;
        let a = plan_pin(&input(p, slot(true, 9_000, 1), true, 150));
        assert!(matches!(a, PinAction::Prove { .. }));
    }

    #[test]
    fn seal_commit_request_carries_bond_and_calldata() {
        let i = input(none_pin(), slot(true, 9_000, 1), true, 100);
        let sealed = SealArtifacts {
            replica_id: [0x11; 32],
            comm_d: [0xD0; 32],
            comm_r: [0x12; 32],
            comm_c: [0x0C; 32],
            porep_proof: vec![0xAB, 0xCD],
        };
        let req = seal_commit_request(&i, &sealed, 1);
        assert_eq!(req.intent, PinIntent::SealCommit);
        assert_eq!(req.value_wei, 10_000); // BOND
        assert_eq!(req.to, INC);
        assert_eq!(&req.calldata[0..4], &chainio::selectors::pin_seal_commit());
    }

    #[test]
    fn submit_post_request_sets_deadline_as_expiry() {
        let i = input(none_pin(), slot(true, 9_000, 1), true, 100);
        let sealed = SealArtifacts {
            replica_id: [0x11; 32],
            comm_d: [0xD0; 32],
            comm_r: [0x12; 32],
            comm_c: [0x0C; 32],
            porep_proof: vec![],
        };
        let mut nonce = [0u8; 32];
        nonce[31] = 9;
        let req = submit_post_request(&i, &sealed, nonce, 250, &[0x01]);
        assert_eq!(req.intent, PinIntent::SubmitPoSt);
        assert_eq!(req.expires_block, 250);
        assert_eq!(&req.calldata[0..4], &chainio::selectors::pin_submit_post());
    }

    // ── seam smoke tests: a recording signer + a deterministic fake sealer ──

    #[derive(Default)]
    struct RecordingPinSigner {
        last: std::sync::Mutex<Option<PinSignatureRequest>>,
    }
    impl PinSigner for RecordingPinSigner {
        async fn request(
            &self,
            req: PinSignatureRequest,
        ) -> Result<PinTxObserved, PinSignerError> {
            *self.last.lock().expect("lock") = Some(req);
            Ok(PinTxObserved { tx_hash: None })
        }
    }

    struct FakeSealer;
    impl Sealer for FakeSealer {
        async fn seal(&self, inputs: &SealInputs) -> Result<SealArtifacts, SealerError> {
            // Deterministic, input-bound artifacts (NOT a real proof — this is a
            // #[cfg(test)] fixture; the production Sealer is the SidecarSealer).
            Ok(SealArtifacts {
                replica_id: inputs.pinner_identity,
                comm_d: [0xD0; 32],
                comm_r: inputs.pinner_identity,
                comm_c: [0x0C; 32],
                porep_proof: inputs.pinner_identity.to_vec(),
            })
        }
        async fn prove_post(
            &self,
            inputs: &SealInputs,
            challenge_index: u64,
        ) -> Result<Vec<u8>, SealerError> {
            let mut p = inputs.pinner_identity.to_vec();
            p.extend_from_slice(&challenge_index.to_be_bytes());
            Ok(p)
        }
    }

    fn fake_inputs(i: &PinPlanInput) -> SealInputs {
        SealInputs {
            pinner_identity: chainio::pinning::pin_id(i.me, i.cid, i.sector),
            cid: i.cid,
            sector: i.sector,
            epoch: i.current_block,
            data: [[0u8; 32]; 4],
        }
    }

    #[tokio::test]
    async fn seam_seal_then_signer_records() {
        let i = input(none_pin(), slot(true, 9_000, 1), true, 100);
        // Planner says Seal.
        assert_eq!(plan_pin(&i), PinAction::Seal { cid: CID, sector: 0 });
        // Loop: seal via the sealer, build the request, hand to the signer.
        let sealer = FakeSealer;
        let inputs = fake_inputs(&i);
        let sealed = sealer.seal(&inputs).await.expect("seal");
        assert_eq!(sealed.comm_r, inputs.pinner_identity);
        let signer = RecordingPinSigner::default();
        let obs = signer
            .request(seal_commit_request(&i, &sealed, 1))
            .await
            .expect("request");
        assert!(obs.tx_hash.is_none());
        let rec = signer.last.lock().expect("lock").clone().expect("recorded");
        assert_eq!(rec.intent, PinIntent::SealCommit);
        assert_eq!(rec.value_wei, i.bond_wei);
    }
}
