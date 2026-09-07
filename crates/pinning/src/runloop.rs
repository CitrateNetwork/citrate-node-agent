//! `runloop` — the PIN-S6 daemon tick: wire on-chain reads → [`plan_pin`] →
//! the [`Sealer`] (for seal/prove) → the [`PinSigner`] (unsigned writes).
//!
//! This is the integration seam between the pure planner and the live world.
//! It is generic over three traits so it's fully testable with fakes:
//!   - [`PinChainView`] — reads pin/slot/registered state + the chain head
//!     (the real impl is over `chainio`'s eth_call client);
//!   - [`Sealer`] (lib.rs) — the seal/prove sidecar;
//!   - [`PinSigner`] (lib.rs) — the no-keys relay.
//!
//! One [`tick_pin`] call advances ONE (cid, sector) by at most one on-chain
//! write. The daemon loops it across its configured targets each interval; the
//! daemon never holds keys — every write is an UNSIGNED request the relay signs.

use crate::{
    plan_pin, seal_commit_request, submit_post_request, PinAction, PinPlanInput, PinSigner,
    PinSignerError, PinTxObserved, SealInputs, Sealer, SealerError,
};
use chainio::abi::Address;
use chainio::pinning::{PinState, SlotState};

/// Read-side seam: the live pin/slot/registration state the planner needs.
/// The real impl wraps `chainio`'s `eth_call` client; fakes drive tests.
pub trait PinChainView {
    /// Has `me` completed KYC-gated `registerPinner()`?
    fn registered(
        &self,
        me: Address,
    ) -> impl std::future::Future<Output = Result<bool, ViewError>> + Send;
    /// `getPin(me, cid, sector)`.
    fn pin(
        &self,
        me: Address,
        cid: [u8; 32],
        sector: u128,
    ) -> impl std::future::Future<Output = Result<PinState, ViewError>> + Send;
    /// `getSlot(cid, sector)`.
    fn slot(
        &self,
        cid: [u8; 32],
        sector: u128,
    ) -> impl std::future::Future<Output = Result<SlotState, ViewError>> + Send;
    /// The current chain head (block number) — for the deadline guard.
    fn current_block(&self) -> impl std::future::Future<Output = Result<u128, ViewError>> + Send;
}

/// Error reading chain state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewError(pub String);

impl core::fmt::Display for ViewError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "chain view error: {}", self.0)
    }
}

/// Static per-deployment config the planner + sealer need (mirrored from the
/// `IPFSIncentives` immutables + node identity).
#[derive(Debug, Clone)]
pub struct PinConfig {
    pub me: Address,
    pub incentives: Address,
    pub chain_id: u64,
    pub quorum: u128,
    pub rounds: u128,
    pub per_round: u128,
    pub bond_wei: u128,
    /// `CHALLENGE_N` — at the reduced size this == N (4), so an on-chain nonce
    /// indexes a real circuit node. The challenge index passed to the prover is
    /// `nonce % challenge_n`.
    pub challenge_n: u64,
}

/// What the tick did (for `/health` + logs). At most one write per tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TickOutcome {
    /// Planner said nothing to do.
    Idle,
    /// Planner held with a reason (slot full, slashed, window closed, …).
    Hold(crate::HoldReason),
    /// A `Sign` write (register/claim/challenge/return-bond) was requested.
    Requested(crate::PinIntent, PinTxObserved),
    /// A seal was produced + `sealCommit` requested.
    Sealed(PinTxObserved),
    /// A PoSt was produced + `submitPoSt` requested.
    Proved(PinTxObserved),
}

/// Error advancing a pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TickError {
    View(ViewError),
    Seal(SealerError),
    Sign(PinSignerError),
}

impl core::fmt::Display for TickError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TickError::View(e) => write!(f, "{e}"),
            TickError::Seal(e) => write!(f, "{e}"),
            TickError::Sign(e) => write!(f, "{e}"),
        }
    }
}

/// Read-side seam for the locally-held replica bytes of one (cid, sector).
///
/// NA-B-002: the seal MUST be bound to the bytes the node actually stores. This
/// returns the pinner's local replica for the CID/sector; an `Err` (or empty
/// bytes) means "no replica present", which makes [`seal_inputs`] refuse to
/// build a seal — the daemon can never post a bond behind a proof of nothing.
/// The concrete production source (the local content store / verified fetch) is
/// the wiring follow-up; the point closed here is that content is *required*.
pub trait ReplicaSource {
    fn replica(
        &self,
        cid: [u8; 32],
        sector: u128,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, ViewError>> + Send;
}

/// Derive the reduced circuit's `SealInputs` for one (cid, sector),
/// DETERMINISTICALLY — so the daemon reproduces the exact same seal at PoSt time
/// without reading any per-seal state back from the chain (getPin doesn't expose
/// epoch/data). The pinner identity is the node's address (the private pre-image
/// of replicaID); `epoch` is keccak-derived from (cid, sector).
///
/// NA-B-002: the 4 reduced content elements are derived from the actual stored
/// `replica` bytes (not from the public (cid, sector) pair), so a pinner storing
/// nothing — or different bytes — cannot reproduce the honest pinner's public
/// inputs. Sealing is refused (`Err`) when no replica is present: never bond a
/// proof of nothing. (Reduced testnet instance; real-size chunk sampling is
/// PIN-P1 f.6, same content-bound interface.)
pub fn seal_inputs(
    cfg: &PinConfig,
    cid: [u8; 32],
    sector: u128,
    replica: &[u8],
) -> Result<SealInputs, SealerError> {
    use tiny_keccak::Hasher as _;
    if replica.is_empty() {
        return Err(SealerError::Replica(format!(
            "no local replica bytes for cid {} sector {sector}; refusing to seal a \
             proof not bound to stored content (NA-B-002)",
            hex::encode(cid)
        )));
    }

    let mut pinner_identity = [0u8; 32];
    pinner_identity[12..32].copy_from_slice(&cfg.me); // address → field element (left-padded)

    // Content-bound: fold the stored replica bytes into every element. Public
    // (cid, sector) still salt it (so replicas differ per slot), but the bytes
    // are load-bearing — the proof attests to possession of *these* bytes.
    let derive = |tag: &[u8], i: u8| -> [u8; 32] {
        let mut k = tiny_keccak::Keccak::v256();
        let mut out = [0u8; 32];
        k.update(tag);
        k.update(&cid);
        k.update(&sector.to_be_bytes());
        k.update(&[i]);
        k.update(replica); // NA-B-002: the stored bytes are part of the pre-image
        k.finalize(&mut out);
        out[0] = 0; // keep < 2^248 < BN254 modulus (canonical field element)
        out
    };

    let mut data = [[0u8; 32]; 4];
    for (i, slot) in data.iter_mut().enumerate() {
        *slot = derive(b"PIN-reduced-data", i as u8);
    }
    // Deterministic epoch in the low 8 bytes (stable seal↔PoSt; the contract
    // just echoes whatever epoch was sealed). Epoch is an on-chain-echoed value,
    // not part of the content attestation, so it stays (cid, sector)-derived.
    let mut ke = tiny_keccak::Keccak::v256();
    let mut e = [0u8; 32];
    ke.update(b"PIN-epoch");
    ke.update(&cid);
    ke.update(&sector.to_be_bytes());
    ke.update(&[0]);
    ke.finalize(&mut e);
    let mut low = [0u8; 8];
    low.copy_from_slice(&e[24..32]);
    let epoch = u64::from_be_bytes(low) as u128;

    Ok(SealInputs {
        pinner_identity,
        cid,
        sector,
        epoch,
        data,
    })
}

/// Advance one (cid, sector) by at most one on-chain write.
///
/// NA-B-002: `replicas` supplies the locally-stored bytes the seal is bound to.
/// If they are absent, `seal_inputs` refuses and the tick errors — the daemon
/// never posts a bond behind a proof not bound to stored content.
pub async fn tick_pin<V: PinChainView, S: Sealer, G: PinSigner, R: ReplicaSource>(
    view: &V,
    sealer: &S,
    signer: &G,
    replicas: &R,
    cfg: &PinConfig,
    cid: [u8; 32],
    sector: u128,
) -> Result<TickOutcome, TickError> {
    let registered = view.registered(cfg.me).await.map_err(TickError::View)?;
    let pin = view.pin(cfg.me, cid, sector).await.map_err(TickError::View)?;
    let slot = view.slot(cid, sector).await.map_err(TickError::View)?;
    let current_block = view.current_block().await.map_err(TickError::View)?;

    let input = PinPlanInput {
        me: cfg.me,
        cid,
        sector,
        registered,
        pin,
        slot,
        quorum: cfg.quorum,
        rounds: cfg.rounds,
        per_round: cfg.per_round,
        current_block,
        incentives: cfg.incentives,
        bond_wei: cfg.bond_wei,
        chain_id: cfg.chain_id,
    };

    match plan_pin(&input) {
        PinAction::Idle => Ok(TickOutcome::Idle),
        PinAction::Hold(r) => Ok(TickOutcome::Hold(r)),
        PinAction::Sign(req) => {
            let intent = req.intent;
            let obs = signer.request(req).await.map_err(TickError::Sign)?;
            Ok(TickOutcome::Requested(intent, obs))
        }
        PinAction::Seal { cid, sector } => {
            // NA-B-002: fetch the locally-stored replica and bind the seal to it;
            // no bytes → no seal → no bond.
            let bytes = replicas
                .replica(cid, sector)
                .await
                .map_err(|e| TickError::Seal(SealerError::Replica(e.0)))?;
            let inputs = seal_inputs(cfg, cid, sector, &bytes).map_err(TickError::Seal)?;
            let sealed = sealer.seal(&inputs).await.map_err(TickError::Seal)?;
            let req = seal_commit_request(&input, &sealed, inputs.epoch);
            let obs = signer.request(req).await.map_err(TickError::Sign)?;
            Ok(TickOutcome::Sealed(obs))
        }
        PinAction::Prove {
            cid,
            sector,
            nonce,
            deadline,
        } => {
            // The seal is deterministic, so reconstruct the artifacts (CommR/
            // CommC the submitPoSt wire needs) by re-sealing, then prove PoSt at
            // the committed-nonce index (reduced: CHALLENGE_N == N → indexes a
            // real node). [Re-seal is cheap at reduced size; a real-size daemon
            // caches the original SealArtifacts — follow-up.]
            // NA-B-002: re-bind to the same stored bytes so the PoSt answer
            // attests to possession of content, not of a public (cid, sector).
            let bytes = replicas
                .replica(cid, sector)
                .await
                .map_err(|e| TickError::Seal(SealerError::Replica(e.0)))?;
            let inputs = seal_inputs(cfg, cid, sector, &bytes).map_err(TickError::Seal)?;
            let sealed = sealer.seal(&inputs).await.map_err(TickError::Seal)?;
            let challenge_index = nonce_to_index(&nonce, cfg.challenge_n);
            let proof = sealer
                .prove_post(&inputs, challenge_index)
                .await
                .map_err(TickError::Seal)?;
            let req = submit_post_request(&input, &sealed, nonce, deadline, &proof);
            let obs = signer.request(req).await.map_err(TickError::Sign)?;
            Ok(TickOutcome::Proved(obs))
        }
    }
}

/// Map an on-chain 32-byte committed nonce to a reduced-circuit challenge index.
fn nonce_to_index(nonce: &[u8; 32], challenge_n: u64) -> u64 {
    // The contract stores `nonce = uint(keccak(seed)) % CHALLENGE_N`, so it
    // already fits; take the low 8 bytes mod challenge_n defensively.
    let mut low = [0u8; 8];
    low.copy_from_slice(&nonce[24..32]);
    let v = u64::from_be_bytes(low);
    if challenge_n == 0 {
        0
    } else {
        v % challenge_n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HoldReason, PinIntent, PinSignatureRequest, PinStatus, SealArtifacts};
    use std::sync::Mutex;

    const ME: Address = [0xBE; 20];
    const INC: Address = [0x1F; 20];
    const CID: [u8; 32] = [0x11; 32];

    fn cfg() -> PinConfig {
        PinConfig {
            me: ME,
            incentives: INC,
            chain_id: 40204,
            quorum: 3,
            rounds: 4,
            per_round: 1_000,
            bond_wei: 10_000,
            challenge_n: 4,
        }
    }

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

    struct FakeView {
        registered: bool,
        pin: PinState,
        slot: SlotState,
        block: u128,
    }
    impl PinChainView for FakeView {
        async fn registered(&self, _me: Address) -> Result<bool, ViewError> {
            Ok(self.registered)
        }
        async fn pin(&self, _m: Address, _c: [u8; 32], _s: u128) -> Result<PinState, ViewError> {
            Ok(self.pin.clone())
        }
        async fn slot(&self, _c: [u8; 32], _s: u128) -> Result<SlotState, ViewError> {
            Ok(self.slot.clone())
        }
        async fn current_block(&self) -> Result<u128, ViewError> {
            Ok(self.block)
        }
    }

    /// A replica source that always holds bytes for any (cid, sector).
    struct HasReplica;
    impl ReplicaSource for HasReplica {
        async fn replica(&self, cid: [u8; 32], sector: u128) -> Result<Vec<u8>, ViewError> {
            // Distinct-per-slot stand-in bytes; the point is that *some* stored
            // content exists and is folded into the seal.
            let mut b = b"stored-replica:".to_vec();
            b.extend_from_slice(&cid);
            b.extend_from_slice(&sector.to_be_bytes());
            Ok(b)
        }
    }

    /// A replica source that stores nothing — the sybil "store zero bytes" case.
    struct NoReplica;
    impl ReplicaSource for NoReplica {
        async fn replica(&self, _cid: [u8; 32], _sector: u128) -> Result<Vec<u8>, ViewError> {
            Ok(Vec::new())
        }
    }

    struct FakeSealer;
    impl Sealer for FakeSealer {
        async fn seal(&self, inputs: &SealInputs) -> Result<SealArtifacts, SealerError> {
            Ok(SealArtifacts {
                replica_id: inputs.pinner_identity,
                comm_d: [0xD0; 32],
                comm_r: [0x12; 32],
                comm_c: [0x0C; 32],
                porep_proof: vec![0xAB, 0xCD],
            })
        }
        async fn prove_post(&self, _i: &SealInputs, idx: u64) -> Result<Vec<u8>, SealerError> {
            Ok(idx.to_be_bytes().to_vec())
        }
    }

    #[derive(Default)]
    struct RecordingSigner {
        last: Mutex<Option<PinSignatureRequest>>,
    }
    impl PinSigner for RecordingSigner {
        async fn request(
            &self,
            req: PinSignatureRequest,
        ) -> Result<PinTxObserved, PinSignerError> {
            *self.last.lock().expect("lock") = Some(req);
            Ok(PinTxObserved { tx_hash: None })
        }
    }

    fn slot(funded: bool, budget: u128, live: u128) -> SlotState {
        SlotState {
            funded,
            budget,
            live_count: live,
        }
    }

    #[tokio::test]
    async fn tick_unregistered_requests_register() {
        let view = FakeView {
            registered: false,
            pin: none_pin(),
            slot: slot(true, 9_000, 0),
            block: 100,
        };
        let signer = RecordingSigner::default();
        let out = tick_pin(&view, &FakeSealer, &signer, &HasReplica, &cfg(), CID, 0)
            .await
            .expect("tick");
        assert!(matches!(
            out,
            TickOutcome::Requested(PinIntent::RegisterPinner, _)
        ));
    }

    #[tokio::test]
    async fn tick_registered_seals_and_requests_sealcommit() {
        let view = FakeView {
            registered: true,
            pin: none_pin(),
            slot: slot(true, 9_000, 1),
            block: 100,
        };
        let signer = RecordingSigner::default();
        let out = tick_pin(&view, &FakeSealer, &signer, &HasReplica, &cfg(), CID, 0)
            .await
            .expect("tick");
        assert!(matches!(out, TickOutcome::Sealed(_)));
        let rec = signer.last.lock().expect("lock").clone().expect("recorded");
        assert_eq!(rec.intent, PinIntent::SealCommit);
        assert_eq!(rec.value_wei, 10_000);
        assert_eq!(&rec.calldata[0..4], &chainio::selectors::pin_seal_commit());
    }

    // NA-B-002: a seal-ready slot with NO locally-stored replica must NOT post a
    // bond — the daemon errors instead of sealing a proof of nothing.
    #[tokio::test]
    async fn tick_refuses_to_seal_without_a_stored_replica() {
        let view = FakeView {
            registered: true,
            pin: none_pin(),
            slot: slot(true, 9_000, 1),
            block: 100,
        };
        let signer = RecordingSigner::default();
        let out = tick_pin(&view, &FakeSealer, &signer, &NoReplica, &cfg(), CID, 0).await;
        assert!(
            matches!(out, Err(TickError::Seal(SealerError::Replica(_)))),
            "expected a replica-absent seal refusal, got {out:?}"
        );
        // No bonded sealCommit was ever handed to the signer.
        assert!(signer.last.lock().expect("lock").is_none());
    }

    #[tokio::test]
    async fn tick_full_slot_holds() {
        let view = FakeView {
            registered: true,
            pin: none_pin(),
            slot: slot(true, 9_000, 3),
            block: 100,
        };
        let out = tick_pin(&view, &FakeSealer, &RecordingSigner::default(), &HasReplica, &cfg(), CID, 0)
            .await
            .expect("tick");
        assert_eq!(out, TickOutcome::Hold(HoldReason::SlotAtQuorum));
    }

    #[test]
    fn nonce_index_maps_into_range() {
        let mut n = [0u8; 32];
        n[31] = 7;
        assert_eq!(nonce_to_index(&n, 4), 3); // 7 % 4
        assert_eq!(nonce_to_index(&n, 0), 0);
    }

    // NA-B-002 (RC-8 inversion): the pinned version of this test asserted the
    // vulnerable property — that `data` is derived from the public (cid, sector)
    // pair. It now asserts the secure property: `data` is bound to the STORED
    // replica bytes and sealing is refused without them.
    #[test]
    fn seal_inputs_deterministic_and_content_bound() {
        const R: &[u8] = b"the-real-model-weights";
        let a = seal_inputs(&cfg(), CID, 0, R).expect("replica present");
        let b = seal_inputs(&cfg(), CID, 0, R).expect("replica present");
        assert_eq!(
            a, b,
            "seal inputs must be deterministic for the same replica (seal↔PoSt reproduce)"
        );
        assert_eq!(&a.pinner_identity[12..32], &ME);
        // distinct sector → distinct inputs (epoch + data)
        let c = seal_inputs(&cfg(), CID, 1, R).expect("replica present");
        assert_ne!(a.epoch, c.epoch);
        // data is canonical (high byte zeroed) and per-element distinct
        assert!(a.data.iter().all(|d| d[0] == 0));
        assert_ne!(a.data[0], a.data[1]);
        // CONTENT-BOUND: different stored bytes for the same (cid, sector) yield
        // different data — a pinner storing nothing/other bytes cannot reproduce
        // the honest pinner's public inputs (the whole point of the proof).
        let other = seal_inputs(&cfg(), CID, 0, b"different-bytes-entirely").expect("replica");
        assert_ne!(a.data, other.data, "seal data must depend on the stored bytes");
        // No replica → refuse to seal (never bond a proof of nothing).
        assert!(seal_inputs(&cfg(), CID, 0, b"").is_err());
    }
}
