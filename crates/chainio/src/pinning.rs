//! `pinning` — the `IPFSIncentives` (v2/v3) bindings the PIN-S6 pinning daemon
//! needs: write-calldata builders for the pin lifecycle, read decoders for pin
//! and slot state, and the `Challenged` event decode that tells a pinner which
//! nonce to answer.
//!
//! Signatures are taken verbatim from
//! `citrate-chain/contracts/src/IPFSIncentivesV2.sol` (V3 keeps the same
//! sealCommit/claim/returnBond shape and revises the challenge flow to
//! commit-reveal — tracked in sprint PIN-CR-S1; the daemon's challenge path
//! swaps to the V3 calldata when V3 deploys). Every selector used here is
//! pinned in `selectors::selectors_are_pinned` (Rule-11 calldata tripwire).
//!
//! Posture mirrors `marketplace.rs`: pure encode/decode, no I/O; the daemon
//! does NOT sign — each write returns calldata the daemon wraps in an unsigned
//! `SignatureRequest` for the relay (ADR-agent-signing). The on-chain contract
//! is the source of truth for pin/slot state; the daemon reads it, never
//! caches authority.

use crate::abi::{self, AbiError, Address, Decoder, Word};
use crate::selectors;

/// Lifecycle status of a pin, mirroring `IPFSIncentivesV2.Status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinStatus {
    /// No pin (re-sealable).
    None,
    /// Sealed + bonded; answering rolling challenges.
    Active,
    /// Fully vested; bond returnable once fully claimed.
    Done,
    /// Slashed; must `clearSlashed` before re-seal.
    Slashed,
}

impl PinStatus {
    fn from_u8(v: u8) -> Result<Self, AbiError> {
        match v {
            0 => Ok(PinStatus::None),
            1 => Ok(PinStatus::Active),
            2 => Ok(PinStatus::Done),
            3 => Ok(PinStatus::Slashed),
            _ => Err(AbiError::Overflow),
        }
    }
}

/// The subset of `getPin(address,bytes32,uint256)` the daemon drives on:
/// `(Status, uint64 round, uint64 missed, uint256 claimed, uint256 bondHeld,
///   bool challengeOpen, uint256 challengeDeadline, uint256 challengeNonce)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinState {
    pub status: PinStatus,
    pub round: u128,
    pub missed: u128,
    pub claimed: u128,
    pub bond_held: u128,
    pub challenge_open: bool,
    pub challenge_deadline: u128,
    pub challenge_nonce: Word,
}

/// `getSlot(bytes32,uint256) -> (bool funded, uint256 budget, uint256 liveCount)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotState {
    pub funded: bool,
    pub budget: u128,
    pub live_count: u128,
}

fn b32(x: [u8; 32]) -> Word {
    x
}

fn u256_word(v: u128) -> Word {
    abi::word_from_u128(v)
}

// ───────────────────────────── read calldata ───────────────────────────────

/// `registered(address)` — has this address completed KYC-gated registration?
pub fn encode_registered(who: Address) -> Vec<u8> {
    abi::encode_call(selectors::pin_registered(), &[abi::word_from_address(who)])
}

/// `unallocatedSlotFunding()` — governance backing not yet assigned to a slot.
pub fn encode_unallocated_slot_funding() -> Vec<u8> {
    abi::encode_call(selectors::pin_unallocated_slot_funding(), &[])
}

/// Decode the `unallocatedSlotFunding()` return.
pub fn decode_unallocated_slot_funding(data: &[u8]) -> Result<u128, AbiError> {
    Decoder::new(data).u128()
}

/// `getPin(address pinner, bytes32 cid, uint256 sector)`.
pub fn encode_get_pin(pinner: Address, cid: [u8; 32], sector: u128) -> Vec<u8> {
    abi::encode_call(
        selectors::pin_get_pin(),
        &[abi::word_from_address(pinner), b32(cid), u256_word(sector)],
    )
}

/// `getSlot(bytes32 cid, uint256 sector)`.
pub fn encode_get_slot(cid: [u8; 32], sector: u128) -> Vec<u8> {
    abi::encode_call(selectors::pin_get_slot(), &[b32(cid), u256_word(sector)])
}

/// `owedOf(address pinner, bytes32 cid, uint256 sector)`.
pub fn encode_owed_of(pinner: Address, cid: [u8; 32], sector: u128) -> Vec<u8> {
    abi::encode_call(
        selectors::pin_owed_of(),
        &[abi::word_from_address(pinner), b32(cid), u256_word(sector)],
    )
}

// ─────────────────────────── write calldata ─────────────────────────────────

/// `registerPinner()` — KYC-gated; reverts if the caller is not KYC-verified.
pub fn encode_register_pinner() -> Vec<u8> {
    abi::encode_call(selectors::pin_register_pinner(), &[])
}

/// `sealCommit(bytes32 cid, uint256 sector, bytes32 replicaID, uint256 epoch,
///   bytes32 commD, bytes32 commR, bytes32 commC, bytes porepProof)`. The
///   `replicaID` is the CIRCUIT's Poseidon value (the daemon supplies it; the
///   contract binds it 1:1 to the pinner — PIN-S6 finding), `epoch` the seal
///   epoch the proof committed. `porepProof` is the only dynamic arg.
#[allow(clippy::too_many_arguments)]
pub fn encode_seal_commit(
    cid: [u8; 32],
    sector: u128,
    replica_id: [u8; 32],
    epoch: u128,
    comm_d: [u8; 32],
    comm_r: [u8; 32],
    comm_c: [u8; 32],
    porep_proof: &[u8],
) -> Vec<u8> {
    // Head: cid + sector + replicaID + epoch + commD + commR + commC + proofOffset = 8 words.
    const HEAD_LEN: usize = 8 * 32;
    let proof_tail = abi::encode_bytes_tail(porep_proof);
    let mut out = Vec::with_capacity(4 + HEAD_LEN + proof_tail.len());
    out.extend_from_slice(&selectors::pin_seal_commit());
    out.extend_from_slice(&b32(cid));
    out.extend_from_slice(&u256_word(sector));
    out.extend_from_slice(&b32(replica_id));
    out.extend_from_slice(&u256_word(epoch));
    out.extend_from_slice(&b32(comm_d));
    out.extend_from_slice(&b32(comm_r));
    out.extend_from_slice(&b32(comm_c));
    out.extend_from_slice(&u256_word(HEAD_LEN as u128)); // proof offset
    out.extend_from_slice(&proof_tail);
    out
}

/// `challenge(bytes32 cid, uint256 sector)` — open a PoSt challenge for one's
/// own active pin (self-challenge; V3 adds third-party bonded challenges).
pub fn encode_challenge(cid: [u8; 32], sector: u128) -> Vec<u8> {
    abi::encode_call(selectors::pin_challenge(), &[b32(cid), u256_word(sector)])
}

/// `submitPoSt(bytes32 cid, uint256 sector, bytes32 commR, bytes32 commC,
///   uint256 challengeNonce, bytes postProof)`. `postProof` is the only
/// dynamic arg.
pub fn encode_submit_post(
    cid: [u8; 32],
    sector: u128,
    comm_r: [u8; 32],
    comm_c: [u8; 32],
    challenge_nonce: Word,
    post_proof: &[u8],
) -> Vec<u8> {
    // Head: cid + sector + commR + commC + challengeNonce + proofOffset = 6 words.
    const HEAD_LEN: usize = 6 * 32;
    let proof_tail = abi::encode_bytes_tail(post_proof);
    let mut out = Vec::with_capacity(4 + HEAD_LEN + proof_tail.len());
    out.extend_from_slice(&selectors::pin_submit_post());
    out.extend_from_slice(&b32(cid));
    out.extend_from_slice(&u256_word(sector));
    out.extend_from_slice(&b32(comm_r));
    out.extend_from_slice(&b32(comm_c));
    out.extend_from_slice(&challenge_nonce);
    out.extend_from_slice(&u256_word(HEAD_LEN as u128)); // proof offset
    out.extend_from_slice(&proof_tail);
    out
}

/// `claim(bytes32 cid, uint256 sector)` — withdraw vested-but-unclaimed reward.
pub fn encode_claim(cid: [u8; 32], sector: u128) -> Vec<u8> {
    abi::encode_call(selectors::pin_claim(), &[b32(cid), u256_word(sector)])
}

/// `returnBond(bytes32 cid, uint256 sector)` — reclaim bond once Done + fully
/// claimed.
pub fn encode_return_bond(cid: [u8; 32], sector: u128) -> Vec<u8> {
    abi::encode_call(selectors::pin_return_bond(), &[b32(cid), u256_word(sector)])
}

// ─────────────────────────── return decoders ────────────────────────────────

/// Decode the `getPin` return tuple.
pub fn decode_pin(data: &[u8]) -> Result<PinState, AbiError> {
    let mut d = Decoder::new(data);
    let status = PinStatus::from_u8(d.u8_enum()?)?;
    let round = d.u128()?;
    let missed = d.u128()?;
    let claimed = d.u128()?;
    let bond_held = d.u128()?;
    let challenge_open = d.bool()?;
    let challenge_deadline = d.u128()?;
    let challenge_nonce = d.word()?;
    Ok(PinState {
        status,
        round,
        missed,
        claimed,
        bond_held,
        challenge_open,
        challenge_deadline,
        challenge_nonce,
    })
}

/// Decode the `getSlot` return tuple.
pub fn decode_slot(data: &[u8]) -> Result<SlotState, AbiError> {
    let mut d = Decoder::new(data);
    let funded = d.bool()?;
    let budget = d.u128()?;
    let live_count = d.u128()?;
    Ok(SlotState {
        funded,
        budget,
        live_count,
    })
}

/// Decode `owedOf`'s single `uint256` return.
pub fn decode_owed(data: &[u8]) -> Result<u128, AbiError> {
    Decoder::new(data).u128()
}

/// Decode `registered`'s single `bool` return.
pub fn decode_registered(data: &[u8]) -> Result<bool, AbiError> {
    Decoder::new(data).bool()
}

// ────────────────────────────── events ──────────────────────────────────────

/// `keccak256("Challenged(bytes32,uint256,uint256,uint256)")` — topic0 of the
/// event the daemon watches to learn an open challenge's nonce + deadline.
/// `pinId` is indexed (topic1); `(challengeNonce, deadline, counter)` are in
/// `data`. Pinned in the unit tests below.
pub fn challenged_topic0() -> [u8; 32] {
    let mut k = tiny_keccak::Keccak::v256();
    let mut out = [0u8; 32];
    use tiny_keccak::Hasher as _;
    k.update(b"Challenged(bytes32,uint256,uint256,uint256)");
    k.finalize(&mut out);
    out
}

/// The non-indexed payload of a `Challenged` log: `(nonce, deadline, counter)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengedEvent {
    /// Indexed `pinId` (topic1).
    pub pin_id: [u8; 32],
    /// The contract-derived nonce the PoSt proof must commit to.
    pub challenge_nonce: Word,
    /// Block-number deadline for the response.
    pub deadline: u128,
    /// Monotonic per-pin challenge counter (seed domain separation).
    pub counter: u128,
}

/// Decode a `Challenged` log given its topic1 (`pinId`) and `data` payload.
pub fn decode_challenged(pin_id_topic: [u8; 32], data: &[u8]) -> Result<ChallengedEvent, AbiError> {
    let mut d = Decoder::new(data);
    let challenge_nonce = d.word()?;
    let deadline = d.u128()?;
    let counter = d.u128()?;
    Ok(ChallengedEvent {
        pin_id: pin_id_topic,
        challenge_nonce,
        deadline,
        counter,
    })
}

/// `pinId = keccak256(abi.encode(pinner, cid, sector))` — the on-chain key.
/// Mirrors `IPFSIncentivesV2.pinId`. Used to match a `Challenged` log's
/// indexed topic to one of our pins.
pub fn pin_id(pinner: Address, cid: [u8; 32], sector: u128) -> [u8; 32] {
    let mut buf = Vec::with_capacity(96);
    buf.extend_from_slice(&abi::word_from_address(pinner));
    buf.extend_from_slice(&cid);
    buf.extend_from_slice(&u256_word(sector));
    let mut k = tiny_keccak::Keccak::v256();
    let mut out = [0u8; 32];
    use tiny_keccak::Hasher as _;
    k.update(&buf);
    k.finalize(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CID: [u8; 32] = [0x11; 32];
    const COMM_D: [u8; 32] = [0xD0; 32];
    const PINNER: Address = [0xBE; 20];

    fn word_u128(v: u128) -> Word {
        abi::word_from_u128(v)
    }

    fn hex_lower(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn seal_commit_calldata_shape() {
        let proof = vec![0xAB, 0xCD, 0xEF];
        let rid = [0x9A; 32];
        let cd = encode_seal_commit(CID, 7, rid, 42, COMM_D, [0x0C; 32], [0x0E; 32], &proof);
        // 8 head words: cid, sector, replicaID, epoch, commD, commR, commC, proofOffset.
        assert_eq!(&cd[0..4], &selectors::pin_seal_commit());
        assert_eq!(&cd[4..36], &CID); // word 0: cid
        assert_eq!(&cd[36..68], &word_u128(7)); // word 1: sector
        assert_eq!(&cd[68..100], &rid); // word 2: replicaID
        assert_eq!(&cd[100..132], &word_u128(42)); // word 3: epoch
        assert_eq!(&cd[132..164], &COMM_D); // word 4: commD
        // proof offset = 8*32 = 256 (word 7)
        assert_eq!(&cd[4 + 7 * 32..4 + 8 * 32], &word_u128(256));
        // proof length word + padded bytes
        assert_eq!(&cd[4 + 8 * 32..4 + 9 * 32], &word_u128(3));
        assert_eq!(&cd[4 + 9 * 32..4 + 9 * 32 + 3], &proof[..]);
        assert_eq!(cd.len(), 4 + 8 * 32 + 32 + 32);
    }

    #[test]
    fn submit_post_calldata_shape() {
        let proof = vec![0x01, 0x02];
        let nonce = word_u128(5);
        let cd = encode_submit_post(CID, 0, [0x0C; 32], [0x0E; 32], nonce, &proof);
        assert_eq!(&cd[0..4], &selectors::pin_submit_post());
        // challengeNonce at head word index 4 (cid, sector, commR, commC, nonce)
        assert_eq!(&cd[4 + 4 * 32..4 + 5 * 32], &nonce);
        // proof offset = 192
        assert_eq!(&cd[4 + 5 * 32..4 + 6 * 32], &word_u128(192));
        assert_eq!(&cd[4 + 6 * 32..4 + 7 * 32], &word_u128(2));
    }

    #[test]
    fn small_calldata_shapes() {
        assert_eq!(encode_register_pinner(), selectors::pin_register_pinner().to_vec());
        let ch = encode_challenge(CID, 3);
        assert_eq!(&ch[0..4], &selectors::pin_challenge());
        assert_eq!(&ch[4..36], &CID);
        assert_eq!(&ch[36..68], &word_u128(3));
        let cl = encode_claim(CID, 3);
        assert_eq!(&cl[0..4], &selectors::pin_claim());
    }

    #[test]
    fn decode_get_pin_roundtrip() {
        // Build an ABI return for getPin: status=1, round=2, missed=0,
        // claimed=100, bondHeld=1000, challengeOpen=true, deadline=42,
        // nonce=0x07..(word).
        let mut data = Vec::new();
        data.extend_from_slice(&word_u128(1)); // status Active
        data.extend_from_slice(&word_u128(2)); // round
        data.extend_from_slice(&word_u128(0)); // missed
        data.extend_from_slice(&word_u128(100)); // claimed
        data.extend_from_slice(&word_u128(1000)); // bondHeld
        data.extend_from_slice(&word_u128(1)); // challengeOpen true
        data.extend_from_slice(&word_u128(42)); // deadline
        let mut nonce = [0u8; 32];
        nonce[31] = 7;
        data.extend_from_slice(&nonce); // challengeNonce

        let p = decode_pin(&data).expect("decode");
        assert_eq!(p.status, PinStatus::Active);
        assert_eq!(p.round, 2);
        assert_eq!(p.claimed, 100);
        assert_eq!(p.bond_held, 1000);
        assert!(p.challenge_open);
        assert_eq!(p.challenge_deadline, 42);
        assert_eq!(p.challenge_nonce, nonce);
    }

    #[test]
    fn decode_get_slot_roundtrip() {
        let mut data = Vec::new();
        data.extend_from_slice(&word_u128(1)); // funded
        data.extend_from_slice(&word_u128(8000)); // budget
        data.extend_from_slice(&word_u128(2)); // liveCount
        let s = decode_slot(&data).expect("decode");
        assert!(s.funded);
        assert_eq!(s.budget, 8000);
        assert_eq!(s.live_count, 2);
    }

    #[test]
    fn challenged_topic0_is_pinned() {
        // keccak256("Challenged(bytes32,uint256,uint256,uint256)") — pinned so
        // a contract event-signature change can't silently desync the watcher.
        assert_eq!(
            hex_lower(&challenged_topic0()),
            "6d0c7ac7c3b4a4b8e1282022fe50e407dde9a351da86229791dab8a6c15eac40"
        );
    }

    #[test]
    fn decode_challenged_payload() {
        let mut data = Vec::new();
        let mut nonce = [0u8; 32];
        nonce[31] = 9;
        data.extend_from_slice(&nonce); // challengeNonce
        data.extend_from_slice(&word_u128(120)); // deadline
        data.extend_from_slice(&word_u128(3)); // counter
        let topic1 = [0xAB; 32];
        let ev = decode_challenged(topic1, &data).expect("decode");
        assert_eq!(ev.pin_id, topic1);
        assert_eq!(ev.challenge_nonce, nonce);
        assert_eq!(ev.deadline, 120);
        assert_eq!(ev.counter, 3);
    }

    #[test]
    fn pin_id_matches_contract() {
        // Reference vector from `cast keccak (abi-encode(address,bytes32,uint256))`
        // for (0xbebe…be, 0x11*32, 7) — must equal IPFSIncentivesV2.pinId on-chain.
        assert_eq!(
            hex_lower(&pin_id(PINNER, CID, 7)),
            "ccd6278d751ff0de84dd77c60b37d6f6f6bbe6810a6b7495ece0dc8a1f0e15be"
        );
    }
}
