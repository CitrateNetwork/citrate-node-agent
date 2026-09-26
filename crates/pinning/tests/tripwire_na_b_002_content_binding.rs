//! Tripwire for NA-B-002 (2026-09-02 federation graded audit, Leg B).
//!
//! The PIN proof-of-storage seal was not bound to any stored bytes: the reduced
//! circuit's four `data` field elements were `keccak("PIN-reduced-data" || cid
//! || sector || i)` — functions of *public* on-chain values only. A pinner
//! storing NOTHING produced the same PoRep/PoSt public inputs as one storing the
//! model, so the daemon posted a real on-chain BOND behind a proof of nothing
//! and any sybil could farm the reward stream while storing zero bytes.
//!
//! The fix binds `data` to the actual locally-held replica bytes and makes the
//! function refuse to build seal inputs when no replica is present.
//!
//! RED at the pin: `seal_inputs` takes no replica handle (3-arg, infallible), so
//! this file — which requires the handle and the `Result` — does not compile.
//! That compile failure IS the finding: "the function's signature requires a
//! replica handle" does not hold on the pinned code.
//! GREEN after the fix: it compiles and the content-binding assertions pass.

use pinning::runloop::{seal_inputs, PinConfig};

fn cfg() -> PinConfig {
    PinConfig {
        me: [0xBE; 20],
        incentives: [0x1F; 20],
        chain_id: 40204,
        quorum: 3,
        rounds: 4,
        per_round: 1_000,
        bond_wei: 10_000,
        reward_wei: 4_000,
        challenge_n: 4,
    }
}

const CID: [u8; 32] = [0x11; 32];

#[test]
fn seal_inputs_are_bound_to_the_stored_replica_bytes() {
    let cfg = cfg();

    // Two nodes, SAME public (cid, sector), DIFFERENT local bytes. If the seal
    // is content-bound their `data` must differ — a pinner storing nothing (or
    // different bytes) cannot reproduce the honest pinner's public inputs.
    let a = seal_inputs(&cfg, CID, 0, b"the-real-model-weights-AAAA").expect("replica A seals");
    let b = seal_inputs(&cfg, CID, 0, b"the-real-model-weights-BBBB").expect("replica B seals");
    assert_ne!(
        a.data, b.data,
        "NA-B-002: seal `data` is NOT content-bound — two different replicas for \
         the same (cid,sector) produced identical public inputs"
    );

    // Deterministic for the SAME replica (seal↔PoSt must reproduce).
    let a2 = seal_inputs(&cfg, CID, 0, b"the-real-model-weights-AAAA").expect("re-seal A");
    assert_eq!(a.data, a2.data, "same replica must reproduce the same seal inputs");

    // No local replica → refuse to build seal inputs (never bond a proof of
    // nothing).
    assert!(
        seal_inputs(&cfg, CID, 0, b"").is_err(),
        "NA-B-002: sealing must be refused when no replica bytes are present"
    );

    println!("NA-B-002 GREEN: seal inputs are bound to the stored replica bytes");
}
