//! `model_registry` — the one `ModelRegistry` read SELL-S2 needs to provision a
//! model: `getModel(bytes32) -> (…, string ipfsCID, …, bool isActive)`.
//!
//! The executor resolves a job's `modelHash` to **where** to fetch the weights
//! (`ipfsCID`) and **whether** the model is still active (don't run a deactivated
//! model). `getModel`'s return is a flat tuple with four leading `string`s, so we
//! decode by position: the static fields are read in place and the `ipfsCID`
//! string is followed via its head offset.
//!
//! Note on integrity: `getModel` does **not** return `sizeBytes` (only the full
//! `models(bytes32)` struct getter does, which also carries a nested struct). So
//! the size cross-check is optional at this layer; content integrity rests on a
//! CID-addressed fetch (see `executor::models`). Honest seam, logged as tech-debt.

use crate::abi::{AbiError, Address};
use crate::selectors;

/// The subset of `ModelRegistry.getModel` SELL-S2 uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelInfo {
    /// The model owner (head word 0).
    pub owner: Address,
    /// IPFS CID of the weights (head word 4 → tail string).
    pub ipfs_cid: String,
    /// Whether the model is active; a deactivated model must not be run.
    pub is_active: bool,
}

/// `getModel(bytes32 modelHash)` calldata.
pub fn encode_get_model(model_hash: [u8; 32]) -> Vec<u8> {
    crate::abi::encode_call(selectors::get_model(), &[model_hash])
}

/// Read the `i`th 32-byte word of `data`.
///
/// PBA-L6b-023: `i` can come from a hostile offset word, so the byte range is
/// computed with checked arithmetic and an overflow is a decode error.
fn word_at(data: &[u8], i: usize) -> Result<&[u8], AbiError> {
    let start = i.checked_mul(32).ok_or(AbiError::Overflow)?;
    let end = start.checked_add(32).ok_or(AbiError::Overflow)?;
    data.get(start..end).ok_or(AbiError::TooShort {
        need: i.saturating_add(1),
        got: data.len() / 32,
    })
}

/// Interpret a 32-byte big-endian word as a `usize` byte-offset/length (the top
/// bytes must be zero — these are small in practice).
fn be_usize(w: &[u8]) -> Result<usize, AbiError> {
    if w[0..24].iter().any(|&b| b != 0) {
        return Err(AbiError::Overflow);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&w[24..32]);
    usize::try_from(u64::from_be_bytes(buf)).map_err(|_| AbiError::Overflow)
}

/// Decode the ABI return of `getModel(bytes32)`:
/// `(address owner, string name, string framework, string version,
///   string ipfsCID, uint256 inferencePrice, uint256 totalInferences, bool isActive)`.
pub fn decode_get_model(data: &[u8]) -> Result<ModelInfo, AbiError> {
    // head word 0: owner (address, high 12 bytes must be zero).
    let w0 = word_at(data, 0)?;
    if w0[0..12].iter().any(|&b| b != 0) {
        return Err(AbiError::BadAddress);
    }
    let mut owner = [0u8; 20];
    owner.copy_from_slice(&w0[12..32]);

    // head word 4: offset to the ipfsCID string tail.
    let cid_off = be_usize(word_at(data, 4)?)?;

    // head word 7: isActive (bool).
    let w7 = word_at(data, 7)?;
    if w7[0..31].iter().any(|&b| b != 0) {
        return Err(AbiError::BadBool);
    }
    let is_active = match w7[31] {
        0 => false,
        1 => true,
        _ => return Err(AbiError::BadBool),
    };

    // ipfsCID tail: a length word followed by the UTF-8 bytes.
    let len_word = word_at(data, cid_off / 32)?;
    // cid_off is always a multiple of 32 in canonical encoding; guard anyway.
    if cid_off % 32 != 0 {
        return Err(AbiError::BadHex);
    }
    let len = be_usize(len_word)?;
    // PBA-L6b-023: offset and length are attacker-shaped (RPC / registry), so
    // every step is checked; an overflow or out-of-range slice is an error.
    let start = cid_off.checked_add(32).ok_or(AbiError::Overflow)?;
    let end = start.checked_add(len).ok_or(AbiError::Overflow)?;
    let bytes = data.get(start..end).ok_or(AbiError::TooShort {
        need: end.div_ceil(32),
        got: data.len() / 32,
    })?;
    let ipfs_cid = String::from_utf8(bytes.to_vec()).map_err(|_| AbiError::BadString)?;

    Ok(ModelInfo {
        owner,
        ipfs_cid,
        is_active,
    })
}

/// Live-RPC helper (gated by `CITRATE_RPC_URL` in tests).
pub mod live {
    use super::*;
    use crate::abi::Address;
    use crate::rpc::{RpcClient, RpcError};

    /// Read a model's `ipfsCID` + `isActive` from `ModelRegistry.getModel`.
    pub async fn get_model(
        client: &RpcClient,
        registry: Address,
        model_hash: [u8; 32],
    ) -> Result<ModelInfo, RpcError> {
        let data = client
            .eth_call(registry, &encode_get_model(model_hash))
            .await?;
        Ok(decode_get_model(&data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{word_from_address, word_from_u128};

    /// Build a synthetic `getModel` return with empty name/framework/version and
    /// the given `ipfsCID` + `isActive`.
    fn synth_return(owner: Address, cid: &str, is_active: bool) -> Vec<u8> {
        // head = 8 words (256 bytes). Empty strings are a single length-0 word.
        let off_name = 256u128;
        let off_framework = 288u128;
        let off_version = 320u128;
        let off_cid = 352u128;

        let mut d = Vec::new();
        d.extend_from_slice(&word_from_address(owner)); // 0: owner
        d.extend_from_slice(&word_from_u128(off_name)); // 1: name offset
        d.extend_from_slice(&word_from_u128(off_framework)); // 2: framework offset
        d.extend_from_slice(&word_from_u128(off_version)); // 3: version offset
        d.extend_from_slice(&word_from_u128(off_cid)); // 4: ipfsCID offset
        d.extend_from_slice(&word_from_u128(7)); // 5: inferencePrice
        d.extend_from_slice(&word_from_u128(99)); // 6: totalInferences
        d.extend_from_slice(&word_from_u128(is_active as u128)); // 7: isActive
        // tails: name, framework, version (all empty), then ipfsCID.
        d.extend_from_slice(&word_from_u128(0)); // name len 0
        d.extend_from_slice(&word_from_u128(0)); // framework len 0
        d.extend_from_slice(&word_from_u128(0)); // version len 0
        d.extend_from_slice(&word_from_u128(cid.len() as u128)); // ipfsCID len
        let mut cid_padded = cid.as_bytes().to_vec();
        cid_padded.resize(cid.len().div_ceil(32) * 32, 0);
        d.extend_from_slice(&cid_padded);
        d
    }

    #[test]
    fn decodes_get_model_cid_and_active() {
        let owner: Address = [0xab; 20];
        let cid = "bafybeibxm2nsadl3fnxv2sxcxmxaco2rkxqamgwhrn2g7njkz6cabcd123";
        let data = synth_return(owner, cid, true);
        let info = decode_get_model(&data).unwrap();
        assert_eq!(info.owner, owner);
        assert_eq!(info.ipfs_cid, cid);
        assert!(info.is_active);
    }

    #[test]
    fn decodes_inactive_model() {
        let info = decode_get_model(&synth_return([0x01; 20], "Qmshort", false)).unwrap();
        assert_eq!(info.ipfs_cid, "Qmshort");
        assert!(!info.is_active);
    }

    #[test]
    fn encodes_get_model_calldata() {
        let h = [0x22u8; 32];
        let call = encode_get_model(h);
        assert_eq!(call.len(), 36);
        assert_eq!(&call[0..4], &selectors::get_model());
        assert_eq!(&call[4..36], &h);
    }

    #[test]
    fn truncated_data_errors() {
        assert!(decode_get_model(&[0u8; 64]).is_err());
    }

    // PBA-L6b-023 (L6b PoC `l6b_decode_get_model_panics_on_hostile_len`): a
    // hostile RPC / registry return must decode to an Err, never panic the
    // daemon (start + len overflowed in debug and release).
    fn hostile_len() -> Vec<u8> {
        let mut d = vec![0u8; 32 * 10];
        d[4 * 32 + 30] = 0x01; // word 4: ipfsCID offset = 0x100 (word 8)
        d[7 * 32 + 31] = 1; // word 7: isActive = true
        for b in &mut d[8 * 32 + 24..8 * 32 + 32] {
            *b = 0xff; // word 8: length = 0xFFFF_FFFF_FFFF_FFF0
        }
        d[8 * 32 + 31] = 0xf0;
        d
    }

    #[test]
    fn l6b_023_hostile_string_length_is_an_error_not_a_panic() {
        let r = std::panic::catch_unwind(|| decode_get_model(&hostile_len()));
        match r {
            Ok(res) => assert!(res.is_err(), "hostile length must be rejected, got {res:?}"),
            Err(_) => panic!("PBA-L6b-023: decode_get_model panicked on a hostile length word"),
        }
    }

    #[test]
    fn l6b_023_hostile_offset_is_an_error_not_a_panic() {
        let mut d = hostile_len();
        // word 4: offset = 0xFFFF_FFFF_FFFF_FFE0 (a multiple of 32 near u64::MAX).
        for b in &mut d[4 * 32 + 24..4 * 32 + 32] {
            *b = 0xff;
        }
        d[4 * 32 + 31] = 0xe0;
        let r = std::panic::catch_unwind(|| decode_get_model(&d));
        match r {
            Ok(res) => assert!(res.is_err(), "hostile offset must be rejected, got {res:?}"),
            Err(_) => panic!("PBA-L6b-023: decode_get_model panicked on a hostile offset word"),
        }
    }
}
