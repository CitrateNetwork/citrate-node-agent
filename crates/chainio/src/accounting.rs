//! `accounting` — the two `ContributionAccounting` calls SELL-S2 earnings needs:
//! read `claimable(address)` (a public mapping getter) and build the
//! `claimRewards()` write calldata.
//!
//! `claimRewards()` takes no args and zeroes the caller's claimable balance,
//! transferring it out (`ContributionAccounting.sol:218`). The agent holds no
//! keys, so the write is emitted as an unsigned request (see `earnings`).

use crate::abi::{self, AbiError, Address};
use crate::selectors;

/// `claimable(address)` calldata.
pub fn encode_claimable(account: Address) -> Vec<u8> {
    abi::encode_call(selectors::claimable(), &[abi::word_from_address(account)])
}

/// Decode `claimable(address) -> uint256` (wei of SALT).
pub fn decode_claimable(data: &[u8]) -> Result<u128, AbiError> {
    abi::Decoder::new(data).u128()
}

/// `claimRewards()` calldata (selector only — no args).
pub fn encode_claim_rewards() -> Vec<u8> {
    selectors::claim_rewards().to_vec()
}

/// Live-RPC helper (gated by `CITRATE_RPC_URL` in tests).
pub mod live {
    use super::*;
    use crate::rpc::{RpcClient, RpcError};

    /// Read `ContributionAccounting.claimable(account)`.
    pub async fn claimable(
        client: &RpcClient,
        accounting: Address,
        account: Address,
    ) -> Result<u128, RpcError> {
        let data = client
            .eth_call(accounting, &encode_claimable(account))
            .await?;
        Ok(decode_claimable(&data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::word_from_u128;

    #[test]
    fn encodes_claimable_calldata() {
        let acct: Address = [0xcc; 20];
        let call = encode_claimable(acct);
        assert_eq!(call.len(), 36);
        assert_eq!(&call[0..4], &selectors::claimable());
        assert_eq!(&call[4 + 12..4 + 32], &acct);
    }

    #[test]
    fn decodes_claimable_amount() {
        let w = word_from_u128(7 * 10u128.pow(18));
        assert_eq!(decode_claimable(&w).unwrap(), 7 * 10u128.pow(18));
    }

    #[test]
    fn claim_rewards_is_selector_only() {
        let call = encode_claim_rewards();
        assert_eq!(call.len(), 4);
        assert_eq!(call.as_slice(), &selectors::claim_rewards());
    }
}
