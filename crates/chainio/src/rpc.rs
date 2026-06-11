//! `rpc` — a minimal EVM JSON-RPC read client (`eth_call`, `eth_chainId`,
//! `eth_getCode`) over HTTP.
//!
//! This is intentionally tiny: SELL-S1 only needs read access to drive the
//! bidder (provider profile, job, oracle price) and to verify the canonical
//! address book against live `eth_getCode`. Writes (registerProvider, bidOnJob,
//! heartbeat, …) are built as calldata elsewhere and signed/broadcast by the
//! gui-native keystore path; this client never holds keys.
//!
//! Hitting a live RPC is an integration test gated behind `CITRATE_RPC_URL`.
//! The JSON envelope construction/parsing is unit-tested offline.

use serde_json::{json, Value};

use crate::abi::{self, Address, AbiError};

/// Errors from the JSON-RPC client.
#[derive(Debug)]
pub enum RpcError {
    /// Transport / HTTP error.
    Http(reqwest::Error),
    /// The JSON-RPC response carried an `error` object.
    Rpc { code: i64, message: String },
    /// The response was missing or had a malformed `result`.
    MalformedResponse(String),
    /// Decoding the `result` hex / ABI failed.
    Abi(AbiError),
}

impl core::fmt::Display for RpcError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RpcError::Http(e) => write!(f, "rpc http error: {e}"),
            RpcError::Rpc { code, message } => write!(f, "rpc error {code}: {message}"),
            RpcError::MalformedResponse(s) => write!(f, "malformed rpc response: {s}"),
            RpcError::Abi(e) => write!(f, "rpc abi decode error: {e}"),
        }
    }
}

impl std::error::Error for RpcError {}

impl From<AbiError> for RpcError {
    fn from(e: AbiError) -> Self {
        RpcError::Abi(e)
    }
}

/// Build a JSON-RPC 2.0 request envelope for `method`/`params` with `id`.
pub fn build_request(id: u64, method: &str, params: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    })
}

/// Extract the `result` string from a JSON-RPC response, surfacing `error`.
pub fn parse_result_string(resp: &Value) -> Result<String, RpcError> {
    if let Some(err) = resp.get("error") {
        let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
        let message = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        return Err(RpcError::Rpc { code, message });
    }
    match resp.get("result").and_then(Value::as_str) {
        Some(s) => Ok(s.to_string()),
        None => Err(RpcError::MalformedResponse(resp.to_string())),
    }
}

/// Extract the raw `result` JSON value from a response, surfacing `error`.
/// (Like [`parse_result_string`] but for methods whose result is an object,
/// e.g. `eth_getBlockByNumber`.)
pub fn parse_result_value(resp: &Value) -> Result<Value, RpcError> {
    if let Some(err) = resp.get("error") {
        let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
        let message = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        return Err(RpcError::Rpc { code, message });
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| RpcError::MalformedResponse(resp.to_string()))
}

/// Build the `params` array for an `eth_call` to `to` with `data` (calldata
/// bytes), at the `latest` block.
pub fn eth_call_params(to: Address, data: &[u8]) -> Value {
    json!([
        {
            "to": abi::hex_encode(&to),
            "data": abi::hex_encode(data),
        },
        "latest"
    ])
}

/// A blocking-free async JSON-RPC client bound to one endpoint URL.
#[derive(Clone)]
pub struct RpcClient {
    url: String,
    http: reqwest::Client,
    next_id: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl RpcClient {
    /// Create a client for `url` (e.g. the chain-40204 RPC endpoint).
    ///
    /// FUA-NODE-AGENT-06 (SECREM-02 WP 7.4): the endpoint is validated by
    /// [`crate::outbound::validate_outbound_url`] — plaintext `http://` is
    /// only accepted for loopback hosts, so a remote RPC must be `https://`.
    /// The RPC feeds security-relevant truth the executor acts on
    /// (`JobState`, the `committed` gate, oracle price); fail closed at
    /// construction rather than letting a MITM shape those reads.
    pub fn new(url: impl Into<String>) -> Result<Self, crate::outbound::OutboundUrlError> {
        let url = url.into();
        crate::outbound::validate_outbound_url(&url)?;
        Ok(RpcClient {
            url,
            http: reqwest::Client::new(),
            next_id: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1)),
        })
    }

    fn next_id(&self) -> u64 {
        self.next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Low-level: send a JSON-RPC method and return the `result` string.
    pub async fn call_raw(&self, method: &str, params: Value) -> Result<String, RpcError> {
        let req = build_request(self.next_id(), method, params);
        let resp: Value = self
            .http
            .post(&self.url)
            .json(&req)
            .send()
            .await
            .map_err(RpcError::Http)?
            .json()
            .await
            .map_err(RpcError::Http)?;
        parse_result_string(&resp)
    }

    /// `eth_call` to `to` with `data`, returning the raw return bytes.
    pub async fn eth_call(&self, to: Address, data: &[u8]) -> Result<Vec<u8>, RpcError> {
        let result = self.call_raw("eth_call", eth_call_params(to, data)).await?;
        Ok(abi::hex_decode(&result)?)
    }

    /// `eth_getCode(address, latest)` → deployed bytecode (empty `0x` if none).
    pub async fn eth_get_code(&self, address: Address) -> Result<Vec<u8>, RpcError> {
        let params = json!([abi::hex_encode(&address), "latest"]);
        let result = self.call_raw("eth_getCode", params).await?;
        Ok(abi::hex_decode(&result)?)
    }

    /// `eth_chainId()` → chain id as a `u64`.
    pub async fn eth_chain_id(&self) -> Result<u64, RpcError> {
        self.quantity("eth_chainId").await
    }

    /// `eth_blockNumber()` → latest block height as a `u128`.
    pub async fn eth_block_number(&self) -> Result<u128, RpcError> {
        Ok(self.quantity("eth_blockNumber").await? as u128)
    }

    /// Low-level: send a method and return the raw `result` JSON value (for
    /// object results like `eth_getBlockByNumber`).
    pub async fn call_raw_value(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let req = build_request(self.next_id(), method, params);
        let resp: Value = self
            .http
            .post(&self.url)
            .json(&req)
            .send()
            .await
            .map_err(RpcError::Http)?
            .json()
            .await
            .map_err(RpcError::Http)?;
        parse_result_value(&resp)
    }

    /// `eth_getBlockByNumber(block, false).timestamp` → unix seconds.
    pub async fn eth_block_timestamp(&self, block: u128) -> Result<u64, RpcError> {
        let block_hex = format!("0x{block:x}");
        let result = self
            .call_raw_value("eth_getBlockByNumber", json!([block_hex, false]))
            .await?;
        let ts = result
            .get("timestamp")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::MalformedResponse(result.to_string()))?;
        parse_quantity(ts)
    }

    /// Derive average **seconds-per-block** by sampling the timestamp delta
    /// between the latest block and `sample` blocks earlier. Returns `Ok(None)`
    /// when there aren't enough blocks or the timestamps don't advance (e.g. an
    /// idle single-producer devnet) — the caller falls back to a default.
    pub async fn secs_per_block(&self, sample: u128) -> Result<Option<u64>, RpcError> {
        if sample == 0 {
            return Ok(None);
        }
        let head = self.eth_block_number().await?;
        if head < sample {
            return Ok(None);
        }
        let t_head = self.eth_block_timestamp(head).await?;
        let t_prev = self.eth_block_timestamp(head - sample).await?;
        if t_head <= t_prev {
            return Ok(None);
        }
        Ok(Some(((t_head - t_prev) / sample as u64).max(1)))
    }

    /// Call a no-arg JSON-RPC method that returns a hex QUANTITY, parsed as u64.
    async fn quantity(&self, method: &str) -> Result<u64, RpcError> {
        let result = self.call_raw(method, json!([])).await?;
        parse_quantity(&result)
    }
}

/// Parse a `0x`-prefixed hex QUANTITY (variable-length, e.g. `eth_chainId`)
/// into a `u64`. QUANTITY values are minimally encoded, so they may be odd
/// nibble length (e.g. `0x9d4c`), unlike fixed-width DATA.
pub fn parse_quantity(s: &str) -> Result<u64, RpcError> {
    let stripped = s
        .strip_prefix("0x")
        .ok_or_else(|| RpcError::MalformedResponse(s.to_string()))?;
    u64::from_str_radix(stripped, 16)
        .map_err(|_| RpcError::MalformedResponse(s.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_envelope_is_well_formed() {
        let req = build_request(42, "eth_call", json!(["x"]));
        assert_eq!(req["jsonrpc"], "2.0");
        assert_eq!(req["id"], 42);
        assert_eq!(req["method"], "eth_call");
        assert_eq!(req["params"][0], "x");
    }

    #[test]
    fn parse_result_extracts_string() {
        let resp = json!({"jsonrpc":"2.0","id":1,"result":"0xabcd"});
        assert_eq!(parse_result_string(&resp).unwrap(), "0xabcd");
    }

    #[test]
    fn parse_result_value_extracts_object_and_timestamp() {
        // Mirrors an eth_getBlockByNumber result; timestamp is a hex quantity.
        let resp = json!({"jsonrpc":"2.0","id":1,"result":{"number":"0x10","timestamp":"0x64"}});
        let v = parse_result_value(&resp).unwrap();
        let ts = parse_quantity(v.get("timestamp").unwrap().as_str().unwrap()).unwrap();
        assert_eq!(ts, 100); // 0x64
    }

    #[test]
    fn parse_result_value_surfaces_rpc_error() {
        let resp = json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"boom"}});
        assert!(matches!(
            parse_result_value(&resp),
            Err(RpcError::Rpc { code: -32000, .. })
        ));
    }

    #[test]
    fn parse_result_surfaces_rpc_error() {
        let resp = json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"execution reverted"}});
        match parse_result_string(&resp) {
            Err(RpcError::Rpc { code, message }) => {
                assert_eq!(code, -32000);
                assert_eq!(message, "execution reverted");
            }
            other => panic!("expected Rpc error, got {other:?}"),
        }
    }

    #[test]
    fn parse_result_rejects_missing_result() {
        let resp = json!({"jsonrpc":"2.0","id":1});
        assert!(matches!(
            parse_result_string(&resp),
            Err(RpcError::MalformedResponse(_))
        ));
    }

    #[test]
    fn parse_quantity_handles_minimal_hex() {
        assert_eq!(parse_quantity("0x40204").unwrap(), 0x40204);
        assert_eq!(parse_quantity("0x9d4c").unwrap(), 40268);
        assert_eq!(parse_quantity("0x0").unwrap(), 0);
        assert!(parse_quantity("40204").is_err()); // no 0x
    }

    #[test]
    fn eth_call_params_encode_to_and_data() {
        let to: Address = [0x11; 20];
        let data = vec![0xde, 0xad, 0xbe, 0xef];
        let p = eth_call_params(to, &data);
        assert_eq!(p[0]["to"], "0x1111111111111111111111111111111111111111");
        assert_eq!(p[0]["data"], "0xdeadbeef");
        assert_eq!(p[1], "latest");
    }
}
