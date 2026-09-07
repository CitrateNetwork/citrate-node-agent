//! Tripwire for NA-B-001 (2026-09-02 federation graded audit, Leg B).
//!
//! The RPC read client was built with a bare `reqwest::Client::new()`, which has
//! no request timeout: an endpoint that accepts the TCP connection and then says
//! nothing parks `eth_chainId()` forever, wedging the supervised daemon tick
//! (and with it the heartbeat the provider is slashed for missing).
//!
//! RED on the pinned code: the client never times out, so the inner future does
//! not resolve and the outer `tokio::time::timeout` elapses → the test fails.
//! GREEN after the fix: `RpcClient::new` builds a timeout-configured client, so
//! `eth_chain_id()` resolves to `Err` well inside the budget.
//!
//! The test sets a short `CITRATE_HTTP_TIMEOUT_SECS` so GREEN is fast; it is the
//! only test in this binary, so the process-global env set is race-free.

use std::io::Read;
use std::net::TcpListener;
use std::time::{Duration, Instant};

use chainio::rpc::RpcClient;

#[tokio::test]
async fn rpc_client_times_out_against_a_stalled_endpoint() {
    // Short client timeout so a GREEN run is quick; loopback http is permitted
    // by the FUA-NODE-AGENT-06 outbound gate.
    std::env::set_var("CITRATE_HTTP_TIMEOUT_SECS", "2");
    std::env::set_var("CITRATE_HTTP_CONNECT_TIMEOUT_SECS", "1");

    // A listener that accepts every connection and then holds it open, never
    // writing a byte — the "connect succeeds, then silence" stall.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for conn in listener.incoming() {
            match conn {
                Ok(mut s) => {
                    // Read the request bytes then hang onto the socket forever.
                    let mut buf = [0u8; 64];
                    let _ = s.read(&mut buf);
                    held.push(s);
                }
                Err(_) => break,
            }
        }
    });

    let client = RpcClient::new(format!("http://{addr}")).expect("loopback http is allowed");

    let started = Instant::now();
    // Budget is comfortably larger than the client timeout but far smaller than
    // "forever": on the pinned (timeout-less) client this elapses → RED.
    let outcome = tokio::time::timeout(Duration::from_secs(8), client.eth_chain_id()).await;
    let waited = started.elapsed();

    let inner = outcome.unwrap_or_else(|_| {
        panic!(
            "NA-B-001 REPRODUCED: eth_chainId never resolved against a stalled \
             endpoint (waited {waited:?}) — the RPC client has no request timeout"
        )
    });
    assert!(
        inner.is_err(),
        "expected a client-side timeout error, got Ok — the endpoint sent nothing"
    );
    assert!(
        waited < Duration::from_secs(8),
        "client did resolve but too slowly ({waited:?})"
    );
    println!("NA-B-001 GREEN: RPC client timed out against a stalled endpoint in {waited:?}");
}
