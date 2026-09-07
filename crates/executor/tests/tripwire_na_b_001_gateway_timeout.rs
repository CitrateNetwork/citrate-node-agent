//! Tripwire for NA-B-001 (2026-09-02 audit, Leg B) — the IPFS weight gateway.
//!
//! `IpfsGatewaySource` was built with a bare `reqwest::Client::new()`: a gateway
//! (a local Kubo node) that accepts the connection and then stalls parks the
//! weight fetch forever. The body can be gigabytes, so the fix uses a per-read
//! (inactivity) timeout rather than a total-request timeout — a stalled read
//! errors while a legitimate long download is not capped.
//!
//! RED on the pinned code: `fetch()` never resolves → the outer timeout elapses.
//! GREEN after the fix: the read timeout fires and `fetch()` returns `Err`.

use std::io::Read;
use std::net::TcpListener;
use std::time::{Duration, Instant};

use executor::{IpfsGatewaySource, WeightSource};

// A real-shaped CIDv1 base32 so the `validate_cid` guard passes and we reach IO.
const CID: &str = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";

#[tokio::test]
async fn gateway_fetch_times_out_against_a_stalled_gateway() {
    std::env::set_var("CITRATE_HTTP_READ_TIMEOUT_SECS", "2");
    std::env::set_var("CITRATE_HTTP_CONNECT_TIMEOUT_SECS", "1");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for conn in listener.incoming() {
            match conn {
                Ok(mut s) => {
                    let mut buf = [0u8; 128];
                    let _ = s.read(&mut buf);
                    held.push(s); // hold, never write a response
                }
                Err(_) => break,
            }
        }
    });

    let src = IpfsGatewaySource::new(format!("http://{addr}")).expect("loopback http is allowed");

    let started = Instant::now();
    let outcome = tokio::time::timeout(Duration::from_secs(8), src.fetch(CID)).await;
    let waited = started.elapsed();

    let inner = outcome.unwrap_or_else(|_| {
        panic!(
            "NA-B-001 REPRODUCED: gateway fetch never resolved against a stalled \
             gateway (waited {waited:?}) — the weight client has no timeout"
        )
    });
    assert!(inner.is_err(), "expected a fetch timeout error, got Ok");
    assert!(waited < Duration::from_secs(8), "resolved but too slowly ({waited:?})");
    println!("NA-B-001 GREEN: gateway fetch timed out against a stalled gateway in {waited:?}");
}
