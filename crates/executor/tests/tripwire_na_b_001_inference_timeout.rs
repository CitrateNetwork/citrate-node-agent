//! Tripwire for NA-B-001 / NA-B-003 part (a) (2026-09-02 audit, Leg B).
//!
//! `LlamaServerInference` was built with a bare `reqwest::Client::new()` (no
//! timeout), so an inference backend that accepts the connection and then stalls
//! parks `run()` forever. In the job-execution path that means the execution
//! deadline passes with the tick wedged — the on-chain timeout slash NA-B-003
//! describes.
//!
//! RED on the pinned code: `run()` never resolves → the outer timeout elapses.
//! GREEN after the fix: the client carries a request timeout, so `run()` returns
//! an `Err(Backend(..))` inside the budget.

use std::io::Read;
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use executor::{Inference, Integrity, LlamaServerInference, ProvisionedModel};

#[tokio::test]
async fn inference_run_times_out_against_a_stalled_backend() {
    std::env::set_var("CITRATE_HTTP_TIMEOUT_SECS", "2");
    std::env::set_var("CITRATE_HTTP_CONNECT_TIMEOUT_SECS", "1");

    // A real on-disk model file so the `path.exists()` provisioning gate passes
    // and we actually reach the HTTP call.
    let dir = std::env::temp_dir().join("citrate-tripwire-na-b-001-infer");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("model.bin");
    std::fs::write(&path, b"weights").unwrap();
    let model = ProvisionedModel {
        model_hash: [0x01; 32],
        path,
        bytes_len: 7,
        integrity: Integrity::Sha256Verified,
    };

    // Stalled backend: accept + hold, never answer.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for conn in listener.incoming() {
            match conn {
                Ok(mut s) => {
                    let mut buf = [0u8; 64];
                    let _ = s.read(&mut buf);
                    held.push(s);
                }
                Err(_) => break,
            }
        }
    });

    let engine =
        LlamaServerInference::new(format!("http://{addr}")).expect("loopback http is allowed");

    let started = Instant::now();
    let outcome = tokio::time::timeout(Duration::from_secs(8), engine.run(&model, b"prompt")).await;
    let waited = started.elapsed();

    let inner = outcome.unwrap_or_else(|_| {
        panic!(
            "NA-B-001/003 REPRODUCED: LlamaServerInference::run never resolved \
             against a stalled backend (waited {waited:?}) — no request timeout"
        )
    });
    assert!(inner.is_err(), "expected a backend timeout error, got Ok");
    assert!(waited < Duration::from_secs(8), "resolved but too slowly ({waited:?})");
    println!("NA-B-001/003 GREEN: inference run timed out against a stalled backend in {waited:?}");

    let _ = std::fs::remove_dir_all(std::env::temp_dir().join("citrate-tripwire-na-b-001-infer"));
    let _ = PathBuf::new();
}
