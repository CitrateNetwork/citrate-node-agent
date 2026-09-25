//! PBA-L6b-007 (NA-01 residual), executor half.
//!
//! `LlamaServerInference` POSTed `{prompt, n_predict}` with no `temperature` or
//! `seed`, so llama-server sampled (default temperature 0.8, random seed). A
//! re-run after a restart then produced a different output than the one the
//! node committed to, and the reveal could not match the commitment.
//!
//! RED on the pinned code: the captured request body carries no `temperature`
//! / `seed`. GREEN: greedy decoding (`temperature: 0`) with a fixed `seed`.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;

use executor::{Inference, Integrity, LlamaServerInference, ProvisionedModel, LLAMA_FIXED_SEED};

/// Accept one HTTP request, hand its JSON body to the test, answer `content`.
fn capture_server() -> (String, mpsc::Receiver<serde_json::Value>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let Ok((mut s, _)) = listener.accept() else {
            return;
        };
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        // Read headers, then Content-Length bytes of body.
        let body = loop {
            let n = s.read(&mut chunk).unwrap_or(0);
            if n == 0 {
                return;
            }
            buf.extend_from_slice(&chunk[..n]);
            let text = String::from_utf8_lossy(&buf).to_string();
            if let Some(idx) = text.find("\r\n\r\n") {
                let len = text[..idx]
                    .lines()
                    .find_map(|l| {
                        let l = l.to_ascii_lowercase();
                        l.strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                if buf.len() >= idx + 4 + len {
                    break buf[idx + 4..idx + 4 + len].to_vec();
                }
            }
        };
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        let _ = tx.send(v);
        let resp = br#"{"content":"deterministic"}"#;
        let _ = write!(
            s,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            resp.len()
        );
        let _ = s.write_all(resp);
    });
    (format!("http://{addr}"), rx)
}

#[tokio::test]
async fn completion_request_pins_greedy_decoding_and_a_fixed_seed() {
    let dir = std::env::temp_dir().join(format!("citrate-l6b007-sampling-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("model.bin");
    std::fs::write(&path, b"weights").unwrap();
    let model = ProvisionedModel {
        model_hash: [0x01; 32],
        path,
        bytes_len: 7,
        integrity: Integrity::Sha256Verified,
    };

    let (url, rx) = capture_server();
    let engine = LlamaServerInference::new(url).expect("loopback http is allowed");
    let out = engine.run(&model, b"prompt").await.expect("inference ok");
    assert_eq!(out.bytes, b"deterministic");

    let body = rx.recv().expect("request captured");
    assert_eq!(
        body.get("temperature").and_then(|t| t.as_f64()),
        Some(0.0),
        "PBA-L6b-007: completion must request greedy decoding, body was {body}"
    );
    assert_eq!(
        body.get("seed").and_then(|t| t.as_u64()),
        Some(LLAMA_FIXED_SEED as u64),
        "PBA-L6b-007: completion must pin a fixed seed, body was {body}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
