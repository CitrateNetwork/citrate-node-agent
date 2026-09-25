//! PBA-L6b-024: the outbound https/loopback gate was checked only when a
//! client was constructed. reqwest's default redirect policy (`limited(10)`)
//! then followed a 3xx to any scheme/host (https -> http, or to an internal
//! service), and RPC response bodies were read whole with no cap.
//!
//! RED on the pinned code: the RPC client follows the redirect (the second
//! server sees a request and its answer is returned), and a 64 MiB body is
//! buffered. GREEN: redirects are never followed and bodies are capped.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use chainio::rpc::RpcClient;

/// Drain one request's headers (enough for these tests: bodies are small).
fn read_request(s: &mut std::net::TcpStream) {
    let mut buf = [0u8; 8192];
    let mut seen = Vec::new();
    while !String::from_utf8_lossy(&seen).contains("\r\n\r\n") {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => seen.extend_from_slice(&buf[..n]),
        }
    }
    // Swallow a short JSON body if it arrived in a separate segment.
    let _ = s.set_read_timeout(Some(std::time::Duration::from_millis(50)));
    let _ = s.read(&mut buf);
}

/// A server that answers every request with `response` (raw HTTP bytes).
fn serve(response: Vec<u8>, hit: Option<Arc<AtomicBool>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut s) = conn else { break };
            read_request(&mut s);
            if let Some(h) = &hit {
                h.store(true, Ordering::SeqCst);
            }
            let _ = s.write_all(&response);
            let _ = s.flush();
        }
    });
    format!("http://{addr}")
}

fn ok_json(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

#[tokio::test]
async fn rpc_client_does_not_follow_redirects() {
    // The redirect target: a JSON-RPC answer that must never be reached.
    let hit = Arc::new(AtomicBool::new(false));
    let target = serve(
        ok_json(r#"{"jsonrpc":"2.0","id":1,"result":"0x9d0c"}"#),
        Some(hit.clone()),
    );
    let redirector = serve(
        format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: {target}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_bytes(),
        None,
    );
    let client = RpcClient::new(redirector).expect("loopback http is allowed");
    let res = client.eth_chain_id().await;
    assert!(
        res.is_err(),
        "PBA-L6b-024: a redirect must not be followed, got {res:?}"
    );
    assert!(
        !hit.load(Ordering::SeqCst),
        "PBA-L6b-024: the redirect target must never be contacted"
    );
}

#[tokio::test]
async fn rpc_client_caps_the_response_body() {
    // A syntactically valid JSON-RPC answer padded to 64 MiB of whitespace.
    let pad = " ".repeat(64 * 1024 * 1024);
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":"0x9d0c"}}{pad}"#);
    let url = serve(ok_json(&body), None);
    let client = RpcClient::new(url).expect("loopback http is allowed");
    let res = client.eth_chain_id().await;
    assert!(
        res.is_err(),
        "PBA-L6b-024: an oversized RPC body must be refused, got {res:?}"
    );
    let msg = res.unwrap_err().to_string();
    assert!(msg.contains("exceeds"), "unclear error: {msg}");
}

#[tokio::test]
async fn rpc_client_still_reads_a_normal_answer() {
    let url = serve(ok_json(r#"{"jsonrpc":"2.0","id":1,"result":"0x9d0c"}"#), None);
    let client = RpcClient::new(url).expect("loopback http is allowed");
    assert_eq!(client.eth_chain_id().await.expect("ok"), 40204);
}
