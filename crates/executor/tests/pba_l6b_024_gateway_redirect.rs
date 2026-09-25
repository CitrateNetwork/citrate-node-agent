//! PBA-L6b-024 variant: the IPFS gateway weight source (streaming client) must
//! not follow a redirect either — the https/loopback gate is checked once, on
//! the configured gateway URL, so a 3xx to another host would bypass it.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use executor::{IpfsGatewaySource, WeightSource};

fn serve(response: Vec<u8>, hit: Option<Arc<AtomicBool>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut s) = conn else { break };
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            if let Some(h) = &hit {
                h.store(true, Ordering::SeqCst);
            }
            let _ = s.write_all(&response);
        }
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn gateway_fetch_does_not_follow_redirects() {
    let hit = Arc::new(AtomicBool::new(false));
    let target = serve(
        b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nweights".to_vec(),
        Some(hit.clone()),
    );
    let redirector = serve(
        format!("HTTP/1.1 302 Found\r\nLocation: {target}/x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .into_bytes(),
        None,
    );
    let src = IpfsGatewaySource::new(redirector).expect("loopback http is allowed");
    let res = src
        .fetch("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
        .await;
    assert!(res.is_err(), "PBA-L6b-024: gateway redirect must not be followed");
    assert!(
        !hit.load(Ordering::SeqCst),
        "PBA-L6b-024: the redirect target must never be contacted"
    );
}
