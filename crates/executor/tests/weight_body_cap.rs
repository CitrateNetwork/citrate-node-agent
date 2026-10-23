//! The IPFS gateway weight fetch bounds the body it reads: an oversized
//! declared Content-Length is refused before reading, and a body with no
//! length (chunked) is refused once it streams past the cap. Loopback test
//! servers only; the cap comes from `CITRATE_MAX_WEIGHT_BYTES`, which only
//! this test binary sets.

use std::io::{Read, Write};
use std::net::TcpListener;

use executor::{IpfsGatewaySource, WeightSource};

const CID: &str = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
const CAP: u64 = 64;

fn serve(response: Vec<u8>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut s) = conn else { break };
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let _ = s.write_all(&response);
        }
    });
    format!("http://{addr}")
}

fn source(url: String) -> IpfsGatewaySource {
    std::env::set_var("CITRATE_MAX_WEIGHT_BYTES", CAP.to_string());
    IpfsGatewaySource::new(url).expect("loopback http is allowed")
}

#[tokio::test]
async fn oversized_content_length_is_refused_before_the_body_is_read() {
    // Declares far more than the cap but sends only a few bytes: the refusal
    // must come from the declared length, not from a short read.
    let url = serve(
        b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\nConnection: close\r\n\r\nshort".to_vec(),
    );
    let err = source(url).fetch(CID).await.expect_err("oversized declared body");
    assert!(
        err.to_string().contains("too large"),
        "expected the Content-Length refusal, got: {err}"
    );
}

#[tokio::test]
async fn unbounded_chunked_body_is_refused_past_the_cap() {
    let payload = vec![b'w'; (CAP as usize) * 4];
    let mut resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
    for chunk in payload.chunks(16) {
        resp.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        resp.extend_from_slice(chunk);
        resp.extend_from_slice(b"\r\n");
    }
    resp.extend_from_slice(b"0\r\n\r\n");
    let err = source(serve(resp)).fetch(CID).await.expect_err("body past the cap");
    assert!(
        err.to_string().contains("byte cap"),
        "expected the streamed-cap refusal, got: {err}"
    );
}

#[tokio::test]
async fn body_within_the_cap_is_returned() {
    let url = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nweights".to_vec());
    let body = source(url).fetch(CID).await.expect("within cap");
    assert_eq!(body, b"weights");
}
