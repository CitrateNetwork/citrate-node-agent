//! `outbound` — TLS enforcement for the agent's outbound HTTP endpoints
//! (FUA-NODE-AGENT-06, SECREM-02 WP 7.4).
//!
//! The agent's three outbound clients — the JSON-RPC client
//! (`CITRATE_RPC_URL`), the IPFS gateway weight source
//! (`CITRATE_IPFS_GATEWAY`), and the resident llama-server adapter
//! (`CITRATE_LLAMA_URL`) — previously used their endpoint URLs verbatim, so a
//! plaintext `http://` endpoint on a remote host was silently accepted and a
//! network MITM could feed the executor false chain-truth (`JobState`, the
//! `committed` gate, oracle price) or poisoned bytes. The rule, mirrored from
//! the supervision surface's loopback-only `resolve_addr`/`serve` gate
//! (FUA-NODE-AGENT-01, SECREM-02 2.1):
//!
//! - `https://` — accepted for any host.
//! - `http://`  — accepted **only** for loopback hosts (`localhost`,
//!   `127.0.0.0/8`, `[::1]`). A local Kubo node / llama-server stays plain.
//! - anything else (other schemes, missing scheme, empty/garbled host,
//!   userinfo smuggling) — refused, fail closed, at client **construction**
//!   time so a misconfigured daemon dies at startup, not mid-job.
//!
//! Dev-only escape hatch: `CITRATE_NODE_AGENT_ALLOW_INSECURE_OUTBOUND=1`
//! permits plaintext to non-loopback hosts for LAN test rigs. It is logged
//! loudly on every use and must never be set in production — a MITM between
//! the agent and its RPC is exactly the FUA-NODE-AGENT-06 scenario.

/// Env var gating the dev-only plaintext-to-non-loopback escape hatch.
/// Documented dev-only; never set this in production.
pub const ALLOW_INSECURE_ENV: &str = "CITRATE_NODE_AGENT_ALLOW_INSECURE_OUTBOUND";

// ── liveness timeouts (NA-B-001) ────────────────────────────────────────────
//
// None of the agent's three outbound clients set any timeout, so a single
// endpoint that accepts a connection and then goes silent (a wedged RPC/Kubo
// node, an on-path attacker who stalls rather than tampers, a hung GPU box)
// parks the awaiting future forever. In the supervised daemon that starves the
// heartbeat the provider is suspended/slashed for missing — a silent DoS. Every
// client is built through the helpers below so no bare `reqwest::Client::new()`
// (which is timeout-less) survives.

/// Total-request timeout, seconds, for small-response clients (RPC, inference).
/// Overridable via `CITRATE_HTTP_TIMEOUT_SECS`.
pub const HTTP_TIMEOUT_ENV: &str = "CITRATE_HTTP_TIMEOUT_SECS";
/// TCP+TLS connect timeout, seconds, for every outbound client.
/// Overridable via `CITRATE_HTTP_CONNECT_TIMEOUT_SECS`.
pub const HTTP_CONNECT_TIMEOUT_ENV: &str = "CITRATE_HTTP_CONNECT_TIMEOUT_SECS";
/// Per-read inactivity timeout, seconds, for streaming clients (the weight
/// fetch, whose body can be gigabytes — a *total* timeout would break a legit
/// large download, so liveness is bounded by silence-between-reads instead).
/// Overridable via `CITRATE_HTTP_READ_TIMEOUT_SECS`.
pub const HTTP_READ_TIMEOUT_ENV: &str = "CITRATE_HTTP_READ_TIMEOUT_SECS";

const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 30;
const DEFAULT_HTTP_CONNECT_TIMEOUT_SECS: u64 = 10;
const DEFAULT_HTTP_READ_TIMEOUT_SECS: u64 = 60;

fn secs_from_env(var: &str, default: u64) -> std::time::Duration {
    let secs = std::env::var(var)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(default);
    std::time::Duration::from_secs(secs)
}

/// Build a reqwest client with connect + total-request timeouts, for clients
/// whose responses are small and bounded (the JSON-RPC read client and the
/// inference adapter). A stalled endpoint now yields a timeout `Err` instead of
/// an unresolvable future.
///
/// If the TLS backend itself fails to initialize the builder falls back to
/// `reqwest::Client::new()` — the same construction the pinned code used
/// unconditionally, so this is never worse and adds no new panic (Rule 5).
pub fn timed_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(secs_from_env(
            HTTP_CONNECT_TIMEOUT_ENV,
            DEFAULT_HTTP_CONNECT_TIMEOUT_SECS,
        ))
        .timeout(secs_from_env(HTTP_TIMEOUT_ENV, DEFAULT_HTTP_TIMEOUT_SECS))
        // PBA-L6b-024: never follow a redirect — see `no_redirect_fallback`.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|_| no_redirect_fallback())
}

/// PBA-L6b-024: the https/loopback gate ([`validate_outbound_url`]) is checked
/// once, on the configured URL. reqwest's default redirect policy
/// (`limited(10)`) would then follow a 3xx to any scheme or host — https to
/// plaintext http, or to an internal service — silently bypassing the gate. So
/// every outbound client refuses redirects. If the tuned builder cannot be
/// built, the fallback keeps that policy; only if even that fails does it fall
/// back to `Client::new()` (which panics on the same TLS-init failure, so the
/// redirect-following default is never actually reached in a running daemon).
fn no_redirect_fallback() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// PBA-L6b-024: default cap on a small-response body (JSON-RPC answers, the
/// inference completion). Overridable via `CITRATE_MAX_RESPONSE_BYTES`.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
/// Env var overriding [`DEFAULT_MAX_RESPONSE_BYTES`].
pub const MAX_RESPONSE_BYTES_ENV: &str = "CITRATE_MAX_RESPONSE_BYTES";

/// The configured small-response body cap.
pub fn max_response_bytes() -> usize {
    std::env::var(MAX_RESPONSE_BYTES_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(DEFAULT_MAX_RESPONSE_BYTES)
}

/// Why a capped response read was refused.
#[derive(Debug)]
pub enum CappedReadError {
    /// The server answered with a redirect; redirects are never followed.
    Redirect(reqwest::StatusCode),
    /// The body (declared or streamed) exceeds the cap.
    TooLarge { max: usize },
    /// Transport error while streaming the body.
    Http(reqwest::Error),
}

impl core::fmt::Display for CappedReadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CappedReadError::Redirect(s) => write!(
                f,
                "endpoint answered with redirect {s}; redirects are refused (PBA-L6b-024)"
            ),
            CappedReadError::TooLarge { max } => write!(
                f,
                "response body exceeds the {max}-byte cap (PBA-L6b-024)"
            ),
            CappedReadError::Http(e) => write!(f, "reading response body: {e}"),
        }
    }
}

impl std::error::Error for CappedReadError {}

/// PBA-L6b-024: read a response body with a hard byte cap, refusing a redirect
/// status first. Rejects an oversized `Content-Length` up front and stops
/// streaming as soon as the running total would pass `max`, so a hostile or
/// compromised endpoint cannot make the daemon buffer an unbounded body.
pub async fn read_body_capped(
    mut resp: reqwest::Response,
    max: usize,
) -> Result<Vec<u8>, CappedReadError> {
    if resp.status().is_redirection() {
        return Err(CappedReadError::Redirect(resp.status()));
    }
    if let Some(len) = resp.content_length() {
        if len > max as u64 {
            return Err(CappedReadError::TooLarge { max });
        }
    }
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(CappedReadError::Http)? {
        if buf.len().saturating_add(chunk.len()) > max {
            return Err(CappedReadError::TooLarge { max });
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Build a reqwest client with connect + per-read (inactivity) timeouts, for the
/// large-body weight fetch. Bounds liveness (a gateway that stops sending mid
/// body now errors) without capping the total time a legitimate multi-GB
/// download may take. Same fail-safe fallback as [`timed_http_client`].
pub fn streaming_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(secs_from_env(
            HTTP_CONNECT_TIMEOUT_ENV,
            DEFAULT_HTTP_CONNECT_TIMEOUT_SECS,
        ))
        .read_timeout(secs_from_env(
            HTTP_READ_TIMEOUT_ENV,
            DEFAULT_HTTP_READ_TIMEOUT_SECS,
        ))
        // PBA-L6b-024: never follow a redirect (see `no_redirect_fallback`).
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|_| no_redirect_fallback())
}

/// Why an outbound endpoint URL was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundUrlError {
    /// Scheme is neither `http` nor `https` (or missing entirely).
    UnsupportedScheme(String),
    /// Plain `http://` to a non-loopback host without the explicit
    /// dev-only `CITRATE_NODE_AGENT_ALLOW_INSECURE_OUTBOUND=1` override.
    PlaintextNonLoopback(String),
    /// The URL's authority could not be parsed safely (empty host, userinfo).
    Malformed(String),
}

impl core::fmt::Display for OutboundUrlError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            OutboundUrlError::UnsupportedScheme(u) => write!(
                f,
                "outbound endpoint {u:?} has an unsupported scheme: only https:// (any host) or http:// (loopback) are allowed (FUA-NODE-AGENT-06)"
            ),
            OutboundUrlError::PlaintextNonLoopback(u) => write!(
                f,
                "outbound endpoint {u:?} is plaintext http:// to a non-loopback host; use https://, or set {ALLOW_INSECURE_ENV}=1 (dev-only) to override (FUA-NODE-AGENT-06)"
            ),
            OutboundUrlError::Malformed(u) => write!(
                f,
                "outbound endpoint {u:?} has an unparseable or unsafe authority (empty host / userinfo); refusing fail-closed (FUA-NODE-AGENT-06)"
            ),
        }
    }
}

impl std::error::Error for OutboundUrlError {}

/// Validate `url` as an outbound endpoint, reading the
/// [`ALLOW_INSECURE_ENV`] escape hatch from the environment. This is what the
/// client constructors call.
pub fn validate_outbound_url(url: &str) -> Result<(), OutboundUrlError> {
    let allow_insecure = std::env::var(ALLOW_INSECURE_ENV).is_ok_and(|v| v.trim() == "1");
    validate_outbound_url_with(url, allow_insecure)
}

/// Pure core of [`validate_outbound_url`]: `allow_insecure` is the explicit
/// dev-only override (separated for deterministic, env-free unit tests).
pub fn validate_outbound_url_with(
    url: &str,
    allow_insecure: bool,
) -> Result<(), OutboundUrlError> {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r),
        None => return Err(OutboundUrlError::UnsupportedScheme(url.to_string())),
    };
    match scheme.as_str() {
        // TLS: acceptable to any host (still require a parseable authority).
        "https" => {
            host_of(rest).ok_or_else(|| OutboundUrlError::Malformed(url.to_string()))?;
            Ok(())
        }
        "http" => {
            let host = host_of(rest).ok_or_else(|| OutboundUrlError::Malformed(url.to_string()))?;
            if is_loopback_host(&host) {
                Ok(())
            } else if allow_insecure {
                eprintln!(
                    "SECURITY [FUA-NODE-AGENT-06]: {ALLOW_INSECURE_ENV}=1 — allowing PLAINTEXT outbound to non-loopback {url:?}; dev-only, never use in production"
                );
                Ok(())
            } else {
                Err(OutboundUrlError::PlaintextNonLoopback(url.to_string()))
            }
        }
        _ => Err(OutboundUrlError::UnsupportedScheme(url.to_string())),
    }
}

/// Extract the host from the part after `scheme://`: strip path/query/fragment,
/// reject userinfo (`@`) and empty hosts (fail closed — `None`), strip the
/// port. IPv6 literals keep their brackets stripped (`[::1]:80` → `::1`).
fn host_of(rest: &str) -> Option<String> {
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return None; // empty host or userinfo smuggling → fail closed
    }
    if let Some(v6) = authority.strip_prefix('[') {
        // `[::1]` or `[::1]:8545` — the literal is inside the brackets.
        let (inside, after) = v6.split_once(']')?;
        if !(after.is_empty() || after.starts_with(':')) {
            return None;
        }
        return Some(inside.to_string());
    }
    // Non-bracketed: at most one `:` (host:port); more is a malformed
    // (unbracketed-IPv6) authority → fail closed.
    let mut parts = authority.split(':');
    let host = parts.next()?.to_string();
    match (parts.next(), parts.next()) {
        (_, Some(_)) => None,                                  // host:p:q → malformed
        (Some(port), None) if port.parse::<u16>().is_err() => None, // non-numeric port
        _ if host.is_empty() => None,
        _ => Some(host),
    }
}

/// Is `host` (already stripped of brackets/port) a loopback destination?
/// Only the literal `localhost` and loopback IP literals qualify — any other
/// hostname would need DNS to prove loopback-ness, so it fails closed.
fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        return v4.is_loopback();
    }
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        return v6.is_loopback();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // FUA-NODE-AGENT-06: plaintext http:// to a non-loopback host must be
    // refused; loopback may stay http; https is always acceptable.
    #[test]
    fn https_is_accepted_for_any_host() {
        assert!(validate_outbound_url_with("https://rpc.citrate.network", false).is_ok());
        assert!(validate_outbound_url_with("https://203.0.113.7:8545/path", false).is_ok());
    }

    #[test]
    fn plaintext_loopback_is_accepted() {
        for url in [
            "http://127.0.0.1:8545",
            "http://127.5.5.5:8080/ipfs",
            "http://localhost:8080",
            "http://LOCALHOST:8080",
            "http://[::1]:8545",
        ] {
            assert!(validate_outbound_url_with(url, false).is_ok(), "{url} rejected");
        }
    }

    #[test]
    fn plaintext_non_loopback_is_refused() {
        for url in [
            "http://203.0.113.7:8545",
            "http://rpc.citrate.network",
            "http://localhost.evil.example:8080", // not the literal localhost
            "http://[2001:db8::1]:8545",
            "http://192.168.1.50:8080/ipfs",
        ] {
            assert!(
                matches!(
                    validate_outbound_url_with(url, false),
                    Err(OutboundUrlError::PlaintextNonLoopback(_))
                ),
                "{url} was not refused as plaintext non-loopback"
            );
        }
    }

    #[test]
    fn malformed_or_unsupported_urls_fail_closed() {
        for url in [
            "",
            "ftp://203.0.113.7/weights",
            "file:///etc/passwd",
            "203.0.113.7:8545",          // no scheme
            "http://",                   // empty host
            "http://user@127.0.0.1:1",   // userinfo smuggling → fail closed
        ] {
            assert!(validate_outbound_url_with(url, false).is_err(), "{url} accepted");
        }
    }

    // The documented dev-only escape hatch unlocks plaintext non-loopback.
    #[test]
    fn explicit_insecure_override_allows_plaintext_remote() {
        assert!(validate_outbound_url_with("http://192.168.1.50:8545", true).is_ok());
        // …but garbage is still garbage even with the override.
        assert!(validate_outbound_url_with("ftp://192.168.1.50", true).is_err());
    }

    // The fail-closed gate is wired into the RPC client constructor.
    #[test]
    fn rpc_client_refuses_plaintext_remote() {
        assert!(crate::rpc::RpcClient::new("http://203.0.113.7:8545").is_err());
        assert!(crate::rpc::RpcClient::new("http://127.0.0.1:8545").is_ok());
        assert!(crate::rpc::RpcClient::new("https://rpc.citrate.network").is_ok());
    }

    #[test]
    fn host_extraction_handles_ports_paths_and_brackets() {
        assert_eq!(host_of("127.0.0.1:8545/x?y#z").as_deref(), Some("127.0.0.1"));
        assert_eq!(host_of("[::1]:8545/ipfs").as_deref(), Some("::1"));
        assert_eq!(host_of("[::1]").as_deref(), Some("::1"));
        assert_eq!(host_of("host:notaport"), None);
        assert_eq!(host_of("::1:8545"), None); // unbracketed v6 → fail closed
        assert_eq!(host_of(""), None);
    }

    // ── PBA-L6b-024 mutation-hardening ──

    /// Serve `resp` (raw HTTP) to every connection on a loopback port.
    fn serve_raw(resp: Vec<u8>) -> String {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for c in l.incoming() {
                let Ok(mut s) = c else { break };
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let _ = s.write_all(&resp);
            }
        });
        format!("http://{addr}")
    }

    fn sized(body: &[u8], chunked: bool) -> Vec<u8> {
        let mut r = if chunked {
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
                body.len()
            )
            .into_bytes()
        } else {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes()
        };
        r.extend_from_slice(body);
        if chunked {
            r.extend_from_slice(b"\r\n0\r\n\r\n");
        }
        r
    }

    #[tokio::test]
    async fn read_body_capped_boundaries_declared_and_streamed() {
        let client = timed_http_client();
        for chunked in [false, true] {
            // Exactly the cap: accepted.
            let url = serve_raw(sized(&[b'x'; 10], chunked));
            let resp = client.get(&url).send().await.unwrap();
            let b = read_body_capped(resp, 10).await.expect("exactly max is allowed");
            assert_eq!(b.len(), 10, "chunked={chunked}");
            // One over: refused.
            let url = serve_raw(sized(&[b'x'; 11], chunked));
            let resp = client.get(&url).send().await.unwrap();
            assert!(
                matches!(read_body_capped(resp, 10).await, Err(CappedReadError::TooLarge { max: 10 })),
                "chunked={chunked}"
            );
        }
    }

    #[tokio::test]
    async fn no_client_constructor_follows_redirects() {
        let target = serve_raw(sized(b"reached", false));
        let redirect = serve_raw(
            format!("HTTP/1.1 302 Found\r\nLocation: {target}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .into_bytes(),
        );
        for (name, c) in [
            ("timed", timed_http_client()),
            ("streaming", streaming_http_client()),
            ("fallback", no_redirect_fallback()),
        ] {
            let resp = c.get(&redirect).send().await.unwrap();
            assert!(resp.status().is_redirection(), "{name} followed the redirect");
            assert!(matches!(
                read_body_capped(resp, 1024).await,
                Err(CappedReadError::Redirect(_))
            ));
        }
    }

    #[test]
    fn max_response_bytes_env_override_and_zero_fallback() {
        std::env::set_var(MAX_RESPONSE_BYTES_ENV, "5");
        assert_eq!(max_response_bytes(), 5);
        std::env::set_var(MAX_RESPONSE_BYTES_ENV, "0");
        assert_eq!(max_response_bytes(), DEFAULT_MAX_RESPONSE_BYTES);
        std::env::remove_var(MAX_RESPONSE_BYTES_ENV);
        assert_eq!(max_response_bytes(), DEFAULT_MAX_RESPONSE_BYTES);
    }
}
