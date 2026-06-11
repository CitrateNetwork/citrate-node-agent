//! `outbound` — TLS enforcement for the agent's outbound HTTP endpoints
//! (FUA-NODE-AGENT-06, SECREM-02 WP 7.4).
//!
//! RED stage: tests only — the validator does not exist yet, so this module
//! fails to compile (that is the red evidence for the new seam).

#[cfg(test)]
mod tests {
    use super::*;

    // FUA-NODE-AGENT-06 (RED): plaintext http:// to a non-loopback host must be
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
}
