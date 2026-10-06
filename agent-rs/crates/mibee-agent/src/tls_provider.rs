//! Process-wide rustls CryptoProvider selection. The TLS stack is compiled
//! provider-agnostic (reqwest `rustls-tls-webpki-roots-no-provider`,
//! tokio-rustls with no provider feature): ring covers the real targets
//! (x86/x64/arm/aarch64 — the same provider the Go-adjacent stack uses),
//! and MIPS builds use the pure-Rust oxitls provider because ring 0.17
//! simply has no mips backend. Idempotent; the first caller installs.

#[cfg(not(target_arch = "mips"))]
pub fn ensure_tls_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // Failure can only mean another thread beat us to install — fine.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(target_arch = "mips")]
pub fn ensure_tls_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = oxitls_rustcrypto_provider::provider().install_default();
    });
}
