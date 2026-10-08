//! TLS probe: handshake on TLS-typical ports with any-cert acceptance,
//! leaf-cert fields into evidence (Go probe/tls.go: fixed port set, min(
//! timeout,4s), empty keys dropped, no ja3).

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::io::AsyncReadExt;
use tokio_rustls::rustls;

use super::{ev, probe_impl, Evidence, Probe, ProbeHint};

const TLS_PORTS: [u16; 12] = [443, 8443, 9443, 4443, 465, 636, 989, 990, 992, 993, 994, 995];

pub struct TlsProbe;

/// Danger verifier: accept any certificate (Go InsecureSkipVerify).
#[derive(Debug)]
struct AnyServerCert;

impl rustls::client::danger::ServerCertVerifier for AnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
        ]
    }
}

fn any_cert_client() -> Arc<rustls::ClientConfig> {
    crate::tls_provider::ensure_tls_provider();
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyServerCert))
        .with_no_client_auth();
    Arc::new(config)
}

probe_impl!(TlsProbe, "active:tls", |ip: IpAddr, hint: &ProbeHint| async move {

        let mut out = Vec::new();
        for port in TLS_PORTS {
            if !hint.port_spec.contains(&port) {
                continue;
            }
            let timeout = hint.timeout.min(Duration::from_secs(4));
            if let Some(fields) = tls_handshake(ip, port, timeout).await {
                if fields.is_empty() {
                    continue;
                }
                out.extend(tls_evidence_with_cert_cn(ip, port, &fields));
            }
        }
        out
});

/// Evidence pieces for one leaf cert: the tls-kind piece every consumer
/// knows, plus — when the subject CN looks like a device hostname — a
/// hostname-kind piece so the corpus's hostname rules can classify the
/// device in the SAME scan. Mirrors Go tlsEvidenceWithCertCN (7ddd821):
/// the fold's node_hostname CN fallback runs after classification, so
/// without this channel the hostname rules never saw a model signed into
/// the CN ("R68S", field-found 2026-10-06).
pub(crate) fn tls_evidence_with_cert_cn(
    ip: IpAddr,
    port: u16,
    fields: &BTreeMap<String, String>,
) -> Vec<Evidence> {
    let mut e = ev("active:tls", "tls", ip, 0.95);
    e.port = port as i64;
    e.protocol = "tcp".into();
    e.raw_data = Some(fields.clone());
    let mut out = vec![e];
    if let Some(host) = cert_cn_as_hostname(fields.get("subject_cn").map(|s| s.as_str()).unwrap_or("")) {
        let mut h = ev("active:tls", "hostname", ip, 0.7);
        h.raw_data = Some(BTreeMap::from([("hostname".into(), host.into())]));
        h.port = port as i64;
        out.push(h);
    }
    out
}

/// Whether a cert subject CN looks like a device hostname rather than a
/// certificate-ish label: a single DNS label — no dots, spaces, or
/// wildcards, at least one letter or digit, ≤63 bytes. "R68S" qualifies
/// (routers sign their model); "MIWIFI SERVER CERT" (spaces) and
/// "*.hikvision.com" (wildcard/dots) do not. Generic labels ("root",
/// "localhost") may qualify by shape but match no vendor-anchored rule.
pub(crate) fn cert_cn_as_hostname(cn: &str) -> Option<&str> {
    if cn.is_empty() || cn.len() > 63 {
        return None;
    }
    let has_alnum = cn.chars().any(|c| c.is_ascii_alphanumeric());
    if !has_alnum || !cn.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return None;
    }
    Some(cn)
}

async fn tls_handshake(ip: IpAddr, port: u16, timeout: Duration) -> Option<BTreeMap<String, String>> {
    let addr = SocketAddr::new(ip, port);
    let sock = tokio::time::timeout(timeout, TcpStream::connect(addr)).await.ok()?.ok()?;
    let config = any_cert_client();
    let server_name = rustls::pki_types::ServerName::try_from(ip.to_string()).ok()?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let mut stream = tokio::time::timeout(timeout, connector.connect(server_name, sock)).await.ok()?.ok()?;
    // Some servers wait for a request; send a HEAD to be polite then drain.
    use tokio::io::AsyncWriteExt;
    let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await;
    let mut sink = [0u8; 64];
    let _ = tokio::time::timeout(Duration::from_millis(300), stream.read(&mut sink)).await;
    let (_, session) = stream.get_ref();
    let certs = session.peer_certificates()?;
    let leaf = certs.first()?;
    Some(cert_fields(leaf.as_ref()))
}

/// Leaf-cert fields (empty values dropped by the caller building evidence).
pub fn cert_fields(der: &[u8]) -> BTreeMap<String, String> {
    use x509_parser::prelude::*;
    let mut m = BTreeMap::new();
    let Ok((_, cert)) = X509Certificate::from_der(der) else { return m };
    let subject = cert.subject();
    let issuer = cert.issuer();
    let put = |m: &mut BTreeMap<String, String>, k: &str, v: String| {
        if !v.is_empty() {
            m.insert(k.to_string(), v);
        }
    };
    put(&mut m, "subject_cn", subject.iter_common_name().next().map(|c| c.as_str().unwrap_or_default().to_string()).unwrap_or_default());
    put(&mut m, "issuer_cn", issuer.iter_common_name().next().map(|c| c.as_str().unwrap_or_default().to_string()).unwrap_or_default());
    put(&mut m, "issuer_org", issuer.iter_organization().next().map(|c| c.as_str().unwrap_or_default().to_string()).unwrap_or_default());
    let sans: Vec<String> = cert
        .extensions()
        .iter()
        .filter_map(|e| match e.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => Some(san),
            _ => None,
        })
        .flat_map(|san| san.general_names.iter().map(|g| g.to_string()).collect::<Vec<_>>())
        .collect();
    if !sans.is_empty() {
        put(&mut m, "san_dns", sans.iter().filter(|s| !s.contains(':')).cloned().collect::<Vec<_>>().join(","));
        put(&mut m, "san_ip", sans.iter().filter(|s| s.contains(':')).cloned().collect::<Vec<_>>().join(","));
    }
    put(&mut m, "serial", cert.serial.to_bytes_be().iter().rev().map(|b| format!("{b:02x}")).collect::<String>());
    put(&mut m, "not_before", cert.validity().not_before.to_string());
    put(&mut m, "not_after", cert.validity().not_after.to_string());
    put(&mut m, "sig_algorithm", format!("{:?}", cert.signature_algorithm.algorithm));
    put(&mut m, "key_algorithm", format!("{:?}", cert.public_key().algorithm.algorithm));
    put(&mut m, "fingerprint_sha256", {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(der);
        let d = h.finalize();
        d.iter().map(|b| format!("{b:02x}")).collect::<String>()
    });
    let self_signed = subject == issuer;
    m.insert("self_signed".into(), self_signed.to_string());
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signed_flag_and_field_dropping() {
        // any DER parses or returns empty map; a real cert is exercised on
        // the rig. Here: garbage yields empty (dropped evidence upstream).
        let m = cert_fields(&[0xde, 0xad]);
        assert!(m.is_empty());
    }

    #[test]
    fn cert_cn_hostname_shape_gate() {
        // Mirrors Go certCNAsHostname: single DNS label, [a-zA-Z0-9-] only,
        // at least one alnum, <=63 bytes. Routers sign their model ("R68S").
        assert_eq!(cert_cn_as_hostname("R68S"), Some("R68S"));
        assert_eq!(cert_cn_as_hostname("nanopi-r4s"), Some("nanopi-r4s"));
        // Shape-only qualifier ("root"): matches no vendor-anchored rule.
        assert_eq!(cert_cn_as_hostname("root"), Some("root"));
        assert_eq!(cert_cn_as_hostname(""), None);
        assert_eq!(cert_cn_as_hostname("MIWIFI SERVER CERT"), None); // space
        assert_eq!(cert_cn_as_hostname("*.hikvision.com"), None); // wildcard + dots
        assert_eq!(cert_cn_as_hostname("foo_bar"), None); // underscore
        assert_eq!(cert_cn_as_hostname("---"), None); // punctuation only
        assert_eq!(cert_cn_as_hostname("路由器"), None); // non-ASCII
        let ok63 = "a".repeat(63);
        assert_eq!(cert_cn_as_hostname(&ok63), Some(ok63.as_str()));
        let long64 = "a".repeat(64);
        assert_eq!(cert_cn_as_hostname(&long64), None);
    }

    #[test]
    fn tls_evidence_emits_hostname_piece_for_single_label_cn() {
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        let fields = BTreeMap::from([
            ("subject_cn".to_string(), "R68S".to_string()),
            ("issuer_cn".to_string(), "R68S".to_string()),
        ]);
        let evs = tls_evidence_with_cert_cn(ip, 443, &fields);
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].kind, "tls");
        assert_eq!(evs[0].confidence, 0.95);
        assert_eq!(evs[0].port, 443);
        assert_eq!(evs[0].protocol, "tcp");
        // hostname-kind piece so the corpus's hostname rules classify the
        // device in the SAME scan (Go 7ddd821 parity).
        assert_eq!(evs[1].kind, "hostname");
        assert_eq!(evs[1].confidence, 0.7);
        assert_eq!(evs[1].port, 443);
        assert!(evs[1].protocol.is_empty()); // Go sets no protocol here
        assert_eq!(
            evs[1].raw_data.as_ref().unwrap().get("hostname").unwrap(),
            "R68S"
        );
    }

    #[test]
    fn tls_evidence_without_hostname_shaped_cn_is_single_piece() {
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        let wildcard = BTreeMap::from([("subject_cn".to_string(), "*.hikvision.com".to_string())]);
        assert_eq!(tls_evidence_with_cert_cn(ip, 443, &wildcard).len(), 1);
        assert_eq!(tls_evidence_with_cert_cn(ip, 443, &BTreeMap::new()).len(), 1);
    }
}

/// TLS probe against host:port returning cert fields + "_version" key
/// ("1.2"/"1.3") for the prober's tls module.
pub async fn cert_probe(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Option<BTreeMap<String, String>> {
    use tokio::io::AsyncReadExt;
    let addr = SocketAddr::new(host.parse().ok()?, port);
    let sock = tokio::time::timeout(timeout, TcpStream::connect(addr)).await.ok()?.ok()?;
    let config = any_cert_client();
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string()).ok()?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let mut stream = tokio::time::timeout(timeout, connector.connect(server_name, sock))
        .await
        .ok()?
        .ok()?;
    use tokio::io::AsyncWriteExt;
    let _ = stream.write_all(b"HEAD / HTTP/1.0

").await;
    let mut sink = [0u8; 16];
    let _ = tokio::time::timeout(Duration::from_millis(200), stream.read(&mut sink)).await;
    let (io, session) = stream.get_ref();
    let _ = io;
    let version = match session.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "1.3",
        Some(rustls::ProtocolVersion::TLSv1_2) => "1.2",
        _ => "",
    };
    let mut fields = session
        .peer_certificates()
        .and_then(|c| c.first())
        .map(|c| cert_fields(c.as_ref()))
        .unwrap_or_default();
    if !version.is_empty() {
        fields.insert("_version".into(), version.to_string());
    }
    Some(fields)
}
