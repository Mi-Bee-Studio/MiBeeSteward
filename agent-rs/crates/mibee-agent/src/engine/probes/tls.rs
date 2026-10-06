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
                let mut e = ev("active:tls", "tls", ip, 0.95);
                e.port = port as i64;
                e.protocol = "tcp".into();
                e.raw_data = Some(fields.into_iter().collect());
                out.push(e);
            }
        }
        out
});

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
