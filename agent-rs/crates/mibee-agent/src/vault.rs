//! Agent-local SNMPv3 credential vault: AES-256-GCM under
//! `security.master_key` (exactly 32 bytes). Blob format mirrors Go
//! internal/crypto/secrets.go: base64([version 0x01][nonce 12][ciphertext+
//! 16B GCM tag]) with the version byte bound as AAD. Passphrases never
//! echo back — list is a masked projection, decrypt exists only for the
//! scan-time resolver.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};

pub const MASTER_KEY_LEN: usize = 32;

#[derive(Debug)]
pub enum VaultError {
    BadKeyLength(usize),
    Disabled,
    Crypt(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::BadKeyLength(n) => write!(
                f,
                "master key must be exactly {MASTER_KEY_LEN} bytes (got {n}); the vault stays disabled"
            ),
            VaultError::Disabled => write!(f, "vault disabled (no master key configured)"),
            VaultError::Crypt(e) => write!(f, "vault crypto: {e}"),
        }
    }
}

pub struct Vault {
    cipher: Aes256Gcm,
}

impl Vault {
    pub fn new(master_key: &str) -> Result<Vault, VaultError> {
        if master_key.is_empty() {
            return Err(VaultError::Disabled);
        }
        if master_key.len() != MASTER_KEY_LEN {
            return Err(VaultError::BadKeyLength(master_key.len()));
        }
        let key = Key::<Aes256Gcm>::from_slice(master_key.as_bytes());
        Ok(Vault { cipher: Aes256Gcm::new(key) })
    }

    /// Encrypt a passphrase into the stored blob form.
    pub fn encrypt(&self, plaintext: &str) -> Result<String, VaultError> {
        let mut nonce_bytes = [0u8; 12];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = self
            .cipher
            .encrypt(
                nonce,
                Payload { msg: plaintext.as_bytes(), aad: &[0x01] },
            )
            .map_err(|e| VaultError::Crypt(format!("seal: {e}")))?;
        let mut blob = vec![0x01];
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ct);
        use base64::Engine;
        Ok(base64::engine::general_purpose::STANDARD.encode(&blob))
    }

    /// Decrypt a stored blob (scan-time only; never printed).
    pub fn decrypt(&self, blob: &str) -> Result<String, VaultError> {
        use base64::Engine;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(blob)
            .map_err(|e| VaultError::Crypt(format!("b64: {e}")))?;
        if raw.is_empty() || raw[0] != 0x01 {
            return Err(VaultError::Crypt("unknown blob version".into()));
        }
        if raw.len() < 1 + 12 + 16 {
            return Err(VaultError::Crypt("blob too short".into()));
        }
        let nonce = Nonce::from_slice(&raw[1..13]);
        let pt = self
            .cipher
            .decrypt(nonce, Payload { msg: &raw[13..], aad: &[0x01] })
            .map_err(|e| VaultError::Crypt(format!("open: {e}")))?;
        Ok(String::from_utf8_lossy(&pt).into_owned())
    }
}

/// A credential row as stored in agent.db's snmp_credentials.
#[derive(Debug, Clone, Default)]
pub struct SnmpCredential {
    pub id: i64,
    pub name: String,
    pub security_level: String, // v1v2c | noAuthNoPriv | authNoPriv | authPriv
    pub community: String,
    pub username: String,
    pub auth_protocol: String,
    pub auth_passphrase_enc: String,
    pub priv_protocol: String,
    pub priv_passphrase_enc: String,
    pub notes: String,
}

/// Masked projection for `snmp-credential list` — passphrases never appear.
pub fn masked_row(c: &SnmpCredential) -> String {
    let auth = if c.auth_passphrase_enc.is_empty() { "-" } else { "***" };
    let privm = if c.priv_passphrase_enc.is_empty() { "-" } else { "***" };
    format!(
        "{:>4}  {:<24} {:<14} {:<16} auth={:<8} priv={:<8} {}",
        c.id,
        truncate(&c.name, 24),
        c.security_level,
        truncate(if c.username.is_empty() { "-" } else { &c.username }, 16),
        if c.auth_protocol.is_empty() { auth.to_string() } else { format!("{} {}", c.auth_protocol, auth) },
        if c.priv_protocol.is_empty() { privm.to_string() } else { format!("{} {}", c.priv_protocol, privm) },
        truncate(&c.notes, 40),
    )
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect()
    }
}

/// Validation shared by the CLI add path (Go credential.go): security
/// level determines the required fields.
pub fn validate_add(
    security_level: &str,
    community: &str,
    username: &str,
    auth_protocol: &str,
    priv_protocol: &str,
) -> Result<(), String> {
    match security_level {
        "v1v2c" => {
            if community.is_empty() {
                return Err("v1v2c requires -community".to_string());
            }
        }
        "noAuthNoPriv" => {
            if username.is_empty() {
                return Err("noAuthNoPriv requires -username".to_string());
            }
        }
        "authNoPriv" => {
            if username.is_empty() {
                return Err("authNoPriv requires -username".to_string());
            }
            if auth_protocol.is_empty() {
                return Err("authNoPriv requires -auth-protocol".to_string());
            }
        }
        "authPriv" => {
            if username.is_empty() {
                return Err("authPriv requires -username".to_string());
            }
            if auth_protocol.is_empty() {
                return Err("authPriv requires -auth-protocol".to_string());
            }
            if priv_protocol.is_empty() {
                return Err("authPriv requires -priv-protocol".to_string());
            }
        }
        other => return Err(format!("unknown security level {other:?} (v1v2c|noAuthNoPriv|authNoPriv|authPriv)")),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_format() {
        let v = Vault::new("0123456789abcdef0123456789abcdef").unwrap();
        let blob = v.encrypt("hunter2").unwrap();
        assert!(blob.starts_with("A")); // 0x01 first byte -> base64 leading A
        assert_eq!(v.decrypt(&blob).unwrap(), "hunter2");
        // empty passphrase is a valid encrypted empty string
        let empty = v.encrypt("").unwrap();
        assert_eq!(v.decrypt(&empty).unwrap(), "");
        // tampered blob fails
        let mut tampered = blob.clone();
        let flip = if tampered.ends_with('A') { 'B' } else { 'A' };
        tampered.replace_range(tampered.len() - 1.., &flip.to_string());
        assert!(v.decrypt(&tampered).is_err());
    }

    #[test]
    fn key_length_and_disabled() {
        assert!(matches!(Vault::new(""), Err(VaultError::Disabled)));
        assert!(matches!(Vault::new("short"), Err(VaultError::BadKeyLength(5))));
        assert!(matches!(Vault::new(&"x".repeat(44)), Err(VaultError::BadKeyLength(44))));
    }

    #[test]
    fn masked_never_leaks() {
        let c = SnmpCredential {
            id: 1,
            name: "router-snmp".into(),
            security_level: "authPriv".into(),
            community: String::new(),
            username: "admin".into(),
            auth_protocol: "SHA".into(),
            auth_passphrase_enc: "AAAA".into(),
            priv_protocol: "AES".into(),
            priv_passphrase_enc: "BBBB".into(),
            notes: "core switch".into(),
        };
        let row = masked_row(&c);
        assert!(!row.contains("AAAA") && !row.contains("BBBB"));
        assert!(row.contains("router-snmp") && row.contains("***"));
    }

    #[test]
    fn add_validation() {
        assert!(validate_add("v1v2c", "", "", "", "").is_err());
        assert!(validate_add("v1v2c", "public", "", "", "").is_ok());
        assert!(validate_add("authNoPriv", "u1", "", "", "").is_err()); // no auth protocol
        assert!(validate_add("authNoPriv", "u1", "u", "SHA", "").is_ok());
        assert!(validate_add("bogus", "", "", "", "").is_err());
    }
}
