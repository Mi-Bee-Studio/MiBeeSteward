//! SNMPv3 USM client (RFC 3414 / 3826 / 7860) — gosnmp v1.43.2 parity for
//! the one-shot system-OIDs Get the SNMP probe needs. Where the RFCs and
//! gosnmp disagree, gosnmp wins (Go code is the behavior reference):
//!
//! - key localization: Ku = H(password repeated to 2^20 bytes),
//!   Kul = H(Ku ‖ engineID ‖ Ku) — a plain hash chain, not HMAC;
//! - auth digest: MD5/SHA use the RFC 3414 §6.3.2 manual 64-byte-key-pad
//!   HMAC truncated to 12 octets; SHA224/256/384/512 use real HMAC
//!   (RFC 7860) truncated to 16/24/32/48;
//! - privacy: AES-CFB128 with IV = boots(4) ‖ time(4) ‖ salt(8) and a
//!   64-bit incrementing salt; DES-CBC with IV = Kul[8..16] XOR
//!   (boots(4) ‖ salt32(4)) and zero padding (a full pad block when the
//!   plaintext is already block-aligned, gosnmp's make-pad behavior);
//! - AES192/AES256 use the Blumenthal key extension (append H(key)),
//!   AES192C/AES256C the Reeder extension (re-localize with the key's
//!   bytes as the password) — gosnmp's genlocalPrivKey table;
//! - engine discovery: a blank Reportable|NoAuthNoPriv Get whose Report
//!   reply carries the authoritative engineID/boots/time.

use std::net::SocketAddr;
use std::time::Duration;

use sha2::digest::Digest;
use hmac::{Hmac, Mac};

use super::SnmpV3Credential;

// ---------- protocols ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthProtocol {
    NoAuth,
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivProtocol {
    NoPriv,
    Des,
    Aes,
    Aes192,
    Aes256,
    Aes192C,
    Aes256C,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    NoAuthNoPriv,
    AuthNoPriv,
    AuthPriv,
}

/// Static USM identity parsed from a stored credential. Validation mirrors
/// Go probe/snmp_conn.go: empty protocol strings are legal only for the
/// level that doesn't need them (no silent MD5 downgrade on a typo).
#[derive(Debug, Clone)]
pub struct V3Params {
    pub level: SecurityLevel,
    pub auth: AuthProtocol,
    pub auth_pass: String,
    pub priv_: PrivProtocol,
    pub priv_pass: String,
    pub username: String,
}

fn blank_params() -> V3Params {
    V3Params {
        level: SecurityLevel::NoAuthNoPriv,
        auth: AuthProtocol::NoAuth,
        auth_pass: String::new(),
        priv_: PrivProtocol::NoPriv,
        priv_pass: String::new(),
        username: String::new(),
    }
}

impl V3Params {
    pub fn from_credential(c: &SnmpV3Credential) -> Result<V3Params, String> {
        let level = match c.security_level.as_str() {
            "noAuthNoPriv" => SecurityLevel::NoAuthNoPriv,
            "authNoPriv" => SecurityLevel::AuthNoPriv,
            "authPriv" => SecurityLevel::AuthPriv,
            other => return Err(format!("unsupported v3 security level {other:?}")),
        };
        let auth = if c.auth_protocol.is_empty() {
            if level == SecurityLevel::NoAuthNoPriv {
                AuthProtocol::NoAuth
            } else {
                return Err(format!(
                    "auth_protocol required for security level {:?}",
                    c.security_level
                ));
            }
        } else {
            match c.auth_protocol.as_str() {
                "MD5" => AuthProtocol::Md5,
                "SHA" => AuthProtocol::Sha1,
                "SHA224" => AuthProtocol::Sha224,
                "SHA256" => AuthProtocol::Sha256,
                "SHA384" => AuthProtocol::Sha384,
                "SHA512" => AuthProtocol::Sha512,
                other => return Err(format!("unknown auth protocol {other:?}")),
            }
        };
        let priv_ = if c.priv_protocol.is_empty() {
            if level != SecurityLevel::AuthPriv {
                PrivProtocol::NoPriv
            } else {
                return Err(format!(
                    "priv_protocol required for security level {:?}",
                    c.security_level
                ));
            }
        } else {
            match c.priv_protocol.as_str() {
                "DES" => PrivProtocol::Des,
                "AES" => PrivProtocol::Aes,
                "AES192" => PrivProtocol::Aes192,
                "AES256" => PrivProtocol::Aes256,
                "AES192C" => PrivProtocol::Aes192C,
                "AES256C" => PrivProtocol::Aes256C,
                other => return Err(format!("unknown priv protocol {other:?}")),
            }
        };
        Ok(V3Params {
            level,
            auth,
            auth_pass: c.auth_passphrase.clone(),
            priv_,
            priv_pass: c.priv_passphrase.clone(),
            username: c.username.clone(),
        })
    }
}

// ---------- BER ----------

pub fn ber_len(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, (len & 0xFF) as u8]);
    }
}

pub fn ber_tlv(tag: u8, body: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    ber_len(body.len(), out);
    out.extend_from_slice(body);
}

/// Minimal unsigned INTEGER body (gosnmp marshalUint32/shrinkAndWriteUint).
/// Minimal unsigned INTEGER body: strip leading zero bytes, but RE-PAD one
/// when the top byte has bit7 set (BER INTEGERs are signed — `ff ff` reads
/// as -1, `00 ff ff` is 65535). net-snmp silently drops a message whose
/// msgMaxSize encodes negative; our own echo agent didn't, which is why
/// only the real-agent differential caught this.
pub fn minimal_uint(v: u64) -> Vec<u8> {
    let b = v.to_be_bytes();
    let first = b.iter().position(|x| *x != 0).unwrap_or(7);
    let mut out = b[first..].to_vec();
    if out[0] & 0x80 != 0 {
        out.insert(0, 0);
    }
    out
}

pub fn encode_oid(oid: &str) -> Vec<u8> {
    let parts: Vec<u64> = oid.split('.').map(|p| p.parse().unwrap_or(0)).collect();
    let mut body = Vec::new();
    body.push((parts[0] * 40 + parts[1]) as u8);
    for &p in &parts[2..] {
        if p < 128 {
            body.push(p as u8);
        } else {
            let mut stack = Vec::new();
            let mut v = p;
            stack.push((v & 0x7F) as u8);
            v >>= 7;
            while v > 0 {
                stack.push(((v & 0x7F) as u8) | 0x80);
                v >>= 7;
            }
            stack.reverse();
            body.extend_from_slice(&stack);
        }
    }
    let mut out = Vec::new();
    ber_tlv(0x06, &body, &mut out);
    out
}

pub(crate) struct BerReader<'a> {
    pub(crate) buf: &'a [u8],
    pub(crate) pos: usize,
}

impl<'a> BerReader<'a> {
    pub(crate) fn tlv(&mut self) -> Option<(u8, &'a [u8])> {
        let tag = *self.buf.get(self.pos)?;
        self.pos += 1;
        let first = *self.buf.get(self.pos)?;
        self.pos += 1;
        let len = if first < 128 {
            first as usize
        } else {
            let n = (first & 0x7F) as usize;
            if n == 0 || n > 4 {
                return None;
            }
            let mut l = 0usize;
            for _ in 0..n {
                l = (l << 8) | *self.buf.get(self.pos)? as usize;
                self.pos += 1;
            }
            l
        };
        let start = self.pos;
        self.pos = self.pos.checked_add(len)?;
        if self.pos > self.buf.len() {
            return None;
        }
        Some((tag, &self.buf[start..start + len]))
    }
}

fn decode_ber_int(body: &[u8]) -> Option<i64> {
    if body.is_empty() || body.len() > 8 {
        return None;
    }
    let mut v = if body[0] & 0x80 != 0 { -1i64 } else { 0 };
    for &b in body {
        v = (v << 8) | b as i64;
    }
    Some(v)
}

fn oid_to_string(body: &[u8]) -> String {
    if body.is_empty() {
        return String::new();
    }
    let mut parts = vec![(body[0] / 40).to_string(), (body[0] % 40).to_string()];
    let mut v: u64 = 0;
    for &b in &body[1..] {
        v = (v << 7) | (b & 0x7F) as u64;
        if b & 0x80 == 0 {
            parts.push(v.to_string());
            v = 0;
        }
    }
    parts.join(".")
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Decode one varbind value (strings, OIDs, ints, ticks, IP; unknown → hex).
pub fn decode_varbind_value(vt: u8, val: &[u8]) -> Option<String> {
    match vt {
        0x04 => Some(String::from_utf8_lossy(val).into_owned()),
        0x06 => Some(oid_to_string(val)),
        0x02 | 0x0A => decode_ber_int(val).map(|i| i.to_string()),
        0x05 | 0x80 => None,
        0x40 => Some(if val.len() == 4 {
            format!("{}.{}.{}.{}", val[0], val[1], val[2], val[3])
        } else {
            hex_of(val)
        }),
        0x43 => decode_ber_int(val).map(|t| t.to_string()),
        _ => Some(hex_of(val)),
    }
}

// ---------- key derivation ----------

enum Hasher {
    Md5(md5::Md5),
    Sha1(sha1::Sha1),
    Sha224(sha2::Sha224),
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
}

impl Hasher {
    fn new(auth: AuthProtocol) -> Hasher {
        match auth {
            AuthProtocol::Md5 | AuthProtocol::NoAuth => Hasher::Md5(<md5::Md5 as Digest>::new()),
            AuthProtocol::Sha1 => Hasher::Sha1(<sha1::Sha1 as Digest>::new()),
            AuthProtocol::Sha224 => Hasher::Sha224(<sha2::Sha224 as Digest>::new()),
            AuthProtocol::Sha256 => Hasher::Sha256(<sha2::Sha256 as Digest>::new()),
            AuthProtocol::Sha384 => Hasher::Sha384(<sha2::Sha384 as Digest>::new()),
            AuthProtocol::Sha512 => Hasher::Sha512(<sha2::Sha512 as Digest>::new()),
        }
    }
    fn update(&mut self, bytes: &[u8]) {
        match self {
            Hasher::Md5(h) => Digest::update(h, bytes),
            Hasher::Sha1(h) => Digest::update(h, bytes),
            Hasher::Sha224(h) => Digest::update(h, bytes),
            Hasher::Sha256(h) => Digest::update(h, bytes),
            Hasher::Sha384(h) => Digest::update(h, bytes),
            Hasher::Sha512(h) => Digest::update(h, bytes),
        }
    }
    fn finalize(self) -> Vec<u8> {
        match self {
            Hasher::Md5(h) => h.finalize().to_vec(),
            Hasher::Sha1(h) => h.finalize().to_vec(),
            Hasher::Sha224(h) => h.finalize().to_vec(),
            Hasher::Sha256(h) => h.finalize().to_vec(),
            Hasher::Sha384(h) => h.finalize().to_vec(),
            Hasher::Sha512(h) => h.finalize().to_vec(),
        }
    }
}

/// Ku = H(password repeated byte-wise to 2^20 bytes) — RFC 3414 A.2, fed in
/// 64-byte chunks exactly like gosnmp's hashPassword.
pub fn hash_password(auth: AuthProtocol, password: &[u8]) -> Vec<u8> {
    let mut h = Hasher::new(auth);
    let mut pi = 0usize;
    let mut chunk = [0u8; 64];
    for _ in (0..1u32 << 20).step_by(64) {
        for byte in chunk.iter_mut() {
            *byte = password[pi % password.len()];
            pi += 1;
        }
        h.update(&chunk);
    }
    h.finalize()
}

/// Kul = H(Ku ‖ engineID ‖ Ku).
pub(crate) fn localize(auth: AuthProtocol, ku: &[u8], engine_id: &[u8]) -> Vec<u8> {
    let mut h = Hasher::new(auth);
    h.update(ku);
    h.update(engine_id);
    h.update(ku);
    h.finalize()
}

fn auth_key(params: &V3Params, engine_id: &[u8]) -> Vec<u8> {
    let ku = hash_password(params.auth, params.auth_pass.as_bytes());
    localize(params.auth, &ku, engine_id)
}

/// Privacy key per gosnmp genlocalPrivKey: DES localizes directly; AES
/// variants extend first (Reeder for AES/AES192C/AES256C, Blumenthal for
/// AES192/AES256), then truncate to the cipher's key length.
fn priv_key(params: &V3Params, engine_id: &[u8]) -> Vec<u8> {
    let keylen = match params.priv_ {
        PrivProtocol::NoPriv => return Vec::new(),
        PrivProtocol::Des | PrivProtocol::Aes => 16,
        PrivProtocol::Aes192 | PrivProtocol::Aes192C => 24,
        PrivProtocol::Aes256 | PrivProtocol::Aes256C => 32,
    };
    let ku = hash_password(params.auth, params.priv_pass.as_bytes());
    let key = match params.priv_ {
        PrivProtocol::Des => localize(params.auth, &ku, engine_id),
        PrivProtocol::Aes | PrivProtocol::Aes192C | PrivProtocol::Aes256C => {
            // Reeder: treat the localized key's bytes as the password and
            // localize again; the extension supplies bytes past the first
            // hash length.
            let key = localize(params.auth, &ku, engine_id);
            let ku2 = hash_password(params.auth, &key);
            let mut out = key.clone();
            out.extend_from_slice(&localize(params.auth, &ku2, engine_id));
            out
        }
        PrivProtocol::Aes192 | PrivProtocol::Aes256 => {
            // Blumenthal: append H(key).
            let key = localize(params.auth, &ku, engine_id);
            let mut h = Hasher::new(params.auth);
            h.update(&key);
            let mut out = key;
            out.extend_from_slice(&h.finalize());
            out
        }
        PrivProtocol::NoPriv => unreachable!(),
    };
    key[..keylen].to_vec()
}

// ---------- digests ----------

fn digest_len(auth: AuthProtocol) -> usize {
    match auth {
        AuthProtocol::Md5 | AuthProtocol::Sha1 => 12,
        AuthProtocol::Sha224 => 16,
        AuthProtocol::Sha256 => 24,
        AuthProtocol::Sha384 => 32,
        AuthProtocol::Sha512 => 48,
        AuthProtocol::NoAuth => 0,
    }
}

/// Message digest over the full encoded message (authParams zeroed).
pub(crate) fn calc_digest(auth: AuthProtocol, key: &[u8], msg: &[u8]) -> Vec<u8> {
    let full: Vec<u8> = match auth {
        AuthProtocol::Md5 | AuthProtocol::Sha1 => {
            // RFC 3414 6.3.2 manual HMAC with a 64-byte zero-padded key.
            let mut extkey = [0u8; 64];
            extkey[..key.len().min(64)].copy_from_slice(&key[..key.len().min(64)]);
            let mut k1 = [0u8; 64];
            let mut k2 = [0u8; 64];
            for i in 0..64 {
                k1[i] = extkey[i] ^ 0x36;
                k2[i] = extkey[i] ^ 0x5c;
            }
            let mut h1 = Hasher::new(auth);
            h1.update(&k1);
            h1.update(msg);
            let d1 = h1.finalize();
            let mut h2 = Hasher::new(auth);
            h2.update(&k2);
            h2.update(&d1);
            h2.finalize()
        }
        AuthProtocol::Sha224 | AuthProtocol::Sha256 | AuthProtocol::Sha384 | AuthProtocol::Sha512 => {
            macro_rules! mac {
                ($t:ty) => {{
                    let mut m = <Hmac<$t> as Mac>::new_from_slice(key)
                        .expect("hmac accepts any key len");
                    Mac::update(&mut m, msg);
                    m.finalize().into_bytes().to_vec()
                }};
            }
            match auth {
                AuthProtocol::Sha224 => mac!(sha2::Sha224),
                AuthProtocol::Sha256 => mac!(sha2::Sha256),
                AuthProtocol::Sha384 => mac!(sha2::Sha384),
                AuthProtocol::Sha512 => mac!(sha2::Sha512),
                _ => unreachable!(),
            }
        }
        AuthProtocol::NoAuth => Vec::new(),
    };
    full[..digest_len(auth)].to_vec()
}

// ---------- privacy ----------

fn aes_cfb(key: &[u8], iv: &[u8; 16], data: &mut [u8], encrypt: bool) -> bool {
    use cfb_mode::cipher::{AsyncStreamCipher, InnerIvInit, KeyInit};
    let giv = aes::cipher::generic_array::GenericArray::from_slice(iv);
    match (key.len(), encrypt) {
        (16, true) => {
            let Ok(c) = aes::Aes128::new_from_slice(key) else { return false };
            cfb_mode::Encryptor::<aes::Aes128>::inner_iv_init(c, giv).encrypt(data);
            true
        }
        (16, false) => {
            let Ok(c) = aes::Aes128::new_from_slice(key) else { return false };
            cfb_mode::Decryptor::<aes::Aes128>::inner_iv_init(c, giv).decrypt(data);
            true
        }
        (24, true) => {
            let Ok(c) = aes::Aes192::new_from_slice(key) else { return false };
            cfb_mode::Encryptor::<aes::Aes192>::inner_iv_init(c, giv).encrypt(data);
            true
        }
        (24, false) => {
            let Ok(c) = aes::Aes192::new_from_slice(key) else { return false };
            cfb_mode::Decryptor::<aes::Aes192>::inner_iv_init(c, giv).decrypt(data);
            true
        }
        (32, true) => {
            let Ok(c) = aes::Aes256::new_from_slice(key) else { return false };
            cfb_mode::Encryptor::<aes::Aes256>::inner_iv_init(c, giv).encrypt(data);
            true
        }
        (32, false) => {
            let Ok(c) = aes::Aes256::new_from_slice(key) else { return false };
            cfb_mode::Decryptor::<aes::Aes256>::inner_iv_init(c, giv).decrypt(data);
            true
        }
        _ => false,
    }
}

/// Encrypt/decrypt the (SEQ-wrapped) scopedPDU with AES-CFB128;
/// IV = boots ‖ time ‖ salt(8). On encrypt, returns the OCTET STRING
/// wrapper TLV; on decrypt, the plaintext bytes.
fn aes_priv(key: &[u8], boots: u32, time: u32, salt: [u8; 8], scoped_pdu: &[u8], encrypt: bool) -> Option<Vec<u8>> {
    let mut iv = [0u8; 16];
    iv[..4].copy_from_slice(&boots.to_be_bytes());
    iv[4..8].copy_from_slice(&time.to_be_bytes());
    iv[8..].copy_from_slice(&salt);
    let mut data = scoped_pdu.to_vec();
    if !aes_cfb(key, &iv, &mut data, encrypt) {
        return None;
    }
    if encrypt {
        let mut out = Vec::new();
        ber_tlv(0x04, &data, &mut out);
        Some(out)
    } else {
        Some(data)
    }
}

fn des_cbc(key8: &[u8], iv: &[u8; 8], data: &mut [u8], encrypt: bool) -> bool {
    // Block-wise in-place CBC (the buffer is already zero-padded to a
    // multiple of 8 by the caller, gosnmp's approach).
    use cfb_mode::cipher::KeyIvInit;
    use des::cipher::generic_array::GenericArray;
    use des::cipher::{BlockDecryptMut, BlockEncryptMut};
    type DesEnc = cbc::Encryptor<des::Des>;
    type DesDec = cbc::Decryptor<des::Des>;
    if data.len() % 8 != 0 {
        return false;
    }
    if encrypt {
        let Ok(mut c) = DesEnc::new_from_slices(key8, iv) else { return false };
        for chunk in data.chunks_exact_mut(8) {
            c.encrypt_block_mut(GenericArray::from_mut_slice(chunk));
        }
        true
    } else {
        let Ok(mut c) = DesDec::new_from_slices(key8, iv) else { return false };
        for chunk in data.chunks_exact_mut(8) {
            c.decrypt_block_mut(GenericArray::from_mut_slice(chunk));
        }
        true
    }
}

/// DES privacy: pre-IV = key[8..16], IV = pre-IV XOR (boots ‖ salt32),
/// zero padding (always to a block boundary; a full pad block when already
/// aligned, gosnmp's behavior). `des_salt` is the incrementing counter32.
fn des_priv(key: &[u8], boots: u32, des_salt: u32, scoped_pdu: &[u8], encrypt: bool) -> Option<Vec<u8>> {
    let preiv = key.get(8..16)?;
    let salt8 = [boots.to_be_bytes(), des_salt.to_be_bytes()].concat();
    let mut iv = [0u8; 8];
    for i in 0..8 {
        iv[i] = preiv[i] ^ salt8[i];
    }
    if encrypt {
        let pad = 8 - scoped_pdu.len() % 8;
        let mut data = scoped_pdu.to_vec();
        data.extend(std::iter::repeat(0u8).take(pad));
        if !des_cbc(&key[..8], &iv, &mut data, true) {
            return None;
        }
        let mut out = Vec::new();
        ber_tlv(0x04, &data, &mut out);
        Some(out)
    } else {
        let mut data = scoped_pdu.to_vec();
        if data.is_empty() || data.len() % 8 != 0 || !des_cbc(&key[..8], &iv, &mut data, false) {
            return None;
        }
        // Padding stays (gosnmp doesn't strip it); the scopedPDU SEQUENCE
        // length governs parsing.
        Some(data)
    }
}

// ---------- message codec ----------

pub const MSG_FLAG_AUTH: u8 = 0x01;
pub const MSG_FLAG_PRIV: u8 = 0x02;
pub const MSG_FLAG_REPORTABLE: u8 = 0x04;

/// usmStatsNotInTimeWindows.0 — the one recoverable Report (fresh engine
/// values ride the same message; gosnmp retransmits on it).
const USM_STATS_NOT_IN_TIME_WINDOW: &str = "1.3.6.1.6.3.15.1.1.2.0";

/// Marker parked in varbind_names when msgData is an encrypted OCTET
/// STRING; the session decrypts then re-parses the scopedPDU.
pub const ENCRYPTED_MARKER: &str = "__encrypted__:";

/// One decoded incoming v3 message.
#[derive(Debug)]
pub struct V3Message {
    pub msg_id: i64,
    pub msg_flags: u8,
    pub engine_id: Vec<u8>,
    pub boots: u32,
    pub time: u32,
    pub user: String,
    pub auth_params: Vec<u8>,
    pub priv_params: Vec<u8>,
    /// Offset of the authParams VALUE inside the original buffer (zeroing
    /// there re-creates the digest input).
    pub auth_value_offset: usize,
    pub pdu_tag: u8,
    pub req_id: i64,
    pub varbinds: Vec<Option<String>>,
    pub varbind_names: Vec<String>,
    /// Raw (oid, value tag, value bytes) parallel to varbinds — walk paths
    /// need binary values (e.g. 6-octet PhysAddress) that must not pass
    /// through UTF-8 lossy decoding. Filled by parse_scoped_pdu.
    pub varbind_raw: Vec<(String, u8, Vec<u8>)>,
    /// PDU error-status (2 = noSuchName, the end-of-table signal on v1-style
    /// agents). Exposed for the walk loop; 0 in normal responses.
    pub error_status: u8,
}

pub struct V3Session {
    pub params: V3Params,
    pub engine_id: Vec<u8>,
    pub boots: u32,
    pub time: u32,
    pub auth_key: Vec<u8>,
    pub priv_key: Vec<u8>,
    aes_salt: u64,
    des_salt: u32,
    msg_id: u32,
    req_id: i32,
}

impl V3Session {
    pub fn new(params: V3Params, engine_id: Vec<u8>, boots: u32, time: u32) -> V3Session {
        let auth_key = if params.auth != AuthProtocol::NoAuth {
            auth_key(&params, &engine_id)
        } else {
            Vec::new()
        };
        let priv_key = if params.priv_ != PrivProtocol::NoPriv {
            priv_key(&params, &engine_id)
        } else {
            Vec::new()
        };
        V3Session {
            params,
            engine_id,
            boots,
            time,
            auth_key,
            priv_key,
            aes_salt: rand::random::<u64>(),
            des_salt: rand::random::<u32>(),
            msg_id: rand::random::<u32>() & 0x7FFF_FFFF,
            req_id: rand::random::<u32>() as i32 & 0x7FFF_FFFF,
        }
    }

    pub fn flags(&self) -> u8 {
        match self.params.level {
            SecurityLevel::NoAuthNoPriv => 0,
            SecurityLevel::AuthNoPriv => MSG_FLAG_AUTH,
            SecurityLevel::AuthPriv => MSG_FLAG_AUTH | MSG_FLAG_PRIV,
        }
    }

    pub fn req_id(&self) -> i32 {
        self.req_id
    }

    /// Encode a PDU inside a full v3 message with this session's auth/priv.
    /// `blank_identity` builds the RFC 3414 §4 discovery probe: empty
    /// engine/user fields and no auth/priv regardless of the session's
    /// credentials (the flags still carry Reportable).
    pub fn encode_message(&mut self, pdu_tag: u8, pdu_body: &[u8], flags: u8, blank_identity: bool) -> Vec<u8> {
        let discovery = blank_identity;
        let auth_on = !discovery && self.params.auth != AuthProtocol::NoAuth && flags & MSG_FLAG_AUTH != 0;
        let priv_on = !discovery && self.params.priv_ != PrivProtocol::NoPriv && flags & MSG_FLAG_PRIV != 0;
        self.msg_id = self.msg_id.wrapping_add(1) & 0x7FFF_FFFF;

        // scopedPDU
        let mut scoped_inner = Vec::new();
        if discovery {
            ber_tlv(0x04, &[], &mut scoped_inner); // contextEngineID
            ber_tlv(0x04, &[], &mut scoped_inner); // contextName
        } else {
            ber_tlv(0x04, &self.engine_id, &mut scoped_inner);
            ber_tlv(0x04, &[], &mut scoped_inner);
        }
        ber_tlv(pdu_tag, pdu_body, &mut scoped_inner);
        let mut scoped_pdu = Vec::new();
        ber_tlv(0x30, &scoped_inner, &mut scoped_pdu);

        // privacy
        let mut priv_params: Vec<u8> = Vec::new();
        let msg_data: Vec<u8> = if priv_on {
            match self.params.priv_ {
                PrivProtocol::Des => {
                    self.des_salt = self.des_salt.wrapping_add(1);
                    priv_params = [self.boots.to_be_bytes(), self.des_salt.to_be_bytes()].concat();
                    des_priv(&self.priv_key, self.boots, self.des_salt, &scoped_pdu, true)
                }
                _ => {
                    self.aes_salt = self.aes_salt.wrapping_add(1);
                    let mut salt = [0u8; 8];
                    salt.copy_from_slice(&self.aes_salt.to_be_bytes());
                    priv_params = salt.to_vec();
                    aes_priv(&self.priv_key, self.boots, self.time, salt, &scoped_pdu, true)
                }
            }
            .unwrap_or_else(|| scoped_pdu.clone())
        } else {
            scoped_pdu
        };

        // security parameters (USM)
        let mut usm = Vec::new();
        if discovery {
            ber_tlv(0x04, &[], &mut usm); // engineID
            ber_tlv(0x02, &minimal_uint(0), &mut usm); // boots
            ber_tlv(0x02, &minimal_uint(0), &mut usm); // time
            ber_tlv(0x04, &[], &mut usm); // user
            ber_tlv(0x04, &[], &mut usm); // authParams (empty: no auth)
            ber_tlv(0x04, &[], &mut usm); // privParams
        } else {
            ber_tlv(0x04, &self.engine_id, &mut usm);
            ber_tlv(0x02, &minimal_uint(self.boots as u64), &mut usm);
            ber_tlv(0x02, &minimal_uint(self.time as u64), &mut usm);
            ber_tlv(0x04, self.params.username.as_bytes(), &mut usm);
            let mut auth_placeholder = Vec::new();
            if auth_on {
                ber_tlv(0x04, &vec![0u8; digest_len(self.params.auth)], &mut auth_placeholder);
            } else {
                ber_tlv(0x04, &[], &mut auth_placeholder);
            }
            usm.extend_from_slice(&auth_placeholder);
            let mut priv_os = Vec::new();
            ber_tlv(0x04, &priv_params, &mut priv_os);
            usm.extend_from_slice(&priv_os);
            let mut usm_seq = Vec::new();
            ber_tlv(0x30, &usm, &mut usm_seq);
            let mut sec_params = Vec::new();
            ber_tlv(0x04, &usm_seq, &mut sec_params);
            return self.finish_message(flags, &sec_params, &msg_data, auth_on, &auth_placeholder);
        }
        let mut usm_seq = Vec::new();
        ber_tlv(0x30, &usm, &mut usm_seq);
        let mut sec_params = Vec::new();
        ber_tlv(0x04, &usm_seq, &mut sec_params);
        self.finish_message(flags, &sec_params, &msg_data, false, &[])
    }

    /// Assemble the whole message and splice the auth digest into the
    /// planted placeholder (located by exact byte pattern inside the
    /// security-parameters region, the same trick gosnmp's bytes.Index
    /// pulls with macVarbinds).
    fn finish_message(&self, flags: u8, sec_params: &[u8], msg_data: &[u8], auth_on: bool, placeholder: &[u8]) -> Vec<u8> {
        let mut header = Vec::new();
        ber_tlv(0x02, &self.msg_id.to_be_bytes(), &mut header); // fixed 4 bytes (gosnmp)
        ber_tlv(0x02, &minimal_uint(65535), &mut header); // msgMaxSize
        let mut flag_os = Vec::new();
        ber_tlv(0x04, &[flags], &mut flag_os);
        header.extend_from_slice(&flag_os);
        ber_tlv(0x02, &[3], &mut header); // msgSecurityModel = USM

        let mut header_seq = Vec::new();
        ber_tlv(0x30, &header, &mut header_seq);
        let mut body = Vec::new();
        ber_tlv(0x02, &[3], &mut body); // snmpVersion = 3
        body.extend_from_slice(&header_seq);
        body.extend_from_slice(sec_params);
        body.extend_from_slice(msg_data);
        let mut msg = Vec::new();
        ber_tlv(0x30, &body, &mut msg);

        if auth_on {
            // The placeholder lives wholly inside sec_params (which ends
            // msg_data.len() bytes before the packet end).
            let sec_region_end = msg.len() - msg_data.len();
            let idx = msg[..sec_region_end]
                .windows(placeholder.len())
                .position(|w| w == placeholder)
                .expect("auth placeholder planted above");
            let value_at = idx + 2; // skip [tag, len] (digest_len < 128)
            let digest = calc_digest(self.params.auth, &self.auth_key, &msg);
            msg[value_at..value_at + digest.len()].copy_from_slice(&digest);
        }
        msg
    }

    /// Build a GetRequest for `oids`.
    pub fn build_get(&mut self, oids: &[&str], discovery: bool) -> Vec<u8> {
        if !discovery {
            self.req_id = self.req_id.wrapping_add(1) & 0x7FFF_FFFF;
        }
        let mut varbinds = Vec::new();
        for oid in oids {
            let mut vb = encode_oid(oid);
            ber_tlv(0x05, &[], &mut vb);
            ber_tlv(0x30, &vb, &mut varbinds);
        }
        let mut vbl_seq = Vec::new();
        ber_tlv(0x30, &varbinds, &mut vbl_seq);
        let req_id = if discovery { 0 } else { self.req_id };
        let mut pdu_body = Vec::new();
        ber_tlv(0x02, &minimal_uint(req_id as u64), &mut pdu_body);
        ber_tlv(0x02, &[0], &mut pdu_body); // error-status
        ber_tlv(0x02, &[0], &mut pdu_body); // error-index
        pdu_body.extend_from_slice(&vbl_seq);
        let flags = if discovery { MSG_FLAG_REPORTABLE } else { self.flags() };
        self.encode_message(0xA0, &pdu_body, flags, discovery)
    }

    /// Build a single-OID GetNextRequest (PDU tag 0xA1) — the walk step.
    pub fn build_getnext(&mut self, oid: &str, discovery: bool) -> Vec<u8> {
        if !discovery {
            self.req_id = self.req_id.wrapping_add(1) & 0x7FFF_FFFF;
        }
        let mut vb = encode_oid(oid);
        ber_tlv(0x05, &[], &mut vb);
        let mut varbinds = Vec::new();
        ber_tlv(0x30, &vb, &mut varbinds);
        let mut vbl_seq = Vec::new();
        ber_tlv(0x30, &varbinds, &mut vbl_seq);
        let req_id = if discovery { 0 } else { self.req_id };
        let mut pdu_body = Vec::new();
        ber_tlv(0x02, &minimal_uint(req_id as u64), &mut pdu_body);
        ber_tlv(0x02, &[0], &mut pdu_body); // error-status
        ber_tlv(0x02, &[0], &mut pdu_body); // error-index
        pdu_body.extend_from_slice(&vbl_seq);
        let flags = if discovery { MSG_FLAG_REPORTABLE } else { self.flags() };
        self.encode_message(0xA1, &pdu_body, flags, discovery)
    }

    /// Verify + decode an incoming message against this session.
    /// `from_discovery` skips authentication (RFC 3414 §4 exchange).
    pub fn decode(&self, buf: &[u8], expect_req_id: i32, from_discovery: bool) -> Result<V3Message, V3Error> {
        let msg = decode_v3_message(buf).ok_or(V3Error::BadPacket)?;
        if msg.req_id != 0 && expect_req_id != 0 && msg.req_id != expect_req_id as i64 {
            return Err(V3Error::BadPacket);
        }
        if !from_discovery && self.params.auth != AuthProtocol::NoAuth {
            if msg.user != self.params.username {
                return Err(V3Error::AuthFail);
            }
            let mut zeroed = buf.to_vec();
            let end = msg.auth_value_offset + msg.auth_params.len();
            if end > zeroed.len() {
                return Err(V3Error::BadPacket);
            }
            zeroed[msg.auth_value_offset..end].fill(0);
            let digest = calc_digest(self.params.auth, &self.auth_key, &zeroed);
            if !constant_time_eq(&digest, &msg.auth_params) {
                return Err(V3Error::AuthFail);
            }
        }
        Ok(msg)
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Decode a v3 message: header, USM security parameters, scopedPDU
/// (plaintext SEQ parsed in place; encrypted OCTET STRING parked under
/// ENCRYPTED_MARKER for the session to decrypt — its keys are needed).
pub fn decode_v3_message(buf: &[u8]) -> Option<V3Message> {
    let mut top = BerReader { buf, pos: 0 };
    let (_, msg_body) = top.tlv()?;
    let mut r = BerReader { buf: msg_body, pos: 0 };
    let (_, version) = r.tlv()?;
    if decode_ber_int(version)? != 3 {
        return None;
    }
    let (_, header) = r.tlv()?; // msgGlobalData SEQ
    let mut hr = BerReader { buf: header, pos: 0 };
    let (_, msg_id) = hr.tlv()?;
    let (_, _max_size) = hr.tlv()?;
    let (ft, flags) = hr.tlv()?;
    if ft != 0x04 || flags.is_empty() {
        return None;
    }
    let (_, _model) = hr.tlv()?;
    let (st, sec_params) = r.tlv()?; // OCTET STRING wrapping USM
    if st != 0x04 {
        return None;
    }
    let mut sr = BerReader { buf: sec_params, pos: 0 };
    let (seq_t, usm) = sr.tlv()?;
    if seq_t != 0x30 {
        return None;
    }
    let mut ur = BerReader { buf: usm, pos: 0 };
    let (_, engine_id) = ur.tlv()?;
    let (_, boots) = ur.tlv()?;
    let (_, time) = ur.tlv()?;
    let (_, user) = ur.tlv()?;
    let (_, auth_params) = ur.tlv()?;
    let (_, priv_params) = ur.tlv()?;
    // All subslices of one buffer: pointer deltas give the absolute offset.
    let auth_value_offset = auth_params.as_ptr() as usize - buf.as_ptr() as usize;

    let (data_tag, data) = r.tlv()?;
    let mut out = V3Message {
        msg_id: decode_ber_int(msg_id)?,
        msg_flags: flags[0],
        engine_id: engine_id.to_vec(),
        boots: decode_ber_int(boots)? as u32,
        time: decode_ber_int(time)? as u32,
        user: String::from_utf8_lossy(user).into_owned(),
        auth_params: auth_params.to_vec(),
        priv_params: priv_params.to_vec(),
        auth_value_offset,
        pdu_tag: 0,
        req_id: 0,
        varbinds: Vec::new(),
        varbind_names: Vec::new(),
        varbind_raw: Vec::new(),
        error_status: 0,
    };
    if data_tag == 0x30 {
        let mut wrapped = Vec::new();
        ber_tlv(0x30, data, &mut wrapped);
        parse_scoped_pdu(&wrapped, &mut out)?;
    } else if data_tag == 0x04 {
        out.varbind_names.push(format!("{ENCRYPTED_MARKER}{}", hex_of(data)));
    } else {
        return None;
    }
    Some(out)
}

/// Decrypt an encrypted scopedPDU (the ENCRYPTED_MARKER payload) with the
/// session keys and the message's engine values + privParams salt.
pub fn decrypt_scoped_pdu(session: &V3Session, msg: &V3Message, ciphertext: &[u8]) -> Option<Vec<u8>> {
    match session.params.priv_ {
        PrivProtocol::Des => {
            let boots = u32::from_be_bytes(msg.priv_params.get(0..4)?.try_into().ok()?);
            let salt32 = u32::from_be_bytes(msg.priv_params.get(4..8)?.try_into().ok()?);
            des_priv(&session.priv_key, boots, salt32, ciphertext, false)
        }
        PrivProtocol::Aes | PrivProtocol::Aes192 | PrivProtocol::Aes256
        | PrivProtocol::Aes192C | PrivProtocol::Aes256C => {
            let mut salt = [0u8; 8];
            salt.copy_from_slice(msg.priv_params.get(0..8)?);
            aes_priv(&session.priv_key, msg.boots, msg.time, salt, ciphertext, false)
        }
        PrivProtocol::NoPriv => Some(ciphertext.to_vec()),
    }
}

/// Parse a scopedPDU (SEQ{ctxEngineID, ctxName, PDU}) into the message.
pub fn parse_scoped_pdu(bytes: &[u8], out: &mut V3Message) -> Option<()> {
    let mut top = BerReader { buf: bytes, pos: 0 };
    let (seq_t, body) = top.tlv()?;
    if seq_t != 0x30 {
        return None;
    }
    let mut r = BerReader { buf: body, pos: 0 };
    let (_, _ctx_engine) = r.tlv()?;
    let (_, _ctx_name) = r.tlv()?;
    let (pdu_tag, pdu) = r.tlv()?;
    if !(0xA0..=0xA8).contains(&pdu_tag) {
        return None;
    }
    let mut p = BerReader { buf: pdu, pos: 0 };
    let (_, idb) = p.tlv()?;
    out.req_id = decode_ber_int(idb)?;
    let (_t, err_status) = p.tlv()?;
    out.error_status = decode_ber_int(err_status).unwrap_or(0).clamp(0, 255) as u8;
    let (_t, _err_idx) = p.tlv()?;
    let (_t, vbl) = p.tlv()?;
    let mut v = BerReader { buf: vbl, pos: 0 };
    while let Some((tag, vb)) = v.tlv() {
        if tag != 0x30 {
            return None;
        }
        let mut vb_r = BerReader { buf: vb, pos: 0 };
        let (_, oid) = vb_r.tlv()?;
        let (vt, val) = vb_r.tlv()?;
        out.varbind_names.push(oid_to_string(oid));
        out.varbind_raw
            .push((oid_to_string(oid), vt, val.to_vec()));
        out.varbinds.push(decode_varbind_value(vt, val));
    }
    out.pdu_tag = pdu_tag;
    Some(())
}

// ---------- client flow ----------

#[derive(Debug, PartialEq)]
pub enum V3Error {
    Timeout,
    BadPacket,
    AuthFail,
    DecryptFail,
    Report(String),
    BadCredential(String),
}

impl std::fmt::Display for V3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            V3Error::Timeout => write!(f, "v3: no response"),
            V3Error::BadPacket => write!(f, "v3: malformed response"),
            V3Error::AuthFail => write!(f, "v3: authentication failed"),
            V3Error::DecryptFail => write!(f, "v3: decryption failed"),
            V3Error::Report(r) => write!(f, "v3: report {r}"),
            V3Error::BadCredential(r) => write!(f, "v3: credential {r}"),
        }
    }
}

/// One UDP exchange: send `pkt`, wait up to `timeout` for any reply.
pub(crate) async fn udp_exchange(addr: SocketAddr, pkt: &[u8], timeout: Duration) -> Option<Vec<u8>> {
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    sock.send_to(pkt, addr).await.ok()?;
    let mut buf = vec![0u8; 8192];
    let Ok(Ok((n, _))) = tokio::time::timeout(timeout, sock.recv_from(&mut buf)).await else {
        return None;
    };
    buf.truncate(n);
    Some(buf)
}

/// Full v3 Get: engine discovery (Report), then the authenticated and
/// (optionally) encrypted Get — one retry after a dropped response, one
/// re-send after a not-in-time-window report (gosnmp's recoverable case).
#[allow(clippy::too_many_lines)]
pub async fn v3_get(
    addr: SocketAddr,
    cred: &SnmpV3Credential,
    timeout: Duration,
    oids: &[&str],
) -> Result<Vec<Option<String>>, V3Error> {
    let params = V3Params::from_credential(cred).map_err(V3Error::BadCredential)?;

    // 1. engine discovery (blank Reportable packet, unauthenticated).
    let mut discovery = V3Session::new(blank_params(), Vec::new(), 0, 0);
    let probe = discovery.build_get(&[], true);
    let reply = udp_exchange(addr, &probe, timeout)
        .await
        .ok_or(V3Error::Timeout)?;
    let report = decode_v3_message(&reply).ok_or(V3Error::BadPacket)?;
    if report.engine_id.is_empty() {
        return Err(V3Error::BadPacket);
    }

    // 2. real session with localized keys.
    let mut session = V3Session::new(params, report.engine_id.clone(), report.boots, report.time);
    for attempt in 0..3 {
        let pkt = session.build_get(oids, false);
        let expect = session.req_id();
        let Some(reply) = udp_exchange(addr, &pkt, timeout).await else {
            if attempt == 0 {
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
            return Err(V3Error::Timeout);
        };
        let mut msg = match session.decode(&reply, expect, false) {
            Ok(m) => m,
            // some agents answer with reqid 0; tolerate that one shape
            Err(V3Error::BadPacket) if decode_v3_message(&reply).map(|m| m.req_id) == Some(0) => {
                session.decode(&reply, 0, false)?
            }
            Err(e) => return Err(e),
        };
        // encrypted msgData: decrypt + re-parse the scopedPDU
        if let Some(marker) = msg.varbind_names.first().cloned() {
            if let Some(ct_hex) = marker.strip_prefix(ENCRYPTED_MARKER) {
                let ct = hex_to_bytes(ct_hex).ok_or(V3Error::BadPacket)?;
                let pt = decrypt_scoped_pdu(&session, &msg, &ct).ok_or(V3Error::DecryptFail)?;
                msg.varbind_names.clear();
                msg.varbinds.clear();
                parse_scoped_pdu(&pt, &mut msg).ok_or(V3Error::BadPacket)?;
            }
        }
        if msg.req_id != 0 && msg.req_id != expect as i64 {
            return Err(V3Error::BadPacket);
        }
        if msg.pdu_tag == 0xA8 {
            // Report PDU: not-in-time-window is recoverable with the fresh
            // engine values the report carries; anything else is fatal.
            let name = msg.varbind_names.first().cloned().unwrap_or_default();
            if name == USM_STATS_NOT_IN_TIME_WINDOW {
                session.boots = msg.boots;
                session.time = msg.time;
                continue;
            }
            return Err(V3Error::Report(name));
        }
        if msg.varbinds.is_empty() {
            if attempt == 0 {
                continue;
            }
            return Err(V3Error::BadPacket);
        }
        return Ok(msg.varbinds);
    }
    Err(V3Error::Timeout)
}

/// v3 GetNext walk of one table column: engine discovery, then the
/// authenticated/encrypted GetNext loop until the returned OID leaves the
/// subtree (v2c-style end) or noSuchName (error_status 2). Returns raw
/// varbinds (binary table values). 1024-row bound, same as v2c.
pub async fn v3_walk(
    addr: SocketAddr,
    cred: &SnmpV3Credential,
    timeout: Duration,
    root_oid: &str,
) -> Result<Vec<(String, u8, Vec<u8>)>, V3Error> {
    let params = V3Params::from_credential(cred).map_err(V3Error::BadCredential)?;

    // engine discovery (same blank Reportable exchange as v3_get).
    let mut discovery = V3Session::new(blank_params(), Vec::new(), 0, 0);
    let probe = discovery.build_getnext(root_oid, true);
    let reply = udp_exchange(addr, &probe, timeout)
        .await
        .ok_or(V3Error::Timeout)?;
    let report = decode_v3_message(&reply).ok_or(V3Error::BadPacket)?;
    if report.engine_id.is_empty() {
        return Err(V3Error::BadPacket);
    }

    let mut session = V3Session::new(params, report.engine_id.clone(), report.boots, report.time);
    let mut next = root_oid.to_string();
    let mut out: Vec<(String, u8, Vec<u8>)> = Vec::new();
    for _ in 0..1024 {
        let pkt = session.build_getnext(&next, false);
        let expect = session.req_id();
        let Some(reply) = udp_exchange(addr, &pkt, timeout).await else {
            return Err(V3Error::Timeout);
        };
        let mut msg = session.decode(&reply, expect, false)?;
        if let Some(marker) = msg.varbind_names.first().cloned() {
            if let Some(ct_hex) = marker.strip_prefix(ENCRYPTED_MARKER) {
                let ct = hex_to_bytes(ct_hex).ok_or(V3Error::BadPacket)?;
                let pt = decrypt_scoped_pdu(&session, &msg, &ct).ok_or(V3Error::DecryptFail)?;
                msg.varbind_names.clear();
                msg.varbinds.clear();
                msg.varbind_raw.clear();
                parse_scoped_pdu(&pt, &mut msg).ok_or(V3Error::BadPacket)?;
            }
        }
        if msg.req_id != 0 && msg.req_id != expect as i64 {
            return Err(V3Error::BadPacket);
        }
        if msg.pdu_tag == 0xA8 {
            let name = msg.varbind_names.first().cloned().unwrap_or_default();
            if name == USM_STATS_NOT_IN_TIME_WINDOW {
                session.boots = msg.boots;
                session.time = msg.time;
                continue;
            }
            return Err(V3Error::Report(name));
        }
        if msg.error_status == 2 {
            break; // noSuchName: past the table end
        }
        let Some((oid, tag, value)) = msg.varbind_raw.first().cloned() else {
            break;
        };
        if !super::snmp::oid_starts_with(&oid, root_oid) {
            break; // next lexical OID outside the walked subtree
        }
        next = oid.clone();
        out.push((oid, tag, value));
    }
    Ok(out)
}

pub fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(level: &str, auth: &str, privp: &str) -> SnmpV3Credential {
        SnmpV3Credential {
            username: "admin".into(),
            security_level: level.into(),
            auth_protocol: auth.into(),
            auth_passphrase: "authpass".into(),
            priv_protocol: privp.into(),
            priv_passphrase: "privpass".into(),
        }
    }

    #[test]
    fn minimal_uint_pads_high_bit() {
        // BER INTEGER is signed: an unpadded 65535 reads as -1 and net-snmp
        // drops the whole message (found via the real-agent walk differential).
        assert_eq!(minimal_uint(65535), vec![0x00, 0xff, 0xff]);
        assert_eq!(minimal_uint(0x7f), vec![0x7f]);
        assert_eq!(minimal_uint(0x80), vec![0x00, 0x80]);
        assert_eq!(minimal_uint(0), vec![0]);
        assert_eq!(minimal_uint(300), vec![0x01, 0x2c]); // no spurious pad
    }

    #[test]
    fn params_validation_matches_go() {
        assert!(V3Params::from_credential(&cred("authPriv", "", "AES")).is_err());
        assert!(V3Params::from_credential(&cred("authPriv", "MD5", "")).is_err());
        assert!(V3Params::from_credential(&cred("noAuthNoPriv", "", "")).is_ok());
        assert!(V3Params::from_credential(&cred("bogus", "MD5", "AES")).is_err());
        assert!(V3Params::from_credential(&cred("authNoPriv", "QUANTUM", "")).is_err());
        assert!(V3Params::from_credential(&cred("authPriv", "SHA512", "AES256C")).is_ok());
        // empty passphrases for authenticated levels yield keys from ""
        // (gosnmp validate() would reject; the CLI validates on add).
    }

    #[test]
    fn password_hash_is_the_1mib_repeat_form() {
        let ku = hash_password(AuthProtocol::Md5, b"maplesyrup");
        assert_eq!(ku.len(), 16);
        assert_eq!(ku, hash_password(AuthProtocol::Md5, b"maplesyrup"));
        assert_ne!(ku, hash_password(AuthProtocol::Md5, b"maplesyrux"));
        assert_eq!(hash_password(AuthProtocol::Sha224, b"x").len(), 28);
        assert_eq!(hash_password(AuthProtocol::Sha256, b"x").len(), 32);
        assert_eq!(hash_password(AuthProtocol::Sha384, b"x").len(), 48);
        assert_eq!(hash_password(AuthProtocol::Sha512, b"x").len(), 64);
    }

    #[test]
    fn localization_wraps_engine_id() {
        let ku = hash_password(AuthProtocol::Sha1, b"pw");
        let kul = localize(AuthProtocol::Sha1, &ku, b"\x80\x00\x1f\x88\x80");
        assert_eq!(kul.len(), 20);
        assert_ne!(kul, ku);
        assert_ne!(kul, localize(AuthProtocol::Sha1, &ku, b"\x80\x00\x00\x00\x0c"));
    }

    #[test]
    fn rfc3414_digest_equals_generic_hmac() {
        // RFC 3414's manual 64-byte-key-pad HMAC must equal generic HMAC
        // for keys shorter than the block size — exactly our case.
        let key = localize(AuthProtocol::Md5, &hash_password(AuthProtocol::Md5, b"pw"), b"eng");
        let msg = b"the quick brown fox";
        let d = calc_digest(AuthProtocol::Md5, &key, msg);
        assert_eq!(d.len(), 12);
        let mut m = <Hmac<md5::Md5> as Mac>::new_from_slice(&key).unwrap();
        Mac::update(&mut m, msg);
        let full = m.finalize().into_bytes();
        assert_eq!(&d[..], &full[..12]);
        assert_eq!(calc_digest(AuthProtocol::Sha1, &key, msg).len(), 12);
    }

    #[test]
    fn sha2_digests_truncate_per_gosnmp_lengths() {
        for (auth, len) in [
            (AuthProtocol::Sha224, 16),
            (AuthProtocol::Sha256, 24),
            (AuthProtocol::Sha384, 32),
            (AuthProtocol::Sha512, 48),
        ] {
            let key = localize(auth, &hash_password(auth, b"pw"), b"eng");
            assert_eq!(calc_digest(auth, &key, b"msg").len(), len, "{auth:?}");
        }
    }

    #[test]
    fn priv_key_lengths_and_extensions() {
        let params = |privp: PrivProtocol| V3Params {
            level: SecurityLevel::AuthPriv,
            auth: AuthProtocol::Md5,
            auth_pass: "a".into(),
            priv_: privp,
            priv_pass: "p".into(),
            username: "u".into(),
        };
        let engine = b"\x80\x00\x1f\x88\x80";
        assert_eq!(priv_key(&params(PrivProtocol::Aes), engine).len(), 16);
        assert_eq!(priv_key(&params(PrivProtocol::Aes192), engine).len(), 24);
        assert_eq!(priv_key(&params(PrivProtocol::Aes256), engine).len(), 32);
        assert_eq!(priv_key(&params(PrivProtocol::Aes192C), engine).len(), 24);
        assert_eq!(priv_key(&params(PrivProtocol::Aes256C), engine).len(), 32);
        assert_eq!(priv_key(&params(PrivProtocol::Des), engine).len(), 16);
        // Blumenthal vs Reeder extend differently for a 16-byte base key.
        assert_ne!(
            priv_key(&params(PrivProtocol::Aes192), engine),
            priv_key(&params(PrivProtocol::Aes192C), engine)
        );
    }

    #[test]
    fn aes_priv_roundtrip_with_fixed_key() {
        let key = [7u8; 16];
        let scoped = b"\x30\x1e\x04\x00\x04\x00\xa0\x18\x02\x04\x00\x00\x00\x2a".to_vec();
        let salt = [1u8; 8];
        let ct_wrap = aes_priv(&key, 3, 100, salt, &scoped, true).unwrap();
        assert_eq!(ct_wrap[0], 0x04);
        let mut r = BerReader { buf: ct_wrap.as_slice(), pos: 0 };
        let (t, v) = r.tlv().unwrap();
        assert_eq!(t, 0x04);
        let pt = aes_priv(&key, 3, 100, salt, v, false).unwrap();
        assert_eq!(pt, scoped);
        // wrong boots ⇒ different IV ⇒ garbage
        let wrong = aes_priv(&key, 4, 100, salt, v, false).unwrap();
        assert_ne!(wrong, scoped);
    }

    #[test]
    fn des_priv_roundtrip_and_zero_padding() {
        let mut key = vec![9u8; 16];
        key[15] = 0x77;
        let scoped = b"\x30\x0c\x04\x00\x04\x00\xa0\x06\x02\x01\x05".to_vec();
        assert_eq!(scoped.len() % 8, 3);
        let ct_wrap = des_priv(&key, 5, 77, &scoped, true).unwrap();
        let mut r = BerReader { buf: ct_wrap.as_slice(), pos: 0 };
        let (t, v) = r.tlv().unwrap();
        assert_eq!(t, 0x04);
        assert_eq!(v.len() % 8, 0);
        let pt = des_priv(&key, 5, 77, v, false).unwrap();
        assert_eq!(&pt[..scoped.len()], scoped);
        assert!(pt[scoped.len()..].iter().all(|b| *b == 0), "zero padding");
        // aligned plaintext gets a FULL pad block (gosnmp behavior)
        let aligned = vec![0x30u8, 6, 1, 2, 3, 4, 5, 6]; // 8 bytes: block-aligned
        let wrap = des_priv(&key, 5, 78, &aligned, true).unwrap();
        let mut r = BerReader { buf: wrap.as_slice(), pos: 0 };
        let (_, v) = r.tlv().unwrap();
        assert_eq!(v.len(), aligned.len() + 8);
    }

    #[test]
    fn session_builds_and_verifies_authenticated_message() {
        let cred = cred("authNoPriv", "SHA", "");
        let params = V3Params::from_credential(&cred).unwrap();
        let mut session = V3Session::new(params, b"\x80\x00\x00\x00\x01".to_vec(), 2, 500);
        let pkt = session.build_get(&["1.3.6.1.2.1.1.1.0"], false);
        assert_eq!(pkt[0], 0x30);
        let msg = session.decode(&pkt, session.req_id(), false).unwrap();
        assert_eq!(msg.pdu_tag, 0xA0);
        assert_eq!(msg.user, "admin");
        assert_eq!(msg.engine_id, b"\x80\x00\x00\x00\x01");
        // tampering with the packet body must fail the MAC
        let mut tampered = pkt.clone();
        let idx = tampered.len() - 3;
        tampered[idx] ^= 0xFF;
        assert_eq!(session.decode(&tampered, session.req_id(), false).unwrap_err(), V3Error::AuthFail);
        // a different key likewise
        let mut other = V3Session::new(V3Params::from_credential(&cred).unwrap(), b"\x80\x00\x00\x00\x01".to_vec(), 2, 500);
        other.auth_key = vec![1u8; 20];
        assert_eq!(other.decode(&pkt, session.req_id(), false).unwrap_err(), V3Error::AuthFail);
    }

    #[test]
    fn authpriv_roundtrip_full_message() {
        let cred = cred("authPriv", "SHA", "AES");
        let params = V3Params::from_credential(&cred).unwrap();
        let mut session = V3Session::new(params, b"\x80\x00\x00\x00\x02".to_vec(), 7, 900);
        let pkt = session.build_get(&["1.3.6.1.2.1.1.5.0"], false);
        let mut msg = session.decode(&pkt, session.req_id(), false).unwrap();
        assert!(msg.varbind_names[0].starts_with(ENCRYPTED_MARKER));
        let ct = hex_to_bytes(msg.varbind_names[0].strip_prefix(ENCRYPTED_MARKER).unwrap()).unwrap();
        let pt = decrypt_scoped_pdu(&session, &msg, &ct).unwrap();
        msg.varbind_names.clear();
        msg.varbinds.clear();
        parse_scoped_pdu(&pt, &mut msg).unwrap();
        assert_eq!(msg.pdu_tag, 0xA0);
        assert_eq!(msg.varbind_names, vec!["1.3.6.1.2.1.1.5.0".to_string()]);
        assert_eq!(msg.req_id, session.req_id() as i64);
    }

    #[test]
    fn minimal_uint_shape() {
        assert_eq!(minimal_uint(0), vec![0]);
        // padded: bare FF FF is the signed INTEGER -1 (net-snmp drops the msg)
        assert_eq!(minimal_uint(65535), vec![0x00, 0xFF, 0xFF]);
        assert_eq!(minimal_uint(2), vec![2]);
    }

    // ---------- mini agent (agent side of the codec) ----------

    /// Report PDU (usmStatsUnknownEngineIDs.0 = counter) — the discovery
    /// reply every SNMPv3 agent sends to a blank engine request.
    fn build_report(s: &mut V3Session, req_id: i32) -> Vec<u8> {
        let mut vb = encode_oid("1.3.6.1.6.3.15.1.1.4.0");
        ber_tlv(0x41, &[0], &mut vb); // Counter32 usmStatsUnknownEngineIDs.0
        let mut vbl = Vec::new();
        ber_tlv(0x30, &vb, &mut vbl);
        let mut vbl_seq = Vec::new();
        ber_tlv(0x30, &vbl, &mut vbl_seq);
        let mut pdu_body = Vec::new();
        ber_tlv(0x02, &minimal_uint(req_id as u64), &mut pdu_body);
        ber_tlv(0x02, &[0], &mut pdu_body);
        ber_tlv(0x02, &[0], &mut pdu_body);
        pdu_body.extend_from_slice(&vbl_seq);
        s.encode_message(0xA8, &pdu_body, MSG_FLAG_REPORTABLE, false)
    }

    /// GetResponse echoing test values for the requested OIDs (sysDescr /
    /// sysName get content, everything else empty strings).
    fn build_response(s: &mut V3Session, req_id: i32, oids: &[String]) -> Vec<u8> {
        let mut vbl = Vec::new();
        for (i, oid) in oids.iter().enumerate() {
            let mut vb = encode_oid(oid);
            let val: &[u8] = if i == 0 {
                b"Linux mini-agent 6.1"
            } else if i == 4 {
                b"minihost"
            } else {
                b""
            };
            ber_tlv(0x04, val, &mut vb);
            ber_tlv(0x30, &vb, &mut vbl);
        }
        let mut vbl_seq = Vec::new();
        ber_tlv(0x30, &vbl, &mut vbl_seq);
        let mut pdu_body = Vec::new();
        ber_tlv(0x02, &minimal_uint(req_id as u64), &mut pdu_body);
        ber_tlv(0x02, &[0], &mut pdu_body);
        ber_tlv(0x02, &[0], &mut pdu_body);
        pdu_body.extend_from_slice(&vbl_seq);
        let flags = s.flags();
        s.encode_message(0xA2, &pdu_body, flags, false)
    }

    fn run_mini_agent(tx: std::sync::mpsc::Sender<std::net::SocketAddr>, agent_params: V3Params, engine_id: Vec<u8>, oids: usize) {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        tx.send(addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        for _ in 0..6 {
            let mut buf = [0u8; 8192];
            let (n, peer) = match sock.recv_from(&mut buf) {
                Ok(x) => x,
                Err(_) => return,
            };
            let req = decode_v3_message(&buf[..n]).unwrap();
            if req.engine_id.is_empty() {
                // discovery
                let mut s = V3Session::new(blank_params(), engine_id.clone(), 3, 1234);
                let report = build_report(&mut s, req.req_id as i32);
                sock.send_to(&report, peer).unwrap();
                continue;
            }
            // authenticated/encrypted GET: verify, decrypt, respond
            let mut agent = V3Session::new(agent_params.clone(), engine_id.clone(), 3, 1234);
            let mut msg = match agent.decode(&buf[..n], 0, false) {
                Ok(m) => m,
                Err(_) => return, // MAC failure: drop, client times out
            };
            if let Some(marker) = msg.varbind_names.first().cloned() {
                if let Some(ct_hex) = marker.strip_prefix(ENCRYPTED_MARKER) {
                    let ct = hex_to_bytes(ct_hex).unwrap();
                    let pt = decrypt_scoped_pdu(&agent, &msg, &ct).unwrap();
                    msg.varbind_names.clear();
                    msg.varbinds.clear();
                    parse_scoped_pdu(&pt, &mut msg).unwrap();
                }
            }
            assert_eq!(msg.varbind_names.len(), oids);
            let resp = build_response(&mut agent, msg.req_id as i32, &msg.varbind_names.clone());
            sock.send_to(&resp, peer).unwrap();
            return; // one exchange per thread
        }
    }

    #[tokio::test]
    async fn end_to_end_v3_get_authpriv_aes() {
        use super::super::snmp::SYS_OIDS;
        let (tx, rx) = std::sync::mpsc::channel();
        let params = V3Params::from_credential(&cred("authPriv", "SHA", "AES")).unwrap();
        let agent = std::thread::spawn(move || {
            run_mini_agent(tx, params, b"\x80\x00\x9b\x99\x99".to_vec(), SYS_OIDS.len())
        });
        let addr = rx.recv().unwrap();
        let vars = v3_get(addr, &cred("authPriv", "SHA", "AES"), Duration::from_secs(2), &SYS_OIDS)
            .await
            .unwrap();
        assert_eq!(vars.len(), SYS_OIDS.len());
        assert_eq!(vars[0].as_deref(), Some("Linux mini-agent 6.1"));
        assert_eq!(vars[4].as_deref(), Some("minihost"));
        agent.join().unwrap();
    }

    #[tokio::test]
    async fn end_to_end_v3_get_authpriv_des_sha256() {
        use super::super::snmp::SYS_OIDS;
        let (tx, rx) = std::sync::mpsc::channel();
        let params = V3Params::from_credential(&cred("authPriv", "SHA256", "DES")).unwrap();
        let agent = std::thread::spawn(move || {
            run_mini_agent(tx, params, b"\x80\x00\x9b\x99\x99".to_vec(), SYS_OIDS.len())
        });
        let addr = rx.recv().unwrap();
        let vars = v3_get(addr, &cred("authPriv", "SHA256", "DES"), Duration::from_secs(2), &SYS_OIDS)
            .await
            .unwrap();
        assert_eq!(vars.len(), SYS_OIDS.len());
        agent.join().unwrap();
    }

    #[tokio::test]
    async fn end_to_end_v3_rejects_wrong_passphrase() {
        use super::super::snmp::SYS_OIDS;
        let (tx, rx) = std::sync::mpsc::channel();
        let params = V3Params::from_credential(&cred("authNoPriv", "SHA", "")).unwrap();
        let agent = std::thread::spawn(move || {
            run_mini_agent(tx, params, b"\x80\x00\x9b\x99\x99".to_vec(), SYS_OIDS.len())
        });
        let addr = rx.recv().unwrap();
        let mut wrong = cred("authNoPriv", "SHA", "");
        wrong.auth_passphrase = "otherpass".into();
        let err = v3_get(addr, &wrong, Duration::from_secs(2), &SYS_OIDS).await.unwrap_err();
        // the agent drops a bad-MAC request; the client sees a timeout
        assert_eq!(err, V3Error::Timeout);
        agent.join().unwrap();
    }
}
