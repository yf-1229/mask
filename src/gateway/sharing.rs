//! Encrypted mapping-table handoff between teammates (封筒 scheme).
//!
//! The mapping table is the re-identification key, so it only ever leaves a
//! process as ciphertext. The receiving gateway completes the whole process:
//! unseal with the shared passphrase, merge into its session, done.
//!
//! Envelope format (v1):
//! ```json
//! {"v": 1,
//!  "exp": 1700000000,
//!  "kdf": {"name": "argon2id", "salt": "<b64>", "opslimit": 3, "memlimit": 268435456},
//!  "boxed": "<b64 of nonce || XSalsa20-Poly1305 tag || ciphertext>"}
//! ```
//!
//! - key derivation: argon2id from a team passphrase (libsodium parameters)
//! - encryption: XSalsa20-Poly1305 (authenticated) — a wrong passphrase or a
//!   tampered envelope fails authentication
//! - the envelope carries its own KDF parameters, so future releases can raise
//!   the cost without invalidating old files
//!
//! The wire format matches PyNaCl's `SecretBox` (nonce || MAC || ciphertext)
//! and libsodium's argon2id KDF, so envelopes are portable between
//! implementations.
//!
//! Two ways an envelope becomes permanently undecryptable:
//! - 時間切れ: the authoritative expiry is sealed inside the authenticated
//!   payload (the clear copy is only a fast-fail convenience). After it passes,
//!   unseal returns `Expired` — fail-closed, so envelopes without an expiry are
//!   refused too.
//! - 認証失敗: the gateway counts failed passphrase attempts per envelope
//!   (keyed by `envelope_fingerprint`) and locks an envelope for good after the
//!   configured limit. On top of that the gateway marks an envelope consumed
//!   after a successful import (single use). These bound online guessing
//!   through the gateway; offline guessing against a copied envelope is
//!   mitigated by the argon2id cost, the passphrase strength, and the short
//!   expiry window.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use xsalsa20poly1305::aead::{AeadInPlace, KeyInit};
use xsalsa20poly1305::{Nonce, Tag, XSalsa20Poly1305};

pub const ENVELOPE_VERSION: u32 = 1;
pub const KDF_SALT_BYTES: usize = 16;
pub const NONCE_BYTES: usize = 24;
pub const TAG_BYTES: usize = 16;
pub const KEY_BYTES: usize = 32;

/// Default envelope lifetime: 1 h. A handoff is a minutes-scale operation; if
/// it expires, export again.
pub const DEFAULT_TTL_SECONDS: i64 = 3600;

/// argon2id cost. Moderate-grade (~256 MiB, ~0.3 s per seal/unseal). Handoffs
/// are rare and re-export is cheap, so we spend real cost here: this is the
/// only thing slowing offline passphrase guessing against a copied envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub opslimit: u32,
    /// Memory in bytes (libsodium `memlimit`).
    pub memlimit: u64,
}

impl KdfParams {
    pub const MODERATE: KdfParams = KdfParams {
        opslimit: 3,
        memlimit: 256 * 1024 * 1024,
    };

    /// Deliberately cheap parameters for tests. Never use in production.
    pub const TESTING: KdfParams = KdfParams {
        opslimit: 1,
        memlimit: 16 * 1024 * 1024,
    };
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams::MODERATE
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfDescriptor {
    pub name: String,
    pub salt: String,
    pub opslimit: u32,
    pub memlimit: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope {
    pub v: u32,
    pub exp: i64,
    pub kdf: KdfDescriptor,
    pub boxed: String,
}

#[derive(Debug)]
pub enum UnsealError {
    /// The envelope's sealed expiry has passed; decryption is refused.
    Expired,
    /// Wrong passphrase or tampered ciphertext.
    Crypto,
    /// Malformed envelope.
    Malformed(String),
}

impl fmt::Display for UnsealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnsealError::Expired => write!(f, "envelope expired"),
            UnsealError::Crypto => write!(f, "wrong passphrase or corrupted envelope"),
            UnsealError::Malformed(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for UnsealError {}

#[derive(Debug)]
pub enum SealError {
    EmptyPassphrase,
    InvalidTtl,
    Crypto(String),
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SealError::EmptyPassphrase => write!(f, "passphrase must not be empty"),
            SealError::InvalidTtl => write!(f, "ttl_seconds must be a positive integer"),
            SealError::Crypto(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for SealError {}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn random_bytes(n: usize) -> Result<Vec<u8>, SealError> {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).map_err(|e| SealError::Crypto(e.to_string()))?;
    Ok(buf)
}

fn derive_key(
    passphrase: &str,
    salt: &[u8],
    opslimit: u32,
    memlimit: u64,
) -> Result<[u8; KEY_BYTES], UnsealError> {
    let m_cost = memlimit / 1024;
    if !(8..=u32::MAX as u64).contains(&m_cost) {
        return Err(UnsealError::Malformed("unsupported kdf cost".into()));
    }
    let params = Params::new(m_cost as u32, opslimit, 1, Some(KEY_BYTES))
        .map_err(|e| UnsealError::Malformed(format!("unsupported kdf parameters: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_BYTES];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| UnsealError::Malformed(format!("key derivation failed: {e}")))?;
    Ok(key)
}

/// Encrypt a JSON-serializable payload under a passphrase with default cost.
pub fn seal(payload: &Value, passphrase: &str, ttl_seconds: i64) -> Result<Envelope, SealError> {
    seal_with(payload, passphrase, ttl_seconds, KdfParams::MODERATE)
}

/// Encrypt a JSON payload under a passphrase with explicit KDF cost.
///
/// The expiry (`exp`, unix time) is sealed into the authenticated payload; a
/// clear copy on the envelope lets recipients see when it dies.
pub fn seal_with(
    payload: &Value,
    passphrase: &str,
    ttl_seconds: i64,
    params: KdfParams,
) -> Result<Envelope, SealError> {
    if passphrase.is_empty() {
        return Err(SealError::EmptyPassphrase);
    }
    if ttl_seconds <= 0 {
        return Err(SealError::InvalidTtl);
    }
    let exp = now_unix() + ttl_seconds;
    let salt = random_bytes(KDF_SALT_BYTES)?;
    let key = derive_key(passphrase, &salt, params.opslimit, params.memlimit)
        .map_err(|e| SealError::Crypto(e.to_string()))?;

    let mut object: Map<String, Value> = match payload {
        Value::Object(map) => map.clone(),
        other => {
            let mut map = Map::new();
            if !other.is_null() {
                map.insert("payload".to_string(), other.clone());
            }
            map
        }
    };
    object.insert("exp".to_string(), Value::from(exp));
    let plaintext =
        serde_json::to_vec(&Value::Object(object)).map_err(|e| SealError::Crypto(e.to_string()))?;

    let cipher =
        XSalsa20Poly1305::new_from_slice(&key).map_err(|e| SealError::Crypto(e.to_string()))?;
    let nonce_bytes = random_bytes(NONCE_BYTES)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut buffer = plaintext;
    let tag = cipher
        .encrypt_in_place_detached(nonce, b"", &mut buffer)
        .map_err(|e| SealError::Crypto(e.to_string()))?;

    let mut boxed = Vec::with_capacity(NONCE_BYTES + TAG_BYTES + buffer.len());
    boxed.extend_from_slice(&nonce_bytes);
    boxed.extend_from_slice(tag.as_slice());
    boxed.extend_from_slice(&buffer);

    Ok(Envelope {
        v: ENVELOPE_VERSION,
        exp,
        kdf: KdfDescriptor {
            name: "argon2id".to_string(),
            salt: B64.encode(&salt),
            opslimit: params.opslimit,
            memlimit: params.memlimit,
        },
        boxed: B64.encode(&boxed),
    })
}

/// Decrypt an envelope back to its payload.
///
/// Returns `Expired` once the sealed expiry has passed (checked against the
/// clear copy first for a fast fail, then against the authoritative copy inside
/// the ciphertext). Returns `Crypto` on a wrong passphrase or tampered
/// ciphertext, `Malformed` on a malformed envelope.
pub fn unseal(envelope: &Envelope, passphrase: &str) -> Result<Value, UnsealError> {
    if envelope.v != ENVELOPE_VERSION {
        return Err(UnsealError::Malformed(
            "unsupported envelope version".into(),
        ));
    }
    if now_unix() > envelope.exp {
        return Err(UnsealError::Expired);
    }
    if envelope.kdf.name != "argon2id" {
        return Err(UnsealError::Malformed("unsupported kdf".into()));
    }
    let salt = B64
        .decode(&envelope.kdf.salt)
        .map_err(|e| UnsealError::Malformed(format!("bad salt: {e}")))?;
    let raw = B64
        .decode(&envelope.boxed)
        .map_err(|e| UnsealError::Malformed(format!("bad ciphertext: {e}")))?;
    if raw.len() < NONCE_BYTES + TAG_BYTES {
        return Err(UnsealError::Malformed("ciphertext too short".into()));
    }
    let key = derive_key(
        passphrase,
        &salt,
        envelope.kdf.opslimit,
        envelope.kdf.memlimit,
    )?;
    let cipher = XSalsa20Poly1305::new_from_slice(&key).expect("32-byte key");
    let nonce = Nonce::from_slice(&raw[..NONCE_BYTES]);
    let tag = Tag::from_slice(&raw[NONCE_BYTES..NONCE_BYTES + TAG_BYTES]);
    let mut buffer = raw[NONCE_BYTES + TAG_BYTES..].to_vec();
    cipher
        .decrypt_in_place_detached(nonce, b"", &mut buffer, tag)
        .map_err(|_| UnsealError::Crypto)?;
    let payload: Value = serde_json::from_slice(&buffer)
        .map_err(|e| UnsealError::Malformed(format!("bad payload: {e}")))?;
    let exp = payload.get("exp").and_then(Value::as_i64);
    match exp {
        // authoritative, tamper-evident check; missing exp fails closed
        Some(exp) if now_unix() <= exp => Ok(payload),
        _ => Err(UnsealError::Expired),
    }
}

/// Stable identity of a decryptable envelope (salt + ciphertext).
///
/// Used to key the failed-attempt lockout: a copied envelope has the same
/// fingerprint, and a mutated one can never decrypt, so guessing through the
/// gateway cannot be reset by re-copying or tweaking bytes.
pub fn envelope_fingerprint(envelope: &Envelope) -> String {
    let material = format!("{}|{}", envelope.kdf.salt, envelope.boxed);
    let digest = Sha256::digest(material.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}
