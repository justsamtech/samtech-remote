//! SamTech: technician device authorization.
//!
//! Upstream authorizes a controller by password or an accept click only; the controller proves
//! no identity. Here the controlled side additionally requires that the controller's device key
//! is on an allowlist shipped in the signed built-in config (`technician-keys`, comma-separated
//! base64 Ed25519 public keys). With an empty or absent list nothing changes.
//!
//! Protocol: the controlled side adds a random nonce to its `Hash` message. The controller, only
//! when the channel is end-to-end secured against the verified key of the controlled device,
//! signs (domain, that device's public key, nonce, challenge) with its own device key and sends
//! `public_key || signed_transcript` in `LoginRequest.samtech_auth`. Binding the controlled
//! device's key means a signature obtained by one device is useless against another, including
//! when the rendezvous server lies about a device's key.

use hbb_common::{
    config::{Config, HARD_SETTINGS},
    log,
    sodiumoxide::{crypto::sign, randombytes::randombytes},
};

const DOMAIN: &[u8] = b"samtech-technician-auth-v1";
const OPTION_TECHNICIAN_KEYS: &str = "technician-keys";
pub const NONCE_LEN: usize = 32;

fn technician_keys_option() -> String {
    HARD_SETTINGS
        .read()
        .unwrap()
        .get(OPTION_TECHNICIAN_KEYS)
        .cloned()
        .unwrap_or_default()
}

/// True when this build carries a technician allowlist. Fails closed: a present but unusable
/// list still enforces, and then rejects everyone.
pub fn enforced() -> bool {
    !technician_keys_option().trim().is_empty()
}

fn allowed_keys() -> Vec<Vec<u8>> {
    technician_keys_option()
        .split(',')
        .filter_map(|k| crate::decode64(k.trim()).ok())
        .filter(|k| k.len() == sign::PUBLICKEYBYTES)
        .collect()
}

/// Diagnostics build only: with SAMTECH_TRACE set, print a marker to stderr (unbuffered, so it
/// survives an abort that would lose buffered log lines).
pub fn trace(msg: &str) {
    if std::env::var_os("SAMTECH_TRACE").is_some() {
        eprintln!("[samtech-trace] {}", msg);
    }
}

pub fn cfg_mode() -> String {
    std::env::var("SAMTECH_CFG_MODE").unwrap_or_default()
}

pub fn new_nonce() -> Vec<u8> {
    randombytes(NONCE_LEN)
}

fn transcript(controlled_pk: &[u8], nonce: &[u8], challenge: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(DOMAIN.len() + controlled_pk.len() + nonce.len() + challenge.len() + 4);
    v.extend_from_slice(DOMAIN);
    for part in [controlled_pk, nonce, challenge.as_bytes()] {
        v.push(part.len() as u8);
        v.extend_from_slice(part);
    }
    v
}

/// Controller side. Returns an empty vector when there is nothing safe to sign.
pub fn sign_auth(controlled_pk: &[u8], nonce: &[u8], challenge: &str) -> Vec<u8> {
    if controlled_pk.len() != sign::PUBLICKEYBYTES || nonce.len() != NONCE_LEN || challenge.len() > 255 {
        return Vec::new();
    }
    let (sk, pk) = Config::get_key_pair();
    let Some(sk) = sign::SecretKey::from_slice(&sk) else {
        return Vec::new();
    };
    if pk.len() != sign::PUBLICKEYBYTES {
        return Vec::new();
    }
    let mut out = pk;
    out.extend_from_slice(&sign::sign(&transcript(controlled_pk, nonce, challenge), &sk));
    out
}

/// Controlled side. `nonce` and `challenge` are the ones this connection sent in its `Hash`.
pub fn verify_auth(auth: &[u8], nonce: &[u8], challenge: &str) -> bool {
    if auth.len() <= sign::PUBLICKEYBYTES || nonce.len() != NONCE_LEN {
        return false;
    }
    let (their_pk, signed) = auth.split_at(sign::PUBLICKEYBYTES);
    if !allowed_keys().iter().any(|k| k.as_slice() == their_pk) {
        return false;
    }
    let Some(their_pk) = sign::PublicKey::from_slice(their_pk) else {
        return false;
    };
    let Ok(msg) = sign::verify(signed, &their_pk) else {
        return false;
    };
    let (_, my_pk) = Config::get_key_pair();
    msg == transcript(&my_pk, nonce, challenge)
}

/// `--samtech-technician-key`: print this device's public key and save it next to the user's
/// home directory, so it can be added to the allowlist.
pub fn export_technician_key() {
    let (_, pk) = Config::get_key_pair();
    let line = crate::encode64(&pk);
    println!("{}", line);
    let path = Config::get_home().join("samtech-technician-key.txt");
    if let Err(err) = std::fs::write(&path, format!("{}\n", line)) {
        log::error!("samtech: failed to write {:?}: {}", path, err);
    }
}
