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
//!
//! Distribution: the built-in list is only the starting point. Agents also fetch a list signed by
//! the same offline root key that signs `custom.txt` (`technician-keys-url`, comma-separated
//! HTTPS URLs). A fetched list replaces the built-in one when its version is higher than both the
//! built-in `technician-keys-version` and any list seen before, so adding or revoking a technician
//! device needs no reinstall. Whoever hosts the file can withhold or delay it, not forge it or roll
//! it back.

use hbb_common::{
    config::{Config, HARD_SETTINGS},
    log,
    sodiumoxide::{crypto::sign, randombytes::randombytes},
};
use std::{
    io::Read,
    sync::{mpsc, Mutex, Once, RwLock},
    time::{Duration, Instant},
};

const DOMAIN: &[u8] = b"samtech-technician-auth-v1";
const OPTION_TECHNICIAN_KEYS: &str = "technician-keys";
const OPTION_TECHNICIAN_KEYS_VERSION: &str = "technician-keys-version";
const OPTION_TECHNICIAN_KEYS_URL: &str = "technician-keys-url";
pub const NONCE_LEN: usize = 32;

/// Public half of the SamTech root key. Verifies the built-in config and the technician list.
pub const ROOT_KEY: &str = "tmbftO12VsS8r4V04Pn/hX3KGsj9IzwGqP8Mc4mg0Sc=";
const LIST_TYPE: &str = "samtech-technician-keys";
const LIST_CACHE_FILE: &str = "samtech-technician-keys.txt";
const LIST_MAX_BYTES: u64 = 64 * 1024;
const REFRESH_EVERY: Duration = Duration::from_secs(60 * 60);
const REFRESH_MIN_GAP: Duration = Duration::from_secs(30);

lazy_static::lazy_static! {
    /// Newest valid signed list seen by this process: (version, keys).
    static ref FETCHED: RwLock<Option<(u64, Vec<Vec<u8>>)>> = RwLock::new(None);
    static ref REFRESH_TX: Mutex<Option<mpsc::Sender<()>>> = Mutex::new(None);
    static ref LAST_REQUEST: Mutex<Option<Instant>> = Mutex::new(None);
}

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

fn hard_option(key: &str) -> String {
    HARD_SETTINGS.read().unwrap().get(key).cloned().unwrap_or_default()
}

fn builtin_version() -> u64 {
    hard_option(OPTION_TECHNICIAN_KEYS_VERSION).trim().parse().unwrap_or(0)
}

fn parse_keys<'a>(keys: impl Iterator<Item = &'a str>) -> Vec<Vec<u8>> {
    keys.filter_map(|k| crate::decode64(k.trim()).ok())
        .filter(|k| k.len() == sign::PUBLICKEYBYTES)
        .collect()
}

fn allowed_keys() -> Vec<Vec<u8>> {
    if let Some((version, keys)) = FETCHED.read().unwrap().as_ref() {
        if *version > builtin_version() {
            return keys.clone();
        }
    }
    parse_keys(technician_keys_option().split(','))
}

/// Checks a signed list (`base64(signature || json)`, signed by the root key) and returns
/// (version, keys). The `type` field keeps a signed `custom.txt` from passing as a list.
fn verify_list(doc: &str) -> Option<(u64, Vec<Vec<u8>>)> {
    let data = crate::decode64(doc.trim()).ok()?;
    let pk = crate::common::get_rs_pk(ROOT_KEY)?;
    let json = sign::verify(&data, &pk).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&json).ok()?;
    if v.get("type")?.as_str()? != LIST_TYPE {
        return None;
    }
    let version = v.get("version")?.as_u64()?;
    let keys = parse_keys(v.get("keys")?.as_array()?.iter().filter_map(|k| k.as_str()));
    Some((version, keys))
}

/// Takes a list if it is valid and newer than everything seen so far; `save` keeps it on disk
/// so a restart without network still uses it.
fn accept_list(doc: &str, save: bool) -> bool {
    let Some((version, keys)) = verify_list(doc) else {
        log::warn!("samtech: technician list rejected (bad signature or format)");
        return false;
    };
    let mut fetched = FETCHED.write().unwrap();
    let current = fetched.as_ref().map_or(0, |(v, _)| *v).max(builtin_version());
    if version <= current {
        return false;
    }
    log::info!("samtech: technician list version {} with {} keys in use", version, keys.len());
    *fetched = Some((version, keys));
    drop(fetched);
    if save {
        if let Err(err) = std::fs::write(Config::path(LIST_CACHE_FILE), doc.trim()) {
            log::warn!("samtech: could not save technician list: {}", err);
        }
    }
    true
}

fn fetch_list(url: &str) -> Option<String> {
    let client = crate::hbbs_http::create_http_client_with_url_strict(url).ok()?;
    let resp = client.get(url).timeout(Duration::from_secs(20)).send().ok()?;
    if !resp.status().is_success() {
        log::warn!("samtech: technician list {} returned {}", url, resp.status());
        return None;
    }
    let mut body = String::new();
    resp.take(LIST_MAX_BYTES).read_to_string(&mut body).ok()?;
    Some(body)
}

fn refresh_once() {
    for url in hard_option(OPTION_TECHNICIAN_KEYS_URL).split(',').map(str::trim) {
        if url.is_empty() {
            continue;
        }
        if let Some(doc) = fetch_list(url) {
            if verify_list(&doc).is_some() {
                accept_list(&doc, true);
                return;
            }
            log::warn!("samtech: technician list from {} is not validly signed", url);
        }
    }
}

/// Starts the background refresh once per process (no-op without an allowlist). Called when the
/// host server starts and again lazily on the first incoming connection.
pub fn start_list_refresh() {
    static START: Once = Once::new();
    if !enforced() {
        return;
    }
    START.call_once(|| {
        if let Ok(doc) = std::fs::read_to_string(Config::path(LIST_CACHE_FILE)) {
            accept_list(&doc, false);
        }
        if hard_option(OPTION_TECHNICIAN_KEYS_URL).trim().is_empty() {
            return;
        }
        let (tx, rx) = mpsc::channel::<()>();
        *REFRESH_TX.lock().unwrap() = Some(tx);
        std::thread::spawn(move || loop {
            refresh_once();
            match rx.recv_timeout(REFRESH_EVERY) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        });
    });
}

/// After a refusal, fetch again soon: a technician device added a minute ago then gets in on
/// its next attempt instead of within the hour. Rate-limited.
fn request_refresh() {
    let mut last = LAST_REQUEST.lock().unwrap();
    if last.map_or(false, |t| t.elapsed() < REFRESH_MIN_GAP) {
        return;
    }
    *last = Some(Instant::now());
    if let Some(tx) = REFRESH_TX.lock().unwrap().as_ref() {
        tx.send(()).ok();
    }
}

/// True when the signed config lets a verified technician device in without a password or an
/// accept click (`technician-unattended = "Y"`).
pub fn unattended_allowed() -> bool {
    // Owner's policy: installing the program is the consent (the install page says so) and
    // uninstalling it is how a device owner withdraws it. There is no per-device switch.
    HARD_SETTINGS
        .read()
        .unwrap()
        .get("technician-unattended")
        .map_or(false, |v| v == "Y")
}

pub fn new_nonce() -> Vec<u8> {
    start_list_refresh();
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
    // Public key only: lets the owner see which device key a session actually presents.
    log::info!("samtech: presenting technician key {}", crate::encode64(&pk));
    let mut out = pk;
    out.extend_from_slice(&sign::sign(&transcript(controlled_pk, nonce, challenge), &sk));
    out
}

/// Controlled side. `nonce` and `challenge` are the ones this connection sent in its `Hash`.
pub fn verify_auth(auth: &[u8], nonce: &[u8], challenge: &str) -> bool {
    if !enforced() {
        return false;
    }
    if auth.len() <= sign::PUBLICKEYBYTES || nonce.len() != NONCE_LEN {
        log::warn!("samtech: login carries no technician proof ({} bytes)", auth.len());
        return false;
    }
    let (their_pk, signed) = auth.split_at(sign::PUBLICKEYBYTES);
    if !allowed_keys().iter().any(|k| k.as_slice() == their_pk) {
        log::warn!(
            "samtech: technician key {} is not on the allowlist",
            crate::encode64(their_pk)
        );
        request_refresh();
        return false;
    }
    let Some(their_pk) = sign::PublicKey::from_slice(their_pk) else {
        return false;
    };
    let Ok(msg) = sign::verify(signed, &their_pk) else {
        log::warn!("samtech: technician proof has a bad signature");
        return false;
    };
    let (_, my_pk) = Config::get_key_pair();
    let ok = msg == transcript(&my_pk, nonce, challenge);
    if !ok {
        // The controller signed for a different device key or session: stale proof, or the
        // rendezvous server presented another key for this device.
        log::warn!("samtech: technician proof is not for this device and session");
    }
    ok
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
