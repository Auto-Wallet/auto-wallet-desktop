//! Encrypted HD key vault (pure-Rust, no C toolchain — keeps the installer small).
//!
//! This module is the *cryptographic core* only: BIP-39 mnemonic ↔ BIP-44 account
//! derivation, and password-based sealing/opening of the on-disk keystore. It holds
//! NO global state and does NO file I/O — that lives in `lib.rs` (the in-memory
//! unlocked vault + Tauri commands), so this layer stays pure and unit-testable.
//!
//! Security model (see CLAUDE.md): the mnemonic is the root secret. It is encrypted
//! at rest with AES-256-GCM under a key stretched from the user's password via
//! Argon2id. The plaintext keystore stores only public data (addresses + derivation
//! indices) so the UI can show the account before unlock. Private keys are derived
//! in Rust and never leave the backend — never into any webview.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bip39::Mnemonic;
use hmac::{Hmac, Mac};
use k256::ecdsa::SigningKey;
use k256::SecretKey;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use zeroize::Zeroizing;

type HmacSha512 = Hmac<Sha512>;

/// BIP-32 hardened-derivation offset (index | 0x8000_0000 means hardened).
const HARDENED: u32 = 0x8000_0000;

// Argon2id parameters. 64 MiB / 3 passes / 1 lane is comfortably above the OWASP
// minimum and still unlocks in a fraction of a second on a desktop. Stored in the
// keystore so a future tuning doesn't lock out existing vaults.
const ARGON_M_COST: u32 = 65_536; // KiB → 64 MiB
const ARGON_T_COST: u32 = 3;
const ARGON_P_COST: u32 = 1;

// ---------------------------------------------------------------------------
// BIP-39 / BIP-44 derivation
// ---------------------------------------------------------------------------

/// A fresh random wallet id (16 bytes hex) — used as the `wallets/<id>.json`
/// filename. Random, not derived, so it never leaks anything about the secret.
pub fn new_wallet_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Generate a fresh 12-word English BIP-39 mnemonic.
pub fn generate_mnemonic() -> Result<String, String> {
    let mut entropy = Zeroizing::new([0u8; 16]); // 128 bits → 12 words
    OsRng.fill_bytes(entropy.as_mut_slice());
    let m = Mnemonic::from_entropy(entropy.as_slice()).map_err(|e| e.to_string())?;
    Ok(m.to_string())
}

/// Validate a mnemonic phrase (English wordlist + checksum).
pub fn validate_mnemonic(phrase: &str) -> Result<(), String> {
    Mnemonic::parse_normalized(phrase)
        .map(|_| ())
        .map_err(|e| format!("invalid recovery phrase: {e}"))
}

/// Derive the Ethereum account at `m/44'/60'/0'/0/index` from `mnemonic`.
/// Returns the signing key and its lowercase 0x address.
pub fn derive_account(mnemonic: &str, index: u32) -> Result<(SigningKey, String), String> {
    let m = Mnemonic::parse_normalized(mnemonic)
        .map_err(|e| format!("invalid recovery phrase: {e}"))?;
    // BIP-39 seed (empty passphrase — the standard for EVM wallets).
    let seed = Zeroizing::new(m.to_seed_normalized(""));

    let path = [44 | HARDENED, 60 | HARDENED, 0 | HARDENED, 0, index];
    let (mut key, mut chain_code) = master_key(seed.as_slice())?;
    for &child in &path {
        let (k, c) = ckd_priv(&key, &chain_code, child)?;
        key = k;
        chain_code = c;
    }

    let sk = SigningKey::from_slice(&key).map_err(|e| e.to_string())?;
    let address = crate::address_from_verifying_key(sk.verifying_key());
    Ok((sk, address))
}

/// Parse a raw secp256k1 private key from `0x`-prefixed (or bare) 32-byte hex.
/// Used by the "import private key" onboarding path. Rejects wrong-length input
/// and out-of-range/zero scalars (fail loud — no silent fallback).
pub fn parse_private_key(input: &str) -> Result<SigningKey, String> {
    let body = input
        .trim()
        .strip_prefix("0x")
        .unwrap_or_else(|| input.trim());
    if body.len() != 64 {
        return Err("private key must be 32 bytes (64 hex characters)".to_string());
    }
    let bytes = Zeroizing::new(
        hex::decode(body).map_err(|e| format!("private key is not valid hex: {e}"))?,
    );
    SigningKey::from_slice(&bytes)
        .map_err(|_| "invalid private key (out of range or zero)".to_string())
}

/// BIP-32 master key: HMAC-SHA512("Bitcoin seed", seed) → (key, chain_code).
fn master_key(seed: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    let mut mac =
        <HmacSha512 as Mac>::new_from_slice(b"Bitcoin seed").map_err(|e| e.to_string())?;
    mac.update(seed);
    let i = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    let mut cc = [0u8; 32];
    key.copy_from_slice(&i[..32]);
    cc.copy_from_slice(&i[32..]);
    // Reject an out-of-range master key (astronomically unlikely).
    SecretKey::from_slice(&key).map_err(|_| "invalid master key".to_string())?;
    Ok((key, cc))
}

/// BIP-32 CKDpriv: derive a child private key + chain code.
fn ckd_priv(
    parent_key: &[u8; 32],
    parent_cc: &[u8; 32],
    index: u32,
) -> Result<([u8; 32], [u8; 32]), String> {
    let mut mac = <HmacSha512 as Mac>::new_from_slice(parent_cc).map_err(|e| e.to_string())?;
    if index >= HARDENED {
        // Hardened: 0x00 || ser256(k_par) || ser32(i)
        mac.update(&[0u8]);
        mac.update(parent_key);
    } else {
        // Normal: serP(point(k_par)) || ser32(i) — compressed parent pubkey.
        let sk = SigningKey::from_slice(parent_key).map_err(|e| e.to_string())?;
        let pubkey = sk.verifying_key().to_encoded_point(true);
        mac.update(pubkey.as_bytes());
    }
    mac.update(&index.to_be_bytes());
    let i = mac.finalize().into_bytes();
    let (il, ir) = i.split_at(32);

    // child = parse256(IL) + k_par (mod n); both must be valid non-zero scalars.
    let il_scalar = *SecretKey::from_slice(il)
        .map_err(|_| "invalid IL during derivation".to_string())?
        .to_nonzero_scalar();
    let par_scalar = *SecretKey::from_slice(parent_key)
        .map_err(|_| "invalid parent key during derivation".to_string())?
        .to_nonzero_scalar();
    let child_scalar = il_scalar + par_scalar;
    let child_bytes = child_scalar.to_bytes();
    // from_slice rejects a zero child key (would be off the curve subgroup).
    SecretKey::from_slice(child_bytes.as_ref())
        .map_err(|_| "derived an invalid child key".to_string())?;

    let mut key = [0u8; 32];
    let mut cc = [0u8; 32];
    key.copy_from_slice(child_bytes.as_ref());
    cc.copy_from_slice(ir);
    Ok((key, cc))
}

// ---------------------------------------------------------------------------
// Keystore (password-sealed mnemonic at rest)
// ---------------------------------------------------------------------------

/// Public metadata for one derived account (safe to store in plaintext).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountMeta {
    pub index: u32,
    pub address: String,
}

/// The on-disk keystore. Everything here is safe to write to a file: any secret
/// (mnemonic / private key) lives only inside `ciphertext`, which requires the
/// password. A `kind == "ledger"` keystore has NO secret — it records only the
/// device derivation `path` + the public address, so the crypto fields are absent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keystore {
    pub version: u32,
    /// Stable per-wallet id — the filename (`<id>.json`) in the `wallets/` dir.
    /// Empty in legacy single-vault keystores; assigned on migration.
    #[serde(default)]
    pub id: String,
    /// User-facing wallet name (e.g. "Wallet 1"). Empty in legacy keystores;
    /// defaulted on migration.
    #[serde(default)]
    pub label: String,
    /// Creation time (ms since epoch) — used only to order the wallet list
    /// stably. 0 for legacy/migrated keystores (sort first).
    #[serde(default)]
    pub created: u64,
    /// Secret kind: "hd" (BIP-39 mnemonic), "privkey" (a single raw key), or
    /// "ledger" (a hardware account — no stored secret).
    /// Defaults to "hd" so keystores written before this field stay readable.
    #[serde(default = "default_kind")]
    pub kind: String,
    /// Ledger derivation path — present only for `kind == "ledger"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default = "default_kdf")]
    pub kdf: String,
    #[serde(default)]
    pub m_cost: u32,
    #[serde(default)]
    pub t_cost: u32,
    #[serde(default)]
    pub p_cost: u32,
    // Crypto fields — present for "hd"/"privkey", absent for "ledger".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>, // base64
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cipher: Option<String>, // "aes-256-gcm"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>, // base64 (96-bit GCM nonce)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext: Option<String>, // base64 (secret sealed with AES-256-GCM)
    pub accounts: Vec<AccountMeta>,
}

fn default_kind() -> String {
    "hd".to_string()
}

fn default_kdf() -> String {
    "argon2id".to_string()
}

/// Build a Ledger keystore (no secret at rest — just the derivation path + the
/// public address metadata).
pub fn ledger_keystore(path: &str, accounts: Vec<AccountMeta>) -> Keystore {
    Keystore {
        version: 1,
        id: String::new(),
        label: String::new(),
        created: 0,
        kind: "ledger".to_string(),
        path: Some(path.to_string()),
        kdf: "none".to_string(),
        m_cost: 0,
        t_cost: 0,
        p_cost: 0,
        salt: None,
        cipher: None,
        nonce: None,
        ciphertext: None,
        accounts,
    }
}

/// Stretch a password into a 256-bit key-encryption key with Argon2id.
fn derive_kek(
    password: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(32)).map_err(|e| e.to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut kek = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, kek.as_mut_slice())
        .map_err(|e| e.to_string())?;
    Ok(kek)
}

/// Encrypt `secret` (a mnemonic when `kind == "hd"`, or a 0x-hex private key when
/// `kind == "privkey"`) under `password`, producing a keystore for the given accounts.
// `Nonce::from_slice` is aes-gcm 0.10's documented constructor; its deprecation
// leaks from generic-array 0.14 (pinned transitively by k256 0.13 — 1.x isn't an
// option), so suppress it locally rather than mask it across the module.
#[allow(deprecated)]
pub fn seal(
    password: &str,
    secret: &str,
    kind: &str,
    accounts: Vec<AccountMeta>,
) -> Result<Keystore, String> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    let kek = derive_kek(password, &salt, ARGON_M_COST, ARGON_T_COST, ARGON_P_COST)?;
    let cipher = Aes256Gcm::new_from_slice(kek.as_slice()).map_err(|e| e.to_string())?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), secret.as_bytes())
        .map_err(|e| format!("encryption failed: {e}"))?;

    Ok(Keystore {
        version: 1,
        id: String::new(),
        label: String::new(),
        created: 0,
        kind: kind.to_string(),
        path: None,
        kdf: "argon2id".to_string(),
        m_cost: ARGON_M_COST,
        t_cost: ARGON_T_COST,
        p_cost: ARGON_P_COST,
        salt: Some(B64.encode(salt)),
        cipher: Some("aes-256-gcm".to_string()),
        nonce: Some(B64.encode(nonce)),
        ciphertext: Some(B64.encode(ciphertext)),
        accounts,
    })
}

/// Decrypt the secret from a keystore. A wrong password fails the GCM tag check
/// and surfaces as a clear "incorrect password" (no silent fallback). Errors loudly
/// if called on a keystore with no encrypted secret (e.g. a Ledger keystore).
#[allow(deprecated)] // see `seal`: aes-gcm 0.10 Nonce::from_slice via generic-array 0.14
pub fn open(password: &str, ks: &Keystore) -> Result<Zeroizing<String>, String> {
    let no = |name: &str| format!("keystore has no {name} (not an encrypted vault)");
    let salt = B64
        .decode(ks.salt.as_ref().ok_or_else(|| no("salt"))?)
        .map_err(|e| e.to_string())?;
    let nonce = B64
        .decode(ks.nonce.as_ref().ok_or_else(|| no("nonce"))?)
        .map_err(|e| e.to_string())?;
    if nonce.len() != 12 {
        return Err("invalid keystore nonce length".into());
    }
    let ciphertext = B64
        .decode(ks.ciphertext.as_ref().ok_or_else(|| no("ciphertext"))?)
        .map_err(|e| e.to_string())?;

    let kek = derive_kek(password, &salt, ks.m_cost, ks.t_cost, ks.p_cost)?;
    let cipher = Aes256Gcm::new_from_slice(kek.as_slice()).map_err(|e| e.to_string())?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| "incorrect password".to_string())?;
    let phrase = String::from_utf8(plaintext).map_err(|e| e.to_string())?;
    Ok(Zeroizing::new(phrase))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Anvil/Hardhat's well-known dev mnemonic. Its m/44'/60'/0'/0/0 account is the
    // exact key/address hard-coded as DEV_PRIVKEY_HEX/SPIKE_ACCOUNT today, so it is a
    // strong external oracle for the whole BIP-39→44 pipeline. NOT a real secret.
    const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";

    #[test]
    fn malformed_nonce_returns_an_error_instead_of_panicking() {
        let mut wallet = seal("test-password", TEST_MNEMONIC, "hd", vec![]).unwrap();
        wallet.nonce = Some(B64.encode([0_u8; 11]));
        let result = std::panic::catch_unwind(|| open("test-password", &wallet));
        assert!(result.is_ok(), "corrupt wallet metadata must not poison vault locks");
        assert!(result.unwrap().is_err());
    }

    #[test]
    fn derive_matches_known_anvil_vectors() {
        // Account 0 must reproduce the publicly-known Anvil #0 key + address.
        let (k0, a0) = derive_account(TEST_MNEMONIC, 0).unwrap();
        assert_eq!(
            hex::encode(k0.to_bytes()),
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        );
        assert_eq!(a0, "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");

        // Account 1 must reproduce Anvil #1's address (exercises non-hardened index>0).
        let (_k1, a1) = derive_account(TEST_MNEMONIC, 1).unwrap();
        assert_eq!(a1, "0x70997970c51812dc3a010c7d01b50e0d17dc79c8");

        // Account 2 → Anvil #2.
        let (_k2, a2) = derive_account(TEST_MNEMONIC, 2).unwrap();
        assert_eq!(a2, "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc");
    }

    #[test]
    fn generated_mnemonic_is_valid_and_derivable() {
        let phrase = generate_mnemonic().unwrap();
        assert_eq!(phrase.split_whitespace().count(), 12);
        validate_mnemonic(&phrase).unwrap();
        // It must derive a syntactically valid address.
        let (_k, addr) = derive_account(&phrase, 0).unwrap();
        assert!(addr.starts_with("0x") && addr.len() == 42);
    }

    #[test]
    fn parse_private_key_matches_anvil_account_0() {
        // Anvil #0's well-known key must yield Anvil #0's address (oracle).
        let key =
            parse_private_key("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
                .unwrap();
        let addr = crate::address_from_verifying_key(key.verifying_key());
        assert_eq!(addr, "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        // The same key without the 0x prefix must parse identically.
        let key2 =
            parse_private_key("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
                .unwrap();
        assert_eq!(key2.to_bytes(), key.to_bytes());
    }

    #[test]
    fn parse_private_key_rejects_bad_input() {
        assert!(parse_private_key("0x1234").is_err()); // too short
        assert!(parse_private_key(&format!("0x{}", "zz".repeat(32))).is_err()); // not hex
        assert!(parse_private_key(&format!("0x{}", "00".repeat(32))).is_err()); // zero key
    }

    #[test]
    fn privkey_keystore_roundtrips_and_is_tagged() {
        let key_hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let accounts = vec![AccountMeta {
            index: 0,
            address: "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266".to_string(),
        }];
        let ks = seal("pw-pw-pw-pw", key_hex, "privkey", accounts.clone()).unwrap();
        assert_eq!(ks.kind, "privkey");
        // The raw key must NOT leak into any plaintext field.
        assert!(!ks.ciphertext.as_deref().unwrap().contains("ac0974"));
        let recovered = open("pw-pw-pw-pw", &ks).unwrap();
        assert_eq!(recovered.as_str(), key_hex);
    }

    #[test]
    fn ledger_keystore_has_no_secret_and_round_trips() {
        let accounts = vec![AccountMeta {
            index: 0,
            address: "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266".to_string(),
        }];
        let ks = ledger_keystore("m/44'/60'/0'/0/0", accounts.clone());
        assert_eq!(ks.kind, "ledger");
        assert_eq!(ks.path.as_deref(), Some("m/44'/60'/0'/0/0"));
        // No encrypted secret at rest, and the crypto fields are omitted from JSON.
        assert!(ks.ciphertext.is_none() && ks.salt.is_none());
        let json = serde_json::to_string(&ks).unwrap();
        assert!(
            !json.contains("ciphertext"),
            "ledger keystore must not serialize a ciphertext"
        );
        let back: Keystore = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, "ledger");
        assert_eq!(back.path.as_deref(), Some("m/44'/60'/0'/0/0"));
        assert_eq!(back.accounts, accounts);
        // open() must refuse loudly — there is nothing to decrypt.
        assert!(open("whatever", &ks).unwrap_err().contains("no"));
    }

    #[test]
    fn invalid_mnemonic_is_rejected() {
        // Wrong checksum / not in wordlist.
        assert!(validate_mnemonic("not a real mnemonic phrase at all zzz").is_err());
        assert!(derive_account("not a real mnemonic phrase at all zzz", 0).is_err());
    }

    #[test]
    fn seal_open_roundtrip_recovers_mnemonic() {
        let accounts = vec![AccountMeta {
            index: 0,
            address: "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266".to_string(),
        }];
        let ks = seal(
            "correct horse battery staple",
            TEST_MNEMONIC,
            "hd",
            accounts.clone(),
        )
        .unwrap();
        // The mnemonic must NOT appear in any plaintext field.
        assert!(!ks.ciphertext.as_deref().unwrap().contains("test"));
        assert_eq!(ks.kind, "hd");
        assert_eq!(ks.accounts, accounts);

        let recovered = open("correct horse battery staple", &ks).unwrap();
        assert_eq!(recovered.as_str(), TEST_MNEMONIC);
    }

    #[test]
    fn open_with_wrong_password_fails() {
        let ks = seal("right-password", TEST_MNEMONIC, "hd", vec![]).unwrap();
        let err = open("wrong-password", &ks).unwrap_err();
        assert!(err.contains("incorrect password"), "got: {err}");
    }

    #[test]
    fn each_seal_uses_a_fresh_salt_and_nonce() {
        let a = seal("pw", TEST_MNEMONIC, "hd", vec![]).unwrap();
        let b = seal("pw", TEST_MNEMONIC, "hd", vec![]).unwrap();
        // Same password + mnemonic must still produce different salt/nonce/ciphertext.
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }
}
