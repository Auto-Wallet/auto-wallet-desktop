use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use tauri::webview::{PageLoadEvent, WebviewBuilder};
use tauri::window::WindowBuilder;
use tauri::{AppHandle, Emitter, LogicalPosition, LogicalSize, Manager, Runtime, WebviewUrl};

// ---------------------------------------------------------------------------
// Crypto helpers.
// ---------------------------------------------------------------------------
use k256::ecdsa::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

// Encrypted HD key vault (BIP-39/44 + Argon2id/AES-GCM). Pure crypto core; the
// in-memory unlocked state + file I/O + Tauri commands live below in this file.
#[cfg(target_os = "macos")]
mod shell_startup;
mod smoke;
#[cfg(all(target_os = "macos", debug_assertions))]
mod startup_smoke;
mod vault;
mod password_change;
// EIP-1559 transaction encoding + signing (pure). eth_sendTransaction fills the
// fields from the node in lib.rs, then builds + signs here.
mod eth_tx;
// EIP-712 typed-data hashing (pure) for eth_signTypedData_v4.
mod eip712;
// Ledger hardware wallet over USB-HID (framing + Ethereum APDUs + hidapi I/O).
mod ledger;
mod native_menu;
mod okx_account;
mod relay;
mod touch_id;

use native_menu::{DEBUG_DAPP_CONSOLE_MENU_ID, DEBUG_SHELL_CONSOLE_MENU_ID};
use relay::{relay_chains, relay_quote, relay_status};
use okx_account::{
    okx_connection_status, okx_delete_credentials, okx_get_assets, okx_get_dcd_index_prices,
    okx_get_dcd_orders, okx_save_credentials, okx_save_dcd_csv,
};

const DEFI_PROVIDER_TIMEOUT: Duration = Duration::from_secs(12);
const DAPP_LAYOUT_INVALIDATED_EVENT: &str = "dapp-layout-invalidated";
const TOUCH_ID_MARKER_FILE: &str = "touch-id-enabled";

#[derive(Serialize)]
struct Wallet {
    address: String,
    private_key: String,
    public_key: String,
}

/// EVM address for a public key: "0x" || last 20 bytes of
/// keccak256(uncompressed_pubkey[1..]) (drops the 0x04 prefix byte).
fn address_from_verifying_key(verifying_key: &VerifyingKey) -> String {
    let encoded = verifying_key.to_encoded_point(false);
    let hash = Keccak256::digest(&encoded.as_bytes()[1..]);
    format!("0x{}", hex::encode(&hash[12..]))
}

/// Derive an EVM wallet from a secp256k1 key.
fn derive_wallet(signing_key: &SigningKey) -> Wallet {
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(false);
    Wallet {
        address: address_from_verifying_key(verifying_key),
        private_key: format!("0x{}", hex::encode(signing_key.to_bytes())),
        public_key: format!("0x{}", hex::encode(encoded.as_bytes())),
    }
}

#[allow(dead_code)]
fn generate_wallet() -> Wallet {
    derive_wallet(&SigningKey::random(&mut OsRng))
}

// ---------------------------------------------------------------------------
// Key vault (in-memory unlocked state).
//
// Private keys live ONLY in Rust and ONLY while the wallet is unlocked. The
// encrypted mnemonic at rest is handled by `mod vault` (Argon2id + AES-256-GCM);
// here we hold the decrypted, HD-derived accounts for the session. No key material
// ever crosses into any webview. There is NO hardcoded dev key anymore — a locked
// wallet refuses to sign (密钥安全: fail loud, never fall back to a default key).
// ---------------------------------------------------------------------------

/// How an account signs. A software account holds the secp256k1 key in process; a
/// Ledger account holds no key — it signs on the device over USB-HID at its path.
enum Signer {
    Local(SigningKey),
    Ledger { path: String },
}

/// One unlocked account. Software accounts are derived at `m/44'/60'/0'/0/index`;
/// Ledger accounts carry their own derivation path inside `Signer::Ledger`.
struct UnlockedAccount {
    index: u32,
    address: String,
    signer: Signer,
}

/// What kind of secret backs this vault — decides whether more accounts can be
/// derived. An imported single private key has no mnemonic to walk.
enum VaultSecret {
    /// BIP-39 root mnemonic — kept to derive further HD accounts on demand;
    /// zeroized on drop.
    Mnemonic(Zeroizing<String>),
    /// A single imported private key — the key lives in its `UnlockedAccount`;
    /// there is nothing to derive from, so `add_account` is refused.
    PrivateKey,
    /// A Ledger device — no in-process secret at all; signing goes to the device.
    Ledger,
}

/// The active account's signing capability, snapshotted out of the vault lock.
enum ActiveKind {
    /// Software key — sign in-process via `with_active_key`.
    Local,
    /// Ledger account at this derivation path — sign on the device (no lock held).
    Ledger(String),
}

/// One unlocked wallet — a single keystore's worth of accounts plus its root
/// secret. The app can hold several at once (multiple seeds / private keys /
/// Ledgers side by side), each identified by a stable `id`.
struct UnlockedWallet {
    id: String,
    label: String,
    secret: VaultSecret,
    accounts: Vec<UnlockedAccount>,
}

impl UnlockedWallet {
    /// On-disk kind tag for this wallet's secret.
    fn kind(&self) -> &'static str {
        match self.secret {
            VaultSecret::Mnemonic(_) => "hd",
            VaultSecret::PrivateKey => "privkey",
            VaultSecret::Ledger => "ledger",
        }
    }
}

/// The decrypted multi-wallet store for this session.
///
/// `password` is the single app password, kept in memory (Zeroizing) while
/// unlocked so a NEW software wallet can be sealed without re-prompting. This is
/// no weaker than holding the decrypted mnemonics, which already live here — the
/// password protects the very secrets already in RAM. `None` when no software
/// wallet exists (a Ledger-only setup has no password). `active` is the active
/// account ADDRESS (lowercase 0x), unique across all wallets.
struct WalletStore {
    password: Option<Zeroizing<String>>,
    wallets: Vec<UnlockedWallet>,
    active: String,
}

#[derive(Clone)]
enum ExposedAccount {
    Signer(String),
    WatchOnly(String),
}

fn store_state() -> &'static Mutex<Option<WalletStore>> {
    static V: OnceLock<Mutex<Option<WalletStore>>> = OnceLock::new();
    V.get_or_init(|| Mutex::new(None))
}

fn exposed_account_state() -> &'static Mutex<Option<ExposedAccount>> {
    static V: OnceLock<Mutex<Option<ExposedAccount>>> = OnceLock::new();
    V.get_or_init(|| Mutex::new(None))
}

/// The active account's address, or `None` when the wallet is locked / empty.
fn active_account_address() -> Option<String> {
    let guard = store_state().lock().unwrap();
    let s = guard.as_ref()?;
    s.wallets
        .iter()
        .flat_map(|w| &w.accounts)
        .find(|a| a.address == s.active)
        .map(|a| a.address.clone())
}

fn normalize_evm_address(address: &str) -> Result<String, String> {
    let trimmed = address.trim();
    let body = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .ok_or_else(|| format!("invalid address {trimmed}: expected 0x prefix"))?;
    if body.len() != 40 || !body.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("invalid address {trimmed}"));
    }
    Ok(format!("0x{}", body.to_ascii_lowercase()))
}

/// The public address exposed through EIP-1193 account reads. Signer addresses
/// still require an unlocked vault; watch-only addresses are public viewing
/// targets and may be exposed without any signing key.
fn dapp_account_address() -> Option<String> {
    match exposed_account_state().lock().unwrap().clone() {
        Some(ExposedAccount::WatchOnly(address)) => Some(address),
        Some(ExposedAccount::Signer(address)) => {
            let active = active_account_address()?;
            (active == address).then_some(address)
        }
        None => active_account_address(),
    }
}

/// Run `f` with the active account's *software* signing key. Errors clearly when
/// locked or when the active account is a Ledger (use the device path instead),
/// rather than silently falling back to any default key.
// Test-only: production signing looks the key up by the address the approval
// window showed (`with_key_for` / `signer_kind_for`), never by "whatever is
// active now" — that is how a switch mid-approval once signed with another key.
#[cfg(test)]
fn with_active_key<T>(f: impl FnOnce(&SigningKey) -> T) -> Result<T, String> {
    let guard = store_state().lock().unwrap();
    let s = guard.as_ref().ok_or("wallet is locked")?;
    let acct = s
        .wallets
        .iter()
        .flat_map(|w| &w.accounts)
        .find(|a| a.address == s.active)
        .ok_or("no active account")?;
    match &acct.signer {
        Signer::Local(key) => Ok(f(key)),
        Signer::Ledger { .. } => Err("active account is a Ledger — sign on the device".to_string()),
    }
}

/// Run `f` with a specific unlocked software account. Safe accounts are
/// represented in the UI by their contract address, while their confirmations
/// must be signed by one of the local owner EOAs. Looking the owner up by address
/// avoids switching the dApp-visible account away from the Safe.
fn with_key_for<T>(address: &str, f: impl FnOnce(&SigningKey) -> T) -> Result<T, String> {
    let address = normalize_evm_address(address)?;
    let guard = store_state().lock().unwrap();
    let s = guard.as_ref().ok_or("wallet is locked")?;
    let acct = s
        .wallets
        .iter()
        .flat_map(|w| &w.accounts)
        .find(|a| a.address == address)
        .ok_or_else(|| format!("{address} is not an unlocked local account"))?;
    match &acct.signer {
        Signer::Local(key) => Ok(f(key)),
        Signer::Ledger { .. } => Err("account is a Ledger — sign on the device".to_string()),
    }
}

/// Snapshot the active account's signing kind (and Ledger path) without holding the
/// store lock during the (slow) device round-trip.
// Test-only: production signing looks the key up by the address the approval
// window showed (`with_key_for` / `signer_kind_for`), never by "whatever is
// active now" — that is how a switch mid-approval once signed with another key.
#[cfg(test)]
fn active_signer_kind() -> Result<ActiveKind, String> {
    let guard = store_state().lock().unwrap();
    let s = guard.as_ref().ok_or("wallet is locked")?;
    let acct = s
        .wallets
        .iter()
        .flat_map(|w| &w.accounts)
        .find(|a| a.address == s.active)
        .ok_or("no active account")?;
    Ok(match &acct.signer {
        Signer::Local(_) => ActiveKind::Local,
        Signer::Ledger { path } => ActiveKind::Ledger(path.clone()),
    })
}

/// Snapshot a specific unlocked account's signing kind. Used by Safe owner
/// confirmations, where the selected account is the Safe contract but the signer
/// is one of its local owners.
fn signer_kind_for(address: &str) -> Result<ActiveKind, String> {
    let address = normalize_evm_address(address)?;
    let guard = store_state().lock().unwrap();
    let s = guard.as_ref().ok_or("wallet is locked")?;
    let acct = s
        .wallets
        .iter()
        .flat_map(|w| &w.accounts)
        .find(|a| a.address == address)
        .ok_or_else(|| format!("{address} is not an unlocked local account"))?;
    Ok(match &acct.signer {
        Signer::Local(_) => ActiveKind::Local,
        Signer::Ledger { path } => ActiveKind::Ledger(path.clone()),
    })
}

fn signer_kind_name(kind: &ActiveKind) -> &'static str {
    match kind {
        ActiveKind::Local => "local",
        ActiveKind::Ledger(_) => "ledger",
    }
}

/// Derive `count` (≥1) HD accounts from `mnemonic` into unlocked accounts + their
/// public metadata (for sealing into the keystore). Pure — touches no global state.
fn derive_hd_accounts(
    mnemonic: &str,
    count: u32,
) -> Result<(Vec<UnlockedAccount>, Vec<vault::AccountMeta>), String> {
    let count = count.max(1);
    let mut accounts = Vec::with_capacity(count as usize);
    let mut metas = Vec::with_capacity(count as usize);
    for index in 0..count {
        let (key, address) = vault::derive_account(mnemonic, index)?;
        metas.push(vault::AccountMeta {
            index,
            address: address.clone(),
        });
        accounts.push(UnlockedAccount {
            index,
            address,
            signer: Signer::Local(key),
        });
    }
    Ok((accounts, metas))
}

/// Build an in-memory HD wallet from a keystore's decrypted mnemonic, deriving each
/// RECORDED account index and checking the address matches (integrity). Consumes the
/// `Zeroizing` mnemonic so it lives on inside the wallet (and nowhere else).
fn build_hd_wallet_from_keystore(
    ks: &vault::Keystore,
    mnemonic: Zeroizing<String>,
) -> Result<UnlockedWallet, String> {
    let mut accounts = Vec::new();
    for meta in &ks.accounts {
        let (key, address) = vault::derive_account(&mnemonic, meta.index)?;
        if address != meta.address {
            return Err("keystore integrity check failed".to_string());
        }
        accounts.push(UnlockedAccount {
            index: meta.index,
            address,
            signer: Signer::Local(key),
        });
    }
    if accounts.is_empty() {
        // A legacy keystore may record no accounts — derive the first.
        let (key, address) = vault::derive_account(&mnemonic, 0)?;
        accounts.push(UnlockedAccount {
            index: 0,
            address,
            signer: Signer::Local(key),
        });
    }
    Ok(UnlockedWallet {
        id: ks.id.clone(),
        label: ks.label.clone(),
        secret: VaultSecret::Mnemonic(mnemonic),
        accounts,
    })
}

/// Build an in-memory single-account wallet from a keystore's decrypted private key.
fn build_privkey_wallet_from_keystore(
    ks: &vault::Keystore,
    privkey_hex: &str,
) -> Result<UnlockedWallet, String> {
    let key = vault::parse_private_key(privkey_hex)?;
    let address = address_from_verifying_key(key.verifying_key());
    if let Some(meta) = ks.accounts.first() {
        if meta.address != address {
            return Err("keystore integrity check failed".to_string());
        }
    }
    Ok(UnlockedWallet {
        id: ks.id.clone(),
        label: ks.label.clone(),
        secret: VaultSecret::PrivateKey,
        accounts: vec![UnlockedAccount {
            index: 0,
            address,
            signer: Signer::Local(key),
        }],
    })
}

/// Build an in-memory Ledger wallet from its keystore (path + public address only —
/// no in-process key; signing goes to the device).
fn build_ledger_wallet_from_keystore(ks: &vault::Keystore) -> Result<UnlockedWallet, String> {
    let path = ks
        .path
        .as_deref()
        .ok_or("ledger keystore missing derivation path")?;
    let address = ks
        .accounts
        .first()
        .map(|a| a.address.clone())
        .ok_or("ledger keystore has no account")?;
    Ok(UnlockedWallet {
        id: ks.id.clone(),
        label: ks.label.clone(),
        secret: VaultSecret::Ledger,
        accounts: vec![UnlockedAccount {
            index: 0,
            address,
            signer: Signer::Ledger {
                path: path.to_string(),
            },
        }],
    })
}

/// Push a freshly-built wallet into the session store (creating the store if it was
/// locked/absent), make its first account active, and — when adding the first
/// software wallet — record the app password. Returns the new active address.
fn store_push_wallet(wallet: UnlockedWallet, password: Option<Zeroizing<String>>) -> String {
    let first = wallet
        .accounts
        .first()
        .map(|a| a.address.clone())
        .unwrap_or_default();
    note_activity();
    let mut guard = store_state().lock().unwrap();
    match guard.as_mut() {
        Some(store) => {
            if password.is_some() {
                store.password = password;
            }
            store.wallets.push(wallet);
            store.active = first.clone();
        }
        None => {
            *guard = Some(WalletStore {
                password,
                wallets: vec![wallet],
                active: first.clone(),
            });
        }
    }
    if !first.is_empty() {
        *exposed_account_state().lock().unwrap() = Some(ExposedAccount::Signer(first.clone()));
    }
    first
}

/// Install a single freshly-derived HD wallet as THE session store (test helper —
/// resets any existing store; production paths ADD wallets via `store_push_wallet`).
#[cfg(test)]
fn install_unlocked_vault(mnemonic: &str, count: u32) -> Result<Vec<vault::AccountMeta>, String> {
    let (accounts, metas) = derive_hd_accounts(mnemonic, count)?;
    let active = accounts
        .first()
        .map(|a| a.address.clone())
        .unwrap_or_default();
    *store_state().lock().unwrap() = Some(WalletStore {
        password: None,
        wallets: vec![UnlockedWallet {
            id: "w-hd".to_string(),
            label: "Wallet 1".to_string(),
            secret: VaultSecret::Mnemonic(Zeroizing::new(mnemonic.to_string())),
            accounts,
        }],
        active,
    });
    Ok(metas)
}

/// Install a single imported private key as THE session store (test helper).
#[cfg(test)]
fn install_privkey_vault(privkey_hex: &str) -> Result<Vec<vault::AccountMeta>, String> {
    let key = vault::parse_private_key(privkey_hex)?;
    let address = address_from_verifying_key(key.verifying_key());
    let metas = vec![vault::AccountMeta {
        index: 0,
        address: address.clone(),
    }];
    *store_state().lock().unwrap() = Some(WalletStore {
        password: None,
        wallets: vec![UnlockedWallet {
            id: "w-privkey".to_string(),
            label: "Wallet 1".to_string(),
            secret: VaultSecret::PrivateKey,
            accounts: vec![UnlockedAccount {
                index: 0,
                address: address.clone(),
                signer: Signer::Local(key),
            }],
        }],
        active: address,
    });
    Ok(metas)
}

/// Install a single Ledger account as THE session store (test helper).
#[cfg(test)]
fn install_ledger_vault(path: &str, address: &str) -> Result<Vec<vault::AccountMeta>, String> {
    let metas = vec![vault::AccountMeta {
        index: 0,
        address: address.to_string(),
    }];
    *store_state().lock().unwrap() = Some(WalletStore {
        password: None,
        wallets: vec![UnlockedWallet {
            id: "w-ledger".to_string(),
            label: "Wallet 1".to_string(),
            secret: VaultSecret::Ledger,
            accounts: vec![UnlockedAccount {
                index: 0,
                address: address.to_string(),
                signer: Signer::Ledger {
                    path: path.to_string(),
                },
            }],
        }],
        active: address.to_string(),
    });
    Ok(metas)
}

/// Decode a `personal_sign` message param. dApps usually send 0x-hex; some send a
/// raw UTF-8 string. EIP-191 hashes the *bytes*, so we just need the byte form.
fn decode_message_param(param: &Value) -> Result<Vec<u8>, String> {
    let s = param
        .as_str()
        .ok_or("personal_sign: message param must be a string")?;
    match s.strip_prefix("0x") {
        Some(hex_body) => hex::decode(hex_body)
            .map_err(|e| format!("personal_sign: message is not valid hex: {e}")),
        None => Ok(s.as_bytes().to_vec()),
    }
}

/// EIP-191 `personal_sign`. A software account signs keccak256("\x19Ethereum
/// Signed Message:\n" || len || msg) locally; a Ledger applies the EIP-191 prefix
/// itself, so it gets the raw message. Returns 65-byte r‖s‖v hex (v = 27/28).
///
/// `address` is the signer the approval window showed; the key is looked up by
/// it, so switching the active account while the prompt is open cannot change
/// which key signs.
fn personal_sign_for(address: &str, message: &[u8]) -> Result<Value, String> {
    let sig = match signer_kind_for(address)? {
        ActiveKind::Local => {
            let mut preimage =
                format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
            preimage.extend_from_slice(message);
            let digest = Keccak256::digest(&preimage);
            let (signature, recovery_id) =
                with_key_for(address, |k| k.sign_prehash_recoverable(&digest))?
                    .map_err(|e| format!("personal_sign: signing failed: {e}"))?;
            let mut sig = signature.to_bytes().to_vec(); // 64 bytes: r ‖ s
            sig.push(27 + recovery_id.to_byte()); // v
            sig
        }
        ActiveKind::Ledger(path) => ledger::sign_personal_message(&path, message)?.to_vec(),
    };
    Ok(json!(format!("0x{}", hex::encode(sig))))
}

// ---------------------------------------------------------------------------
// Wallet backend.
//
// Methods split three ways (see `route_method`):
//   * Wallet  — answered from local wallet state (accounts, selected chain).
//   * Signing — need the private key + user approval; not wired yet.
//   * Forward — read-only, proxied to the selected chain's public RPC node.
//
// The signing path + an encrypted key vault land next; for now dApps can read
// real chain state through the wallet and switch between built-in chains.
// ---------------------------------------------------------------------------

/// Anvil/Hardhat account #0 — the address the well-known test mnemonic derives at
/// `m/44'/60'/0'/0/0`. Test-only fixture (the unlocked test vault uses that
/// mnemonic), so production builds don't reference it.
#[cfg(test)]
const SPIKE_ACCOUNT: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";

/// A supported EVM chain. `rpc` is the public node we forward read-only JSON-RPC
/// to. Users can add custom chains and edit existing params from Settings; the
/// effective list lives in `chains_state()` and is persisted to chains.json.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct ChainCfg {
    /// EIP-155 chain id as a 0x-hex string (what dApps see via `eth_chainId`).
    id: String,
    name: String,
    symbol: String,
    rpc: String,
    decimals: u32,
    /// Brand color for the chain dot (frontend display).
    color: String,
    #[serde(
        default,
        rename = "explorerUrl",
        skip_serializing_if = "Option::is_none"
    )]
    explorer_url: Option<String>,
    /// Built-in chains can be edited (rpc/name/symbol) but not removed.
    builtin: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActivityRecord {
    id: String,
    hash: String,
    chain_id: String,
    chain_name: String,
    symbol: String,
    from: String,
    to: String,
    value: String,
    data: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    gas: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    nonce: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    max_priority_fee_per_gas: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    max_fee_per_gas: String,
    origin: String,
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    counterparty: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    asset_symbol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    asset_decimals: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    amount: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    swap: Option<ActivitySwap>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    balance_changes: Vec<ActivityBalanceChange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    timestamp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActivityBalanceChange {
    symbol: String,
    formatted_delta: String,
    direction: String,
}

/// Swap/bridge legs the wallet's own cross-chain flow attaches to the source tx,
/// so Activity can name the provider and both amounts. Amounts are hex wei.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActivitySwap {
    provider: String,
    from_symbol: String,
    from_amount: String,
    from_decimals: u32,
    from_chain_name: String,
    to_symbol: String,
    to_amount: String,
    to_decimals: u32,
    to_chain_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PortfolioSnapshot {
    address: String,
    total_usd: f64,
    timestamp: u64,
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    html_url: String,
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateInfo {
    current_version: String,
    latest_version: String,
    available: bool,
    release_url: String,
    download_url: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DefiPositionToken {
    symbol: String,
    balance: Option<String>,
    balance_usd: Option<f64>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DefiPosition {
    id: String,
    app_name: String,
    app_image_url: Option<String>,
    app_url: Option<String>,
    network_name: String,
    chain_id: String,
    label: String,
    group_label: Option<String>,
    balance_usd: f64,
    symbols: Vec<String>,
    tokens: Vec<DefiPositionToken>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DefiPositionsResponse {
    source: String,
    positions: Vec<DefiPosition>,
}

#[derive(Clone, Copy)]
struct CustomDefiProvider {
    name: &'static str,
    fetch: fn(PriceOracleStore, String) -> CustomDefiFetch,
}

type CustomDefiFetch =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<DefiPosition>, String>> + Send>>;

#[derive(Clone)]
struct PriceOracleStore {
    path: Option<PathBuf>,
    log_path: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PriceOracleCache {
    updated_at_ms: u64,
    prices: HashMap<String, PriceOracleEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PriceOracleEntry {
    usd: f64,
    change_24h: f64,
}

#[derive(Clone, Copy)]
struct XStakeFarmingPool {
    key: &'static str,
    contract: &'static str,
    staking_symbol: &'static str,
    staking_decimals: u8,
    staking_price_id: &'static str,
    reward_symbol: &'static str,
    reward_decimals: u8,
    reward_price_id: &'static str,
    reward_addr: &'static str,
}

struct Multicall3Call {
    target: String,
    call_data: String,
}

fn default_explorer_url(chain_id: &str) -> Option<String> {
    let base = match chain_id.to_lowercase().as_str() {
        "0x1" => "https://etherscan.io/tx/",
        "0x2105" => "https://basescan.org/tx/",
        "0xa" => "https://optimistic.etherscan.io/tx/",
        "0xa4b1" => "https://arbiscan.io/tx/",
        "0x89" => "https://polygonscan.com/tx/",
        "0x38" => "https://bscscan.com/tx/",
        "0xa86a" => "https://snowtrace.io/tx/",
        "0xe708" => "https://lineascan.build/tx/",
        "0x13e31" => "https://blastscan.io/tx/",
        "0x144" => "https://era.zksync.network/tx/",
        "0x44d" => "https://zkevm.polygonscan.com/tx/",
        "0x92" => "https://sonicscan.org/tx/",
        "0xc4" => "https://www.oklink.com/xlayer/tx/",
        "0x1e0" => "https://worldscan.org/tx/",
        "0x250" => "https://astar.subscan.io/evm_transaction/",
        "0x378" => "https://wanscan.org/tx/",
        "0x440" => "https://andromeda-explorer.metis.io/tx/",
        "0xa4ec" => "https://celoscan.io/tx/",
        _ => return None,
    };
    Some(base.to_string())
}

fn hydrate_chain_defaults(chain: &mut ChainCfg) {
    if chain.explorer_url.is_none() {
        chain.explorer_url = default_explorer_url(&chain.id);
    }
}

fn builtin_chains() -> Vec<ChainCfg> {
    fn c(id: &str, name: &str, symbol: &str, rpc: &str, color: &str) -> ChainCfg {
        ChainCfg {
            id: id.into(),
            name: name.into(),
            symbol: symbol.into(),
            rpc: rpc.into(),
            decimals: 18,
            color: color.into(),
            explorer_url: default_explorer_url(id),
            builtin: true,
        }
    }
    vec![
        c(
            "0x1",
            "Ethereum",
            "ETH",
            "https://ethereum-rpc.publicnode.com",
            "#627EEA",
        ),
        c(
            "0x2105",
            "Base",
            "ETH",
            "https://base-rpc.publicnode.com",
            "#0052FF",
        ),
        c(
            "0xa",
            "OP Mainnet",
            "ETH",
            "https://optimism-rpc.publicnode.com",
            "#FF0420",
        ),
        c(
            "0xa4b1",
            "Arbitrum One",
            "ETH",
            "https://arbitrum-one-rpc.publicnode.com",
            "#28A0F0",
        ),
        c(
            "0x89",
            "Polygon",
            "POL",
            "https://polygon-bor-rpc.publicnode.com",
            "#8247E5",
        ),
        // Extended default set (EVM subset of the xflows supported-chains snapshot).
        c(
            "0x38",
            "BNB Chain",
            "BNB",
            "https://bsc-dataseed.bnbchain.org",
            "#F3BA2F",
        ),
        c(
            "0xa86a",
            "Avalanche",
            "AVAX",
            "https://avalanche-c-chain-rpc.publicnode.com",
            "#E84142",
        ),
        c(
            "0xe708",
            "Linea",
            "ETH",
            "https://linea-rpc.publicnode.com",
            "#61DFFF",
        ),
        c(
            "0x13e31",
            "Blast",
            "ETH",
            "https://blast-rpc.publicnode.com",
            "#FCD000",
        ),
        c(
            "0x144",
            "zkSync Era",
            "ETH",
            "https://mainnet.era.zksync.io",
            "#8C8DFC",
        ),
        c(
            "0x44d",
            "Polygon zkEVM",
            "ETH",
            "https://zkevm-rpc.com",
            "#7B3FE4",
        ),
        c("0x92", "Sonic", "S", "https://rpc.soniclabs.com", "#1969FF"),
        c(
            "0xc4",
            "X Layer",
            "OKB",
            "https://rpc.xlayer.tech",
            "#1A1A1A",
        ),
        c(
            "0x1e0",
            "World Chain",
            "ETH",
            "https://worldchain-mainnet.g.alchemy.com/public",
            "#1A1A1A",
        ),
        c(
            "0x250",
            "Astar",
            "ASTR",
            "https://evm.astar.network",
            "#1B6DC1",
        ),
        c(
            "0x378",
            "Wanchain",
            "WAN",
            "https://gwan-ssl.wandevs.org:56891",
            "#2A6BE9",
        ),
        c(
            "0x440",
            "Metis",
            "METIS",
            "https://andromeda.metis.io/?owner=1088",
            "#00DACC",
        ),
        c(
            "0xa4ec",
            "Celo",
            "CELO",
            "https://forno.celo.org",
            "#FCB728",
        ),
    ]
}

/// Overlay a persisted chains.json snapshot onto the CURRENT built-in set.
///
/// The file is a full snapshot from whatever app version wrote it, so built-ins
/// added in a later release are missing from it; adopting it verbatim would
/// freeze the registry at that old version forever (networks "lost" after
/// upgrading). Persisted entries win for ids they contain — user RPC/name edits
/// survive, apart from exact retired defaults that need a one-time migration —
/// and a persisted entry whose id has since become a built-in is promoted
/// (non-removable, sorted with the built-ins). Built-ins the file doesn't know
/// about are backfilled with current defaults, in built-in order; custom chains
/// keep their relative order at the end.
fn merge_persisted_chains(mut persisted: Vec<ChainCfg>) -> Vec<ChainCfg> {
    for chain in &mut persisted {
        hydrate_chain_defaults(chain);
    }
    let mut merged: Vec<ChainCfg> = Vec::new();
    for builtin in builtin_chains() {
        match persisted
            .iter()
            .find(|c| c.id.eq_ignore_ascii_case(&builtin.id))
        {
            Some(saved) => {
                let mut saved = saved.clone();
                // Retire the former BNB default without overwriting a user-picked RPC.
                if saved.id.eq_ignore_ascii_case("0x38")
                    && saved.rpc == "https://bsc-rpc.publicnode.com"
                {
                    saved.rpc = builtin.rpc.clone();
                }
                saved.builtin = true;
                merged.push(saved);
            }
            None => merged.push(builtin),
        }
    }
    for chain in persisted {
        if !merged.iter().any(|c| c.id.eq_ignore_ascii_case(&chain.id)) {
            merged.push(chain);
        }
    }
    merged
}

/// The effective chain registry (built-ins + user edits/additions). Initialized to
/// the built-ins; `load_chains` merges the persisted user file at startup.
fn chains_state() -> &'static Mutex<Vec<ChainCfg>> {
    static C: OnceLock<Mutex<Vec<ChainCfg>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(builtin_chains()))
}

fn find_chain(id: &str) -> Option<ChainCfg> {
    chains_state()
        .lock()
        .unwrap()
        .iter()
        .find(|c| c.id.eq_ignore_ascii_case(id))
        .cloned()
}

/// The wallet's currently selected chain (EIP-155 hex). dApps read it via
/// `eth_chainId`; read-only RPC is forwarded to this chain's node. Mutable so
/// `wallet_switchEthereumChain` works. Defaults to Ethereum mainnet.
fn current_chain() -> &'static Mutex<String> {
    static CURRENT: OnceLock<Mutex<String>> = OnceLock::new();
    CURRENT.get_or_init(|| Mutex::new("0x1".to_string()))
}

/// The one dApp tab currently visible in the browser content area. Background
/// webviews stay alive when tabs/pages switch, but they must not be able to pop
/// signing approvals while hidden.
fn active_dapp_label() -> &'static Mutex<Option<String>> {
    static ACTIVE: OnceLock<Mutex<Option<String>>> = OnceLock::new();
    ACTIVE.get_or_init(|| Mutex::new(None))
}

fn set_active_dapp_label(label: String) {
    *active_dapp_label().lock().unwrap() = Some(label);
}

fn clear_active_dapp_label(label: &str) {
    let mut active = active_dapp_label().lock().unwrap();
    if active.as_deref() == Some(label) {
        *active = None;
    }
}

fn toggle_devtools<R: Runtime>(webview: &tauri::Webview<R>) {
    if webview.is_devtools_open() {
        webview.close_devtools();
    } else {
        webview.open_devtools();
    }
}

fn handle_debug_menu_event<R: Runtime + 'static>(app: &AppHandle<R>, menu_id: &str) {
    match menu_id {
        DEBUG_SHELL_CONSOLE_MENU_ID => {
            if let Some(shell) = app.get_webview("shell") {
                toggle_devtools(&shell);
            } else {
                println!("[AutoDesktop] debug menu: shell webview not found");
            }
        }
        DEBUG_DAPP_CONSOLE_MENU_ID => {
            let active = active_dapp_label().lock().unwrap().clone();
            let Some(label) = active else {
                println!("[AutoDesktop] debug menu: no active dApp webview");
                return;
            };
            if let Some(dapp) = app.get_webview(&label) {
                toggle_devtools(&dapp);
                repair_dapp_bounds_after_devtools(app.clone(), label.clone());
                let _ = app.emit(
                    DAPP_LAYOUT_INVALIDATED_EVENT,
                    DappLayoutInvalidatedEvent { label },
                );
            } else {
                println!("[AutoDesktop] debug menu: active dApp webview {label:?} not found");
            }
        }
        _ => {}
    }
}

fn install_app_menu<R: Runtime + 'static>(app: &tauri::App<R>) -> tauri::Result<()> {
    let menu = native_menu::build(app.handle(), "en")
        .map_err(|error| tauri::Error::Io(std::io::Error::other(error)))?;
    app.set_menu(menu)?;
    app.on_menu_event(|app, event| {
        handle_debug_menu_event(app, event.id().as_ref());
    });
    Ok(())
}

#[tauri::command]
fn set_app_menu_language<R: Runtime>(app: AppHandle<R>, language: String) -> Result<(), String> {
    let menu = native_menu::build(&app, &language)?;
    app.set_menu(menu)
        .map(|_| ())
        .map_err(|error| format!("installing app menu: {error}"))
}

fn ensure_signing_webview_is_active(label: &str) -> Result<(), String> {
    let active = active_dapp_label().lock().unwrap().clone();
    if active.as_deref() == Some(label) {
        Ok(())
    } else {
        Err("Request blocked because this dApp is not the active tab".to_string())
    }
}

/// How long a single JSON-RPC read may take before the call fails. `prepare_tx`
/// makes up to four of these in sequence and is capped as a whole by
/// `TX_PREPARE_TIMEOUT`, so this bound is what stops ONE stalled call from eating
/// the entire budget — it is deliberately smaller than the cap, not a quarter of it.
const RPC_TIMEOUT: Duration = Duration::from_secs(6);
/// Broadcasting gets longer than a read: a timeout here leaves the transaction in
/// an unknown state (signed, possibly accepted), which is worse than waiting.
const BROADCAST_TIMEOUT: Duration = Duration::from_secs(15);
/// The whole pre-approval preparation (nonce + gas + fees).
const TX_PREPARE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the approval window gets to actually come up and report in.
const APPROVAL_WINDOW_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the user then gets to read the request and decide. This one is long on
/// purpose — a Ledger confirmation is slow — and it starts only once the window is
/// up, so it can no longer hide a window that never appeared.
const DECISION_TIMEOUT: Duration = Duration::from_secs(300);

/// A pooled HTTP client (keeps connections warm across RPC calls).
///
/// The timeouts are not optional garnish. With a bare `reqwest::Client::new()`
/// there is no request timeout, no connect timeout and no pool hygiene, so a
/// keep-alive connection the peer had silently dropped would swallow a request
/// and never answer — the future parked forever and the UI sat on "confirm in
/// window" with no window and no error. `pool_idle_timeout` + `tcp_keepalive`
/// retire those sockets before they can be reused; `timeout` bounds what is left.
fn http() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(BROADCAST_TIMEOUT) // per-call `.timeout()` tightens this
            .pool_idle_timeout(Duration::from_secs(15))
            .tcp_keepalive(Duration::from_secs(30))
            .build()
            .expect("build the shared HTTP client")
    })
}

#[derive(Debug, PartialEq)]
enum Route {
    /// Answered locally from wallet state.
    Wallet,
    /// Needs the private key + user approval (see the approval flow).
    Signing,
    /// Read-only; forwarded to the selected chain's node.
    Forward,
}

/// Classify an RPC method. Anything not explicitly wallet- or signing-related is
/// treated as a read-only node call (the long tail of `eth_*` getters).
fn route_method(method: &str) -> Route {
    match method {
        "eth_accounts"
        | "eth_requestAccounts"
        | "eth_coinbase"
        | "eth_chainId"
        | "net_version"
        | "wallet_switchEthereumChain"
        | "wallet_addEthereumChain"
        | "wallet_requestPermissions"
        | "wallet_getPermissions"
        | "wallet_revokePermissions"
        | "wallet_watchAsset" => Route::Wallet,

        "eth_sendTransaction"
        | "eth_sign"
        | "personal_sign"
        | "eth_signTypedData"
        | "eth_signTypedData_v1"
        | "eth_signTypedData_v3"
        | "eth_signTypedData_v4" => Route::Signing,

        _ => Route::Forward,
    }
}

/// Result of a wallet-method call. `SwitchChain` is a directive the caller
/// applies to the shared `current_chain()` state — keeping this function pure
/// (no global mutation) so it can be unit-tested deterministically.
#[derive(Debug, PartialEq)]
enum WalletOutcome {
    Reply(Value),
    SwitchChain(String),
    /// EIP-3085: a dApp asked to add a network the registry doesn't have yet. The
    /// caller inserts + persists it, then switches to it.
    AddChain(ChainCfg),
}

/// Handle a wallet-namespaced method against the given `current` chain id and the
/// active account (`None` when the wallet is locked). Pure: reads no globals, does
/// no I/O — the caller supplies chain + account so this stays unit-testable.
fn handle_wallet_method(
    method: &str,
    params: &[Value],
    current: &str,
    account: Option<&str>,
) -> Result<WalletOutcome, String> {
    let chain_id_param = || -> Result<&str, String> {
        params
            .first()
            .and_then(|p| p.get("chainId"))
            .and_then(|c| c.as_str())
            .ok_or_else(|| format!("{method}: missing chainId param"))
    };

    match method {
        // EIP-1193: an unlocked wallet reports its active account; a locked one
        // reports none (the dApp shows a "connect" prompt). We never expose a key
        // here — only the public address.
        "eth_accounts" | "eth_requestAccounts" => Ok(WalletOutcome::Reply(
            account.map(|a| json!([a])).unwrap_or_else(|| json!([])),
        )),
        "eth_coinbase" => Ok(WalletOutcome::Reply(
            account.map(|a| json!(a)).unwrap_or(Value::Null),
        )),
        "eth_chainId" => Ok(WalletOutcome::Reply(json!(current))),
        "net_version" => {
            // current is always a registry id (valid hex) — surface a real error
            // rather than masking an impossible bad value with a default.
            let dec = u64::from_str_radix(current.trim_start_matches("0x"), 16)
                .map_err(|_| format!("invalid current chain id: {current}"))?;
            Ok(WalletOutcome::Reply(json!(dec.to_string())))
        }
        "wallet_switchEthereumChain" => {
            let target = chain_id_param()?;
            let chain = find_chain(target).ok_or_else(|| {
                format!("Unrecognized chain ID {target}; add it first with wallet_addEthereumChain (code 4902)")
            })?;
            Ok(WalletOutcome::SwitchChain(chain.id.to_string()))
        }
        "wallet_addEthereumChain" => {
            let target = chain_id_param()?;
            // Already known → switch to OUR configured chain (we keep our own RPC,
            // never adopt the dApp-supplied one for a chain we already trust).
            if let Some(chain) = find_chain(target) {
                return Ok(WalletOutcome::SwitchChain(chain.id));
            }
            // New chain → build a ChainCfg from the EIP-3085 params and add it.
            let p = params
                .first()
                .ok_or_else(|| format!("{method}: missing params"))?;
            let id = normalize_chain_id(target)?;
            let name = p
                .get("chainName")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| format!("{method}: chainName is required"))?;
            let rpc = p
                .get("rpcUrls")
                .and_then(|v| v.as_array())
                .and_then(|a| a.iter().find_map(|u| u.as_str()))
                .map(|s| s.to_string())
                .ok_or_else(|| format!("{method}: an rpcUrls entry is required"))?;
            validate_rpc(&rpc)?;
            let nc = p.get("nativeCurrency");
            let symbol = nc
                .and_then(|n| n.get("symbol"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("ETH")
                .to_string();
            let decimals = nc
                .and_then(|n| n.get("decimals"))
                .and_then(|v| v.as_u64())
                .filter(|d| *d != 0)
                .unwrap_or(18) as u32;
            let explorer_url = p
                .get("blockExplorerUrls")
                .and_then(|v| v.as_array())
                .and_then(|a| a.iter().find_map(|u| u.as_str()))
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            if let Some(url) = explorer_url.as_deref() {
                validate_explorer_url(url)?;
            }
            Ok(WalletOutcome::AddChain(ChainCfg {
                id,
                name,
                symbol,
                rpc,
                decimals,
                color: "#6b7280".to_string(),
                explorer_url,
                builtin: false,
            }))
        }
        // Minimal EIP-2255: we only ever grant eth_accounts.
        "wallet_requestPermissions" | "wallet_getPermissions" => Ok(WalletOutcome::Reply(
            json!([{ "parentCapability": "eth_accounts" }]),
        )),
        "wallet_revokePermissions" => Ok(WalletOutcome::Reply(Value::Null)),
        "wallet_watchAsset" => Ok(WalletOutcome::Reply(json!(true))),
        other => Err(format!("wallet method not handled: {other}")),
    }
}

/// PublicNode gates its RPC endpoints behind an API key, supplied as the last
/// path segment (`https://ethereum-rpc.publicnode.com/<key>`). The key is
/// deliberately NOT baked into `builtin_chains()`: those URLs get persisted to
/// chains.json and rendered in Settings, so it is appended here — at the request
/// site — and never reaches disk or the UI. A publicnode URL that already carries
/// a path (someone pasted their own keyed endpoint) is left alone, as is every
/// non-publicnode node.
fn apply_public_node_key<'a>(url: &'a str, key: &str) -> Cow<'a, str> {
    let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    else {
        return Cow::Borrowed(url);
    };
    // Split host off first so the suffix match can't be spoofed by a hostile
    // path or query, e.g. `https://evil.example/publicnode.com`.
    let (host, path) = match rest.find(['/', '?', '#']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if host != "publicnode.com" && !host.ends_with(".publicnode.com") {
        return Cow::Borrowed(url);
    }
    if !path.is_empty() && path != "/" {
        return Cow::Borrowed(url);
    }
    Cow::Owned(format!("{}/{}", url.trim_end_matches('/'), key))
}

fn with_public_node_key(url: &str) -> Cow<'_, str> {
    match public_node_key() {
        Some(key) => apply_public_node_key(url, key),
        None => Cow::Borrowed(url),
    }
}

/// Forward a read-only method to the selected chain's node and return its result.
/// Node-side JSON-RPC errors are propagated (not masked).
/// Low-level JSON-RPC POST to a specific chain's configured node. Done server-side
/// (reqwest), so it is NOT subject to the node's CORS policy — many public RPCs
/// send no CORS headers, which would break a browser `fetch`. Shared by dApp
/// forwarding and the shell's read command.
async fn node_rpc_call(chain: &ChainCfg, method: &str, params: &[Value]) -> Result<Value, String> {
    node_rpc_call_within(chain, method, params, RPC_TIMEOUT).await
}

/// Why a call failed. The difference matters exactly once — when broadcasting a
/// signed transaction. `Rejected` means the node read it and said no, so nothing
/// is in flight. `Unreachable` means we never got an answer, so it might be.
enum RpcFailure {
    Rejected(String),
    Unreachable(String),
}

impl RpcFailure {
    fn message(self) -> String {
        match self {
            RpcFailure::Rejected(m) | RpcFailure::Unreachable(m) => m,
        }
    }
}

/// `node_rpc_call` with an explicit budget. Reads take `RPC_TIMEOUT`; broadcasting
/// takes `BROADCAST_TIMEOUT`. No call is ever unbounded.
async fn node_rpc_call_within(
    chain: &ChainCfg,
    method: &str,
    params: &[Value],
    budget: Duration,
) -> Result<Value, String> {
    node_rpc_try(chain, method, params, budget)
        .await
        .map_err(RpcFailure::message)
}

async fn node_rpc_try(
    chain: &ChainCfg,
    method: &str,
    params: &[Value],
    budget: Duration,
) -> Result<Value, RpcFailure> {
    let payload = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });

    let resp = http()
        .post(with_public_node_key(&chain.rpc).as_ref())
        .timeout(budget)
        .json(&payload)
        .send()
        .await
        // `without_url` matters now that the URL carries the API key: reqwest's
        // Display prints the failing URL, which would spill the key into the
        // error string the UI and the dApp both get to see.
        .map_err(|e| {
            RpcFailure::Unreachable(format!(
                "RPC request to {} failed: {}",
                chain.name,
                e.without_url()
            ))
        })?;
    let body: Value = resp.json().await.map_err(|e| {
        RpcFailure::Unreachable(format!(
            "RPC response from {} was not JSON: {e}",
            chain.name
        ))
    })?;

    if let Some(err) = body.get("error") {
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown RPC error");
        // The node answered, in full sentences: this is a verdict, not a gap.
        return Err(RpcFailure::Rejected(format!("{msg} (code {code})")));
    }
    body.get("result").cloned().ok_or_else(|| {
        RpcFailure::Unreachable(format!("RPC response from {} had no result", chain.name))
    })
}

async fn forward_to_node(method: &str, params: &[Value]) -> Result<Value, String> {
    let chain_id = current_chain().lock().unwrap().clone();
    let chain =
        find_chain(&chain_id).ok_or_else(|| format!("no RPC configured for chain {chain_id}"))?;
    node_rpc_call(&chain, method, params).await
}

/// Methods a dApp may have forwarded to the selected chain's node: the standard
/// read/filter methods plus `eth_sendRawTransaction` (the page signed it itself).
/// Everything else — `anvil_*`, `hardhat_*`, `personal_*`, `debug_*`, `admin_*`,
/// `eth_signTransaction` — is refused: on a local dev node the user registered,
/// those would let a web page mint balances or use node-held accounts.
fn is_forwardable_method(method: &str) -> bool {
    matches!(
        method,
        "eth_blockNumber"
            | "eth_call"
            | "eth_estimateGas"
            | "eth_feeHistory"
            | "eth_gasPrice"
            | "eth_maxPriorityFeePerGas"
            | "eth_blobBaseFee"
            | "eth_getBalance"
            | "eth_getBlockByHash"
            | "eth_getBlockByNumber"
            | "eth_getBlockReceipts"
            | "eth_getBlockTransactionCountByHash"
            | "eth_getBlockTransactionCountByNumber"
            | "eth_getCode"
            | "eth_getFilterChanges"
            | "eth_getFilterLogs"
            | "eth_getLogs"
            | "eth_getProof"
            | "eth_getStorageAt"
            | "eth_getTransactionByBlockHashAndIndex"
            | "eth_getTransactionByBlockNumberAndIndex"
            | "eth_getTransactionByHash"
            | "eth_getTransactionCount"
            | "eth_getTransactionReceipt"
            | "eth_getUncleByBlockHashAndIndex"
            | "eth_getUncleByBlockNumberAndIndex"
            | "eth_getUncleCountByBlockHash"
            | "eth_getUncleCountByBlockNumber"
            | "eth_newBlockFilter"
            | "eth_newFilter"
            | "eth_newPendingTransactionFilter"
            | "eth_uninstallFilter"
            | "eth_protocolVersion"
            | "eth_syncing"
            | "eth_sendRawTransaction"
            | "net_listening"
            | "net_peerCount"
            | "web3_clientVersion"
            | "web3_sha3"
    )
}

/// Read-only methods the trusted shell may forward to a node. Keeps `node_rpc` a
/// pure read channel — writes (eth_sendRawTransaction) go through the signing path.
fn is_read_method(method: &str) -> bool {
    matches!(
        method,
        "eth_getBalance"
            | "eth_call"
            | "eth_getTransactionCount"
            | "eth_gasPrice"
            | "eth_maxPriorityFeePerGas"
            | "eth_estimateGas"
            | "eth_blockNumber"
            | "eth_getBlockByNumber"
            | "eth_chainId"
            | "net_version"
            | "eth_getCode"
            | "eth_getTransactionReceipt"
            | "eth_getTransactionByHash"
            | "eth_feeHistory"
    )
}

/// Read-only JSON-RPC for the TRUSTED shell against ANY registered chain (not just
/// the active one). Server-side, so it works on chains whose public RPC doesn't
/// allow browser CORS. Shell-only (capabilities/default.json); read methods only.
#[tauri::command]
async fn node_rpc(
    chain_id: String,
    method: String,
    params: Option<Vec<Value>>,
) -> Result<Value, String> {
    if !is_read_method(&method) {
        return Err(format!("node_rpc: method not allowed: {method}"));
    }
    let chain =
        find_chain(&chain_id).ok_or_else(|| format!("node_rpc: unknown chain {chain_id}"))?;
    node_rpc_call(&chain, &method, &params.unwrap_or_default()).await
}

// ---------------------------------------------------------------------------
// Safe smart-account integration (trusted shell only).
//
// Import is verified against the Safe contract itself (getOwners/getThreshold/
// nonce). Pending transactions and off-chain confirmations use the Safe
// Transaction Service. The service never receives a private key: the selected
// local owner signs the canonical SafeTx EIP-712 digest in Rust or on Ledger,
// after the normal dedicated approval window.
// ---------------------------------------------------------------------------

const SAFE_GET_OWNERS_SELECTOR: &str = "0xa0e67e2b";
const SAFE_GET_THRESHOLD_SELECTOR: &str = "0xe75235b8";
const SAFE_NONCE_SELECTOR: &str = "0xaffed0e0";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SafeInfo {
    address: String,
    chain_id: String,
    owners: Vec<String>,
    threshold: u64,
    /// Kept as an RPC hex quantity so large nonces are never rounded in JS.
    nonce: String,
}

fn decode_abi_bytes(raw: &Value, field: &str) -> Result<Vec<u8>, String> {
    let value = raw
        .as_str()
        .ok_or_else(|| format!("{field}: eth_call did not return hex"))?;
    let body = value
        .strip_prefix("0x")
        .ok_or_else(|| format!("{field}: expected 0x response"))?;
    hex::decode(body).map_err(|e| format!("{field}: malformed ABI response: {e}"))
}

fn word_to_usize(word: &[u8], field: &str) -> Result<usize, String> {
    if word.len() != 32 {
        return Err(format!("{field}: ABI word must be 32 bytes"));
    }
    if word[..24].iter().any(|b| *b != 0) {
        return Err(format!("{field}: ABI integer is too large"));
    }
    let mut tail = [0u8; 8];
    tail.copy_from_slice(&word[24..]);
    usize::try_from(u64::from_be_bytes(tail))
        .map_err(|_| format!("{field}: ABI integer does not fit this platform"))
}

fn decode_abi_uint_u64(raw: &Value, field: &str) -> Result<u64, String> {
    let bytes = decode_abi_bytes(raw, field)?;
    if bytes.len() != 32 || bytes[..24].iter().any(|b| *b != 0) {
        return Err(format!("{field}: expected one uint64-compatible ABI word"));
    }
    let mut tail = [0u8; 8];
    tail.copy_from_slice(&bytes[24..]);
    Ok(u64::from_be_bytes(tail))
}

fn decode_abi_addresses(raw: &Value, field: &str) -> Result<Vec<String>, String> {
    let bytes = decode_abi_bytes(raw, field)?;
    if bytes.len() < 64 {
        return Err(format!("{field}: response is too short"));
    }
    let offset = word_to_usize(&bytes[..32], field)?;
    if offset.checked_add(32).is_none_or(|end| end > bytes.len()) {
        return Err(format!("{field}: invalid array offset"));
    }
    let len = word_to_usize(&bytes[offset..offset + 32], field)?;
    let start = offset + 32;
    let end = start
        .checked_add(
            len.checked_mul(32)
                .ok_or_else(|| format!("{field}: array length overflow"))?,
        )
        .ok_or_else(|| format!("{field}: array length overflow"))?;
    if end > bytes.len() {
        return Err(format!("{field}: truncated address array"));
    }
    let mut owners = Vec::with_capacity(len);
    for i in 0..len {
        let word = &bytes[start + i * 32..start + (i + 1) * 32];
        if word[..12].iter().any(|b| *b != 0) {
            return Err(format!("{field}: malformed address word"));
        }
        owners.push(format!("0x{}", hex::encode(&word[12..])));
    }
    Ok(owners)
}

async fn safe_contract_call(
    chain: &ChainCfg,
    safe_address: &str,
    data: &str,
) -> Result<Value, String> {
    node_rpc_call(
        chain,
        "eth_call",
        &[json!({ "to": safe_address, "data": data }), json!("latest")],
    )
    .await
}

async fn inspect_safe_contract(chain_id: &str, address: &str) -> Result<SafeInfo, String> {
    let address = normalize_evm_address(address)?;
    let chain = find_chain(chain_id).ok_or_else(|| format!("Safe: unknown chain {chain_id}"))?;
    let code = node_rpc_call(&chain, "eth_getCode", &[json!(address), json!("latest")]).await?;
    let code = code
        .as_str()
        .ok_or("Safe: eth_getCode returned a non-string")?;
    if code == "0x" || code == "0x0" {
        return Err(
            "No deployed contract exists at this address on the selected network".to_string(),
        );
    }

    let owners = decode_abi_addresses(
        &safe_contract_call(&chain, &address, SAFE_GET_OWNERS_SELECTOR).await?,
        "Safe.getOwners",
    )?;
    if owners.is_empty() {
        return Err("The contract returned no Safe owners".to_string());
    }
    let threshold = decode_abi_uint_u64(
        &safe_contract_call(&chain, &address, SAFE_GET_THRESHOLD_SELECTOR).await?,
        "Safe.getThreshold",
    )?;
    if threshold == 0 || threshold as usize > owners.len() {
        return Err(format!(
            "Invalid Safe threshold {threshold} for {} owners",
            owners.len()
        ));
    }
    let nonce = safe_contract_call(&chain, &address, SAFE_NONCE_SELECTOR)
        .await?
        .as_str()
        .ok_or("Safe.nonce returned a non-string")?
        .to_string();
    Ok(SafeInfo {
        address,
        chain_id: chain.id,
        owners,
        threshold,
        nonce,
    })
}

#[tauri::command]
async fn inspect_safe(chain_id: String, address: String) -> Result<SafeInfo, String> {
    inspect_safe_contract(&chain_id, &address).await
}

fn safe_service_base_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim().trim_end_matches('/');
    let url = reqwest::Url::parse(trimmed)
        .map_err(|e| format!("Invalid Safe Transaction Service URL: {e}"))?;
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "Safe Transaction Service URL must not contain credentials, query, or fragment"
                .to_string(),
        );
    }
    let local_http =
        url.scheme() == "http" && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    if url.scheme() != "https" && !local_http {
        return Err(
            "Safe Transaction Service URL must use HTTPS (HTTP is allowed only for localhost)"
                .to_string(),
        );
    }
    Ok(trimmed.to_string())
}

fn safe_api_key() -> Option<String> {
    std::env::var("SAFE_API_KEY")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| read_env_file_value("SAFE_API_KEY"))
        .or_else(|| {
            option_env!("SAFE_API_KEY")
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string)
        })
}

fn is_official_safe_service_url(raw: &str) -> bool {
    reqwest::Url::parse(raw)
        .is_ok_and(|url| url.scheme() == "https" && url.host_str() == Some("api.safe.global"))
}

/// Attach the shared Safe Infrastructure key only to Safe's official HTTPS
/// endpoint. A user-supplied/self-hosted Transaction Service must never receive
/// this credential.
fn authorize_safe_request(
    request: reqwest::RequestBuilder,
    endpoint: &str,
) -> reqwest::RequestBuilder {
    if !is_official_safe_service_url(endpoint) {
        return request;
    }
    match safe_api_key() {
        Some(key) => request.bearer_auth(key),
        None => request,
    }
}

async fn response_json(resp: reqwest::Response, context: &str) -> Result<Value, String> {
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("{context}: failed to read response: {e}"))?;
    if !status.is_success() {
        return Err(format!("{context}: HTTP {status}: {text}"));
    }
    serde_json::from_str(&text).map_err(|e| format!("{context}: invalid JSON: {e}"))
}

#[tauri::command]
async fn safe_pending_transactions(
    service_url: String,
    safe_address: String,
) -> Result<Value, String> {
    normalize_evm_address(&safe_address)?;
    let base = safe_service_base_url(&service_url)?;
    let endpoint = format!(
        "{base}/v1/safes/{}/multisig-transactions/?executed=false&trusted=true&ordering=nonce&limit=100",
        safe_address.trim()
    );
    let resp = authorize_safe_request(http().get(&endpoint), &endpoint)
        .send()
        .await
        .map_err(|e| format!("Safe pending transactions request failed: {e}"))?;
    response_json(resp, "Safe pending transactions").await
}

fn safe_tx_value(tx: &Value, field: &str) -> Result<Value, String> {
    tx.get(field)
        .cloned()
        .ok_or_else(|| format!("Safe transaction is missing {field}"))
}

fn safe_tx_string(tx: &Value, field: &str) -> Result<String, String> {
    tx.get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("Safe transaction {field} must be a string"))
}

fn safe_transaction_typed_data(
    chain_id: &str,
    safe_address: &str,
    tx: &Value,
) -> Result<Value, String> {
    let safe_address = normalize_evm_address(safe_address)?;
    let tx_safe = normalize_evm_address(&safe_tx_string(tx, "safe")?)?;
    if tx_safe != safe_address {
        return Err("Safe transaction address does not match the imported Safe".to_string());
    }
    let chain_number = if let Some(hex_id) = chain_id.strip_prefix("0x") {
        Value::String(format!("0x{hex_id}"))
    } else {
        Value::String(chain_id.to_string())
    };
    let data = match tx.get("data") {
        Some(Value::String(value)) => Value::String(value.clone()),
        Some(Value::Null) | None => Value::String("0x".to_string()),
        _ => return Err("Safe transaction data must be hex or null".to_string()),
    };
    Ok(json!({
        "types": {
            "EIP712Domain": [
                { "name": "chainId", "type": "uint256" },
                { "name": "verifyingContract", "type": "address" }
            ],
            "SafeTx": [
                { "name": "to", "type": "address" },
                { "name": "value", "type": "uint256" },
                { "name": "data", "type": "bytes" },
                { "name": "operation", "type": "uint8" },
                { "name": "safeTxGas", "type": "uint256" },
                { "name": "baseGas", "type": "uint256" },
                { "name": "gasPrice", "type": "uint256" },
                { "name": "gasToken", "type": "address" },
                { "name": "refundReceiver", "type": "address" },
                { "name": "nonce", "type": "uint256" }
            ]
        },
        "domain": {
            "chainId": chain_number,
            "verifyingContract": safe_address
        },
        "primaryType": "SafeTx",
        "message": {
            "to": safe_tx_value(tx, "to")?,
            "value": safe_tx_value(tx, "value")?,
            "data": data,
            "operation": safe_tx_value(tx, "operation")?,
            "safeTxGas": safe_tx_value(tx, "safeTxGas")?,
            "baseGas": safe_tx_value(tx, "baseGas")?,
            "gasPrice": safe_tx_value(tx, "gasPrice")?,
            "gasToken": safe_tx_value(tx, "gasToken")?,
            "refundReceiver": safe_tx_value(tx, "refundReceiver")?,
            "nonce": safe_tx_value(tx, "nonce")?
        }
    }))
}

fn safe_tx_already_confirmed(tx: &Value, owner_address: &str) -> bool {
    tx.get("confirmations")
        .and_then(Value::as_array)
        .is_some_and(|confirmations| {
            confirmations.iter().any(|confirmation| {
                confirmation
                    .get("owner")
                    .and_then(Value::as_str)
                    .is_some_and(|owner| owner.eq_ignore_ascii_case(owner_address))
            })
        })
}

#[tauri::command]
async fn safe_confirm_transaction<R: Runtime>(
    app: AppHandle<R>,
    chain_id: String,
    service_url: String,
    safe_address: String,
    owner_address: String,
    transaction: Value,
) -> Result<String, String> {
    let safe_address_normalized = normalize_evm_address(&safe_address)?;
    let owner_address = normalize_evm_address(&owner_address)?;
    let info = inspect_safe_contract(&chain_id, &safe_address_normalized).await?;
    if !info
        .owners
        .iter()
        .any(|owner| owner.eq_ignore_ascii_case(&owner_address))
    {
        return Err(format!(
            "{owner_address} is no longer an owner of this Safe"
        ));
    }
    let signer_kind = signer_kind_for(&owner_address)?;
    if safe_tx_already_confirmed(&transaction, &owner_address) {
        return Err("This local owner has already confirmed the transaction".to_string());
    }

    let typed = safe_transaction_typed_data(&chain_id, &safe_address_normalized, &transaction)?;
    let digest = eip712::signing_hash(&typed)?;
    let calculated_hash = format!("0x{}", hex::encode(digest));
    let advertised_hash = safe_tx_string(&transaction, "safeTxHash")?;
    if !calculated_hash.eq_ignore_ascii_case(&advertised_hash) {
        return Err(format!(
            "Safe transaction hash mismatch: service returned {advertised_hash}, locally calculated {calculated_hash}"
        ));
    }

    let req = PendingRequest {
        id: next_request_id(),
        method: "safe_confirmTransaction".to_string(),
        origin: service_url.clone(),
        signer_address: Some(owner_address.clone()),
        signer_kind: Some(signer_kind_name(&signer_kind).to_string()),
        summary: format!(
            "Confirm Safe transaction\nSafe: {safe_address}\nNonce: {}\nTo: {}",
            transaction
                .get("nonce")
                .map(Value::to_string)
                .unwrap_or_else(|| "?".to_string()),
            transaction.get("to").and_then(Value::as_str).unwrap_or("?")
        ),
        tx: None,
        typed_data: Some(typed.clone()),
    };
    if !request_approval(&app, req).await?.approved {
        return Err("User rejected the Safe confirmation (4001)".to_string());
    }

    let signature = sign_typed_data_for(&owner_address, &typed)?;
    let base = safe_service_base_url(&service_url)?;
    let endpoint = format!("{base}/v1/multisig-transactions/{advertised_hash}/confirmations/");
    let resp = authorize_safe_request(http().post(&endpoint), &endpoint)
        .json(&json!({ "signature": signature }))
        .send()
        .await
        .map_err(|e| format!("Safe confirmation submission failed: {e}"))?;
    response_json(resp, "Safe confirmation submission").await?;
    Ok(signature)
}

const BCS_API_URL: &str = "https://balance-change-simulate-api.wanscan.org/simulate";

#[derive(Debug, Deserialize)]
struct SimulateTxRequest {
    chain_id: u64,
    from: String,
    to: String,
    data: String,
    value: String,
    gas: u64,
}

/// Balance-change simulation for the trusted approval window. This runs through
/// Rust reqwest because the BCS API does not handle browser CORS preflight from
/// the Tauri WebView (`OPTIONS /simulate` returns 405), while the extension's
/// background context can call it with host permissions.
#[tauri::command]
async fn simulate_tx(req: SimulateTxRequest) -> Result<Value, String> {
    let payload = json!({
        "chain_id": req.chain_id,
        "from": req.from,
        "to": req.to,
        "data": req.data,
        "value": req.value,
        "gas": req.gas,
    });
    let resp = http()
        .post(BCS_API_URL)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("simulation request failed: {e}"))?;
    let status = resp.status().as_u16();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("simulation response read failed: {e}"))?;
    let data = if text.is_empty() {
        json!({})
    } else {
        serde_json::from_str::<Value>(&text).unwrap_or_else(|_| json!({ "message": text }))
    };
    Ok(json!({ "ok": (200..300).contains(&status), "status": status, "data": data }))
}

// ---------------------------------------------------------------------------
// Approval flow.
//
// A signing method suspends in `request_approval` until the user decides in the
// dedicated approval window (a separate OS window — the dapp webview renders on
// top of the shell, so an in-shell modal can't cover it). The window's
// approve/reject commands resolve a per-request oneshot channel.
//
// SECURITY: approve_request/reject_request are scoped to the trusted "approval"
// webview only (capabilities/approval.json) — the dapp webview can never reach
// them, so a page cannot self-approve its own signing request.
// ---------------------------------------------------------------------------

/// A pending approval, as shown to the user (no key material, no responder).
#[derive(Debug, Clone, Serialize)]
struct PendingRequest {
    id: String,
    method: String,
    origin: String,
    /// The exact local owner that will sign. Usually this is the active EOA; for
    /// a Safe confirmation it is the Safe's bound local owner while the Safe
    /// contract address remains selected in the main window.
    #[serde(skip_serializing_if = "Option::is_none")]
    signer_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signer_kind: Option<String>,
    /// Human-readable summary of what is being signed (decoded message text).
    summary: String,
    /// For `eth_sendTransaction`: the fully-resolved transaction to display
    /// (gas/nonce/fees filled in), so the approval window can show details and
    /// let the user adjust the fee. `None` for message-signing methods.
    #[serde(skip_serializing_if = "Option::is_none")]
    tx: Option<PreparedTx>,
    /// For `eth_signTypedData_v4`: the full EIP-712 payload, so the approval
    /// window can render every field (spender/amount/deadline…). A summary
    /// alone would make typed-data signing blind signing (permit phishing).
    #[serde(skip_serializing_if = "Option::is_none")]
    typed_data: Option<Value>,
}

/// A transaction with every field resolved from the node (gas/nonce/fees filled),
/// ready to display in the approval window and then sign. All quantities 0x-hex.
#[derive(Debug, Clone, Serialize)]
struct PreparedTx {
    chain_id: String,
    chain_name: String,
    /// Native gas-token symbol (for displaying `value`).
    symbol: String,
    from: String,
    /// "" for contract creation.
    to: String,
    value: String,
    data: String,
    /// Gas limit.
    gas: String,
    nonce: String,
    max_priority_fee_per_gas: String,
    max_fee_per_gas: String,
}

/// The user's decision from the approval window. For `eth_sendTransaction` the
/// window may hand back fee overrides (wei hex) the user typed in.
#[derive(Debug, Clone, Default)]
struct ApprovalDecision {
    approved: bool,
    max_fee_per_gas: Option<String>,
    max_priority_fee_per_gas: Option<String>,
    tx_data: Option<String>,
    balance_changes: Vec<ActivityBalanceChange>,
}

struct PendingEntry {
    req: PendingRequest,
    responder: tokio::sync::oneshot::Sender<ApprovalDecision>,
}

fn pending() -> &'static Mutex<HashMap<String, PendingEntry>> {
    static PENDING: OnceLock<Mutex<HashMap<String, PendingEntry>>> = OnceLock::new();
    PENDING.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_request_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    format!("req-{}", COUNTER.fetch_add(1, Ordering::Relaxed))
}

/// Render a signed message for display: UTF-8 if it's printable text, else hex.
fn preview_message(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) if s.chars().all(|c| !c.is_control() || c == '\n' || c == '\t') => s.to_string(),
        _ => format!("0x{}", hex::encode(bytes)),
    }
}

/// Proof-of-life from the approval window, bumped by every command only that
/// window may call (see capabilities/approval.json). `build()` returning Ok says
/// nothing about whether a window exists — this does.
static APPROVAL_UI_BEAT: AtomicU64 = AtomicU64::new(0);

fn approval_ui_beat() -> u64 {
    APPROVAL_UI_BEAT.load(Ordering::Relaxed)
}

fn note_approval_ui_alive() -> u64 {
    APPROVAL_UI_BEAT.fetch_add(1, Ordering::Relaxed) + 1
}

/// Wait for the approval window's UI to call in, having already registered the
/// request so it has something to show. Fails inside `budget` rather than falling
/// through to the decision timer — a user who sees nothing happen must be told
/// within seconds, not left to guess for five minutes.
async fn wait_for_approval_ui(baseline: u64, budget: Duration) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if approval_ui_beat() > baseline {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "the approval window did not open within {budget:?}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Register a pending request, surface the approval window, and await the user's
/// decision. Errors when the window never comes up; otherwise returns the decision
/// (rejected on the decision timeout).
async fn request_approval<R: Runtime>(
    app: &AppHandle<R>,
    req: PendingRequest,
) -> Result<ApprovalDecision, String> {
    let id = req.id.clone();
    let method = req.method.clone();
    let (tx, rx) = tokio::sync::oneshot::channel::<ApprovalDecision>();
    // Snapshot before registering, so a beat from a window already showing an
    // EARLIER request cannot be mistaken for one that has picked this one up.
    let baseline = approval_ui_beat();
    pending()
        .lock()
        .unwrap()
        .insert(id.clone(), PendingEntry { req, responder: tx });

    emit_request_phase(app, Some(&id), "awaiting-window");
    if let Err(e) = open_approval_window(app) {
        pending().lock().unwrap().remove(&id);
        log_diagnostic(app, format!("approval window build failed id={id} err={e}"));
        return Err(format!("could not open the approval window: {e}"));
    }

    // `WebviewWindowBuilder::build()` only posts a CreateWindow message to the
    // event loop and returns Ok, so it reports success for a window that never
    // appears. Wait for the window's own UI to prove otherwise.
    if wait_for_approval_ui(baseline, APPROVAL_WINDOW_TIMEOUT)
        .await
        .is_err()
    {
        // …unless it was decided inside that window anyway, which leaves nothing
        // registered under this id and a decision already sitting in the channel.
        if pending().lock().unwrap().remove(&id).is_some() {
            log_diagnostic(
                app,
                format!("approval window never reported in id={id} method={method}"),
            );
            close_approval_window_if_idle(app);
            return Err(format!(
                "the approval window did not open within {APPROVAL_WINDOW_TIMEOUT:?} — nothing was signed"
            ));
        }
    }

    log_diagnostic(app, format!("approval window up id={id} method={method}"));
    emit_request_phase(app, Some(&id), "awaiting-approval");
    let decided = tokio::time::timeout(DECISION_TIMEOUT, rx).await;
    pending().lock().unwrap().remove(&id); // no-op if already resolved; cleans up on timeout
    match decided {
        Ok(Ok(decision)) => Ok(decision),
        _ => {
            // Timed out waiting for the user: the window is still sitting there
            // showing a request nobody will answer, so take it down.
            log_diagnostic(app, format!("approval timed out id={id} method={method}"));
            close_approval_window_if_idle(app);
            Ok(ApprovalDecision::default()) // = rejected
        }
    }
}

/// Open (or focus) the dedicated approval window — a separate top-level window
/// loading the shell UI in approval mode. Always-on-top: a signing prompt
/// hidden behind other windows leaves the dApp (and the user) waiting blind
/// until the 300s timeout rejects the request.
fn open_approval_window<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    if let Some(win) = app.get_webview_window("approval") {
        let _ = win.unminimize();
        let _ = win.show();
        let _ = win.set_always_on_top(true);
        // Re-centre on the way back up: the shell may have moved to another
        // monitor since this window was built, and a prompt left behind on the
        // old display is the same invisible-window bug by a slower route.
        place_over_shell(app, &win);
        let _ = win.set_focus();
        return Ok(());
    }
    // Placement and focus are NOT the platform's business here. Left to macOS the
    // window is put wherever the OS likes, which on a multi-monitor desk means a
    // 420x640 prompt can land on a display the user is not looking at — they see
    // nothing, and `always_on_top` only keeps it above its own screen's windows.
    // The reuse branch above always focuses; a freshly built one must too.
    let win = harden_window(
        tauri::WebviewWindowBuilder::new(
            app,
            "approval",
            WebviewUrl::App("index.html?view=approval".into()),
        )
        .title("Confirm request — AutoDesktop")
        .inner_size(420.0, 640.0)
        .resizable(false)
        .always_on_top(true)
        .focused(true)
        .center(),
    )
    .build()?;
    place_over_shell(app, &win);
    let _ = win.set_focus();
    Ok(())
}

/// Centre the approval window on whatever monitor the main window is on. `.center()`
/// alone centres on the *current* monitor as the OS sees it, which is not
/// necessarily the one the user is working on.
fn place_over_shell<R: Runtime>(app: &AppHandle<R>, win: &tauri::WebviewWindow<R>) {
    let Some(main) = app.get_window("main") else {
        return;
    };
    let (Ok(Some(monitor)), Ok(size)) = (main.current_monitor(), win.outer_size()) else {
        return;
    };
    let (x, y) = centered_on_monitor(
        (monitor.position().x, monitor.position().y),
        (monitor.size().width, monitor.size().height),
        (size.width, size.height),
    );
    let _ = win.set_position(tauri::PhysicalPosition::new(x, y));
}

/// Top-left for a window of `size` centred on the monitor at `origin`. Monitor
/// origins are global desktop coordinates and are negative for displays left of
/// or above the primary, so the offset must be added, never assumed to be zero.
fn centered_on_monitor(origin: (i32, i32), monitor: (u32, u32), size: (u32, u32)) -> (i32, i32) {
    let dx = ((monitor.0 as i64 - size.0 as i64) / 2).max(0) as i32;
    let dy = ((monitor.1 as i64 - size.1 as i64) / 2).max(0) as i32;
    (origin.0 + dx, origin.1 + dy)
}

/// Close the approval window once nothing is waiting on it. A window left showing
/// a request that has already been abandoned is worse than no window.
fn close_approval_window_if_idle<R: Runtime>(app: &AppHandle<R>) {
    if !pending().lock().unwrap().is_empty() {
        return;
    }
    if let Some(win) = app.get_webview_window("approval") {
        let _ = win.close();
    }
}

/// Resolve a pending request and close the approval window once nothing is left.
fn resolve_request<R: Runtime>(
    app: &AppHandle<R>,
    id: &str,
    decision: ApprovalDecision,
) -> Result<(), String> {
    let entry = pending()
        .lock()
        .unwrap()
        .remove(id)
        .ok_or_else(|| format!("no pending request {id}"))?;
    let _ = entry.responder.send(decision); // receiver may have timed out; ignore
    close_approval_window_if_idle(app);
    Ok(())
}

/// Tell the shell how far a request has got, so the UI can say what it is waiting
/// for instead of claiming "confirm in window" before any window exists.
fn emit_request_phase<R: Runtime>(app: &AppHandle<R>, id: Option<&str>, phase: &str) {
    // `id` is genuinely absent before a request is registered and after it is
    // resolved, so it is null there rather than an empty string standing in.
    let _ = app.emit("wallet-request-phase", json!({ "id": id, "phase": phase }));
}

fn is_evm_address(s: &str) -> bool {
    normalize_evm_address(s).is_ok() && s.trim().len() == 42
}

/// Split personal_sign params into (message, named account). The standard order
/// is [message, address]; some older dApps send [address, message], which we
/// accept only when exactly the first param is an address.
fn personal_sign_params(params: &[Value]) -> Result<(&Value, Option<&str>), String> {
    let first = params.first().ok_or("personal_sign: missing message param")?;
    let second = params.get(1);
    match (first.as_str(), second.and_then(Value::as_str)) {
        (Some(a), Some(b)) if is_evm_address(a) && !is_evm_address(b) => {
            Ok((second.expect("matched Some above"), Some(a)))
        }
        _ => match second {
            None | Some(Value::Null) => Ok((first, None)),
            Some(v) => {
                let named = v
                    .as_str()
                    .ok_or("personal_sign: the address param must be a string")?;
                Ok((first, Some(named)))
            }
        },
    }
}

/// The account a dApp names in a signing request must be the one that signs.
fn ensure_named_account(method: &str, named: &str, signer: &str) -> Result<(), String> {
    let named = normalize_evm_address(named)?;
    if named != signer {
        return Err(format!(
            "{method}: {named} is not the selected account ({signer}) (code 4100)"
        ));
    }
    Ok(())
}

/// Drive a signing method through the approval flow. `personal_sign` and
/// `eth_sendTransaction` are wired; other signing methods are rejected up-front
/// (no point opening an approval window for something we can't yet fulfill).
async fn handle_signing<R: Runtime>(
    app: &AppHandle<R>,
    method: &str,
    params: &[Value],
    origin: &str,
    webview_label: &str,
) -> Result<Value, String> {
    // Refuse before opening an approval window if there's no key to sign with —
    // otherwise the user would approve a request we can't fulfill.
    if active_account_address().is_none() {
        return Err("wallet is locked".to_string());
    }
    if matches!(
        exposed_account_state().lock().unwrap().as_ref(),
        Some(ExposedAccount::WatchOnly(_))
    ) {
        return Err(
            "the selected account cannot sign direct EIP-1193 requests; Safe transactions must be confirmed from the Safe queue"
                .to_string(),
        );
    }

    match method {
        "personal_sign" => {
            let (message_param, named) = personal_sign_params(params)?;
            let message = decode_message_param(message_param)?;
            ensure_signing_webview_is_active(webview_label)?;
            // Pin the signer now: this is the account the approval window shows,
            // and the one that signs, whatever is active when the user approves.
            let signer = active_account_address().ok_or("wallet is locked")?;
            if let Some(named) = named {
                ensure_named_account(method, named, &signer)?;
            }
            let req = PendingRequest {
                id: next_request_id(),
                method: method.to_string(),
                origin: origin.to_string(),
                signer_address: Some(signer.clone()),
                signer_kind: signer_kind_for(&signer)
                    .ok()
                    .map(|kind| signer_kind_name(&kind).to_string()),
                summary: preview_message(&message),
                tx: None,
                typed_data: None,
            };
            if request_approval(app, req).await?.approved {
                personal_sign_for(&signer, &message)
            } else {
                Err("User rejected the request (4001)".to_string())
            }
        }
        "eth_sendTransaction" => {
            let tx = params
                .first()
                .ok_or("eth_sendTransaction: missing transaction param")?
                .clone();
            ensure_signing_webview_is_active(webview_label)?;
            let chain_id = current_chain().lock().unwrap().clone();
            approve_and_send(app, &chain_id, origin, &tx).await
        }
        "eth_signTypedData_v4" => {
            // Params are [address, typedData]; the typed data is usually a JSON
            // string, occasionally an object.
            let signer = active_account_address().ok_or("wallet is locked")?;
            let named = params
                .first()
                .and_then(Value::as_str)
                .ok_or("eth_signTypedData_v4: missing address param")?;
            ensure_named_account(method, named, &signer)?;
            let raw = params
                .get(1)
                .ok_or("eth_signTypedData_v4: missing typed-data param")?;
            let typed: Value = match raw {
                Value::String(s) => serde_json::from_str(s)
                    .map_err(|e| format!("eth_signTypedData_v4: invalid typed-data JSON: {e}"))?,
                other => other.clone(),
            };
            // Surface obvious structural errors BEFORE prompting (e.g. unknown type).
            eip712::signing_hash(&typed)?;
            ensure_signing_webview_is_active(webview_label)?;
            let req = PendingRequest {
                id: next_request_id(),
                method: method.to_string(),
                origin: origin.to_string(),
                signer_address: Some(signer.clone()),
                signer_kind: signer_kind_for(&signer)
                    .ok()
                    .map(|kind| signer_kind_name(&kind).to_string()),
                summary: preview_typed_data(&typed),
                tx: None,
                typed_data: Some(typed.clone()),
            };
            if request_approval(app, req).await?.approved {
                sign_typed_data_for(&signer, &typed).map(Value::String)
            } else {
                Err("User rejected the request (4001)".to_string())
            }
        }
        other => Err(format!(
            "{other} not implemented yet (signing lands incrementally)"
        )),
    }
}

/// Sign EIP-712 typed data with a specific account → 65-byte r‖s‖v hex, without
/// touching the app's active/dApp-visible account. A software account signs the
/// 0x1901 digest locally; a Ledger is sent the domain separator + message hash.
/// Used for dApp typed data (signer pinned at request time) and Safe owners.
fn sign_typed_data_for(address: &str, typed: &Value) -> Result<String, String> {
    let sig = match signer_kind_for(address)? {
        ActiveKind::Local => {
            let digest = eip712::signing_hash(typed)?;
            let (signature, recovery_id) =
                with_key_for(address, |k| k.sign_prehash_recoverable(&digest))?
                    .map_err(|e| format!("typed-data signing failed: {e}"))?;
            let mut sig = signature.to_bytes().to_vec();
            sig.push(27 + recovery_id.to_byte());
            sig
        }
        ActiveKind::Ledger(path) => {
            let (domain_separator, message_hash) = eip712::domain_and_message_hash(typed)?;
            ledger::sign_eip712(&path, &domain_separator, &message_hash)?.to_vec()
        }
    };
    Ok(format!("0x{}", hex::encode(sig)))
}

/// A human-readable summary of typed data for the approval window.
fn preview_typed_data(typed: &Value) -> String {
    let primary = typed
        .get("primaryType")
        .and_then(|v| v.as_str())
        .unwrap_or("typed data");
    let domain = typed
        .get("domain")
        .and_then(|d| d.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if domain.is_empty() {
        format!("Sign typed data ({primary})")
    } else {
        format!("Sign {primary} for {domain}")
    }
}

/// Every transaction field we read must be a string when present. `tx_field`
/// reads only strings, so a number or array would otherwise be taken as absent
/// and replaced by its default — `value: 1000` becoming 0, or a non-string `to`
/// turning a transfer into a contract deployment. `to: null` is the one allowed
/// non-string: it is how a deployment is spelled.
fn validate_tx_field_types(tx: &Value) -> Result<(), String> {
    let obj = tx
        .as_object()
        .ok_or("eth_sendTransaction: the transaction must be an object")?;
    for field in [
        "from",
        "to",
        "value",
        "data",
        "input",
        "gas",
        "nonce",
        "gasPrice",
        "maxFeePerGas",
        "maxPriorityFeePerGas",
    ] {
        match obj.get(field) {
            None | Some(Value::String(_)) => {}
            Some(Value::Null) if field == "to" => {}
            Some(other) => {
                return Err(format!(
                    "eth_sendTransaction: '{field}' must be a 0x-hex string, got {other}"
                ))
            }
        }
    }
    if let Some(to) = obj.get("to").and_then(Value::as_str) {
        if !to.is_empty() && to != "0x" && !is_evm_address(to) {
            return Err(format!("eth_sendTransaction: 'to' is not an address: {to}"));
        }
    }
    Ok(())
}

/// Pull a string field from the dApp's transaction object.
fn tx_field<'a>(tx: &'a Value, key: &str) -> Option<&'a str> {
    tx.get(key).and_then(|v| v.as_str())
}

/// Parse a 0x-hex quantity to u128 (used only for the fee arithmetic + summary).
fn hex_to_u128(hex: &str) -> Result<u128, String> {
    let s = hex.strip_prefix("0x").unwrap_or(hex);
    u128::from_str_radix(if s.is_empty() { "0" } else { s }, 16)
        .map_err(|e| format!("bad quantity {hex}: {e}"))
}

fn is_nonzero_quantity(hex: &str) -> bool {
    hex_to_u128(hex).map(|value| value > 0).unwrap_or(false)
}

fn resolve_provided_fees(tx: &Value) -> Option<(String, String)> {
    if let (Some(prio), Some(max)) = (
        tx_field(tx, "maxPriorityFeePerGas"),
        tx_field(tx, "maxFeePerGas"),
    ) {
        if is_nonzero_quantity(max) {
            return Some((prio.to_string(), max.to_string()));
        }
    }
    tx_field(tx, "gasPrice").and_then(|gas_price| {
        if !is_nonzero_quantity(gas_price) {
            return None;
        }
        let fee = gas_price.to_string();
        Some((fee.clone(), fee))
    })
}

fn bump_estimated_gas(gas: &str) -> Result<String, String> {
    let value = hex_to_u128(gas)?;
    // Add a 20% safety margin to node gas estimates. Some contracts pass
    // estimation but still run out of gas at execution with the exact value.
    let margin = value.saturating_add(4) / 5;
    Ok(format!("0x{:x}", value.saturating_add(margin)))
}

/// A human-readable summary of a transaction for the approval window. Display
/// only — `prepare_tx` resolves the real fields and `finalize_tx` signs them.
fn preview_tx(tx: &Value, symbol: &str) -> String {
    let to = tx_field(tx, "to").unwrap_or("new contract");
    let short_to = if to.len() > 12 {
        format!("{}…{}", &to[..6], &to[to.len() - 4..])
    } else {
        to.to_string()
    };
    let amount = hex_to_u128(tx_field(tx, "value").unwrap_or("0x0")).unwrap_or(0) as f64 / 1e18;
    let has_data = tx_field(tx, "data")
        .or_else(|| tx_field(tx, "input"))
        .map_or(false, |d| d.len() > 2);
    if has_data {
        format!("Contract interaction → {short_to} ({amount:.4} {symbol})")
    } else {
        format!("Send {amount:.4} {symbol} → {short_to}")
    }
}

/// Resolve the EIP-1559 fee fields on a specific chain: use the caller's if both
/// EIP-1559 values are given, map legacy `gasPrice` to an equivalent type-2 cap,
/// else suggest `maxPriorityFeePerGas` from the node (1 gwei fallback) and
/// `maxFeePerGas = 2*baseFee + priority` from the pending block's base fee.
async fn resolve_fees_on(chain: &ChainCfg, tx: &Value) -> Result<(String, String), String> {
    if let Some(fees) = resolve_provided_fees(tx) {
        return Ok(fees);
    }
    let priority = match node_rpc_call(chain, "eth_maxPriorityFeePerGas", &[]).await {
        Ok(v) => v
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| "0x3b9aca00".into()),
        Err(_) => "0x3b9aca00".to_string(), // 1 gwei
    };
    let priority_wei = hex_to_u128(&priority)?;
    let block = node_rpc_call(
        chain,
        "eth_getBlockByNumber",
        &[json!("pending"), json!(false)],
    )
    .await?;
    let base_wei = block
        .get("baseFeePerGas")
        .and_then(|v| v.as_str())
        .ok_or("chain has no baseFeePerGas (pre-EIP-1559 chain not supported)")?;
    let base_wei = hex_to_u128(base_wei)?;
    let max_fee = base_wei.saturating_mul(2).saturating_add(priority_wei);
    Ok((format!("0x{priority_wei:x}"), format!("0x{max_fee:x}")))
}

/// Resolve a transaction on `chain_id`: validate `from`, then fill any missing
/// nonce / gas / fees from the node. Pure preparation — no signing, no broadcast —
/// so the approval window can show the user exactly what they're about to sign.
///
/// Bounded by `TX_PREPARE_TIMEOUT`: this runs BEFORE the approval window, so every
/// second spent here is a second the user stares at a Send button that has not yet
/// produced a window.
async fn prepare_tx(chain_id: &str, tx: &Value) -> Result<PreparedTx, String> {
    let chain =
        find_chain(chain_id).ok_or_else(|| format!("no RPC configured for chain {chain_id}"))?;
    prepare_tx_within(&chain, tx, TX_PREPARE_TIMEOUT).await
}

async fn prepare_tx_within(
    chain: &ChainCfg,
    tx: &Value,
    budget: Duration,
) -> Result<PreparedTx, String> {
    tokio::time::timeout(budget, prepare_tx_on(chain, tx))
        .await
        .unwrap_or_else(|_| {
            Err(format!(
                "{} did not answer within {budget:?} — the transaction was not prepared",
                chain.name
            ))
        })
}

async fn prepare_tx_on(chain: &ChainCfg, tx: &Value) -> Result<PreparedTx, String> {
    let chain = chain.clone();
    let from = active_account_address().ok_or("wallet is locked")?;
    if let Some(req_from) = tx_field(tx, "from") {
        if !req_from.eq_ignore_ascii_case(&from) {
            return Err(format!(
                "transaction 'from' {req_from} is not the active account {from}"
            ));
        }
    }

    let to = tx_field(tx, "to").unwrap_or("").to_string();
    let value = tx_field(tx, "value").unwrap_or("0x0").to_string();
    let data = tx_field(tx, "data")
        .or_else(|| tx_field(tx, "input"))
        .unwrap_or("0x")
        .to_string();

    let nonce = match tx_field(tx, "nonce") {
        Some(n) => n.to_string(),
        None => node_rpc_call(
            &chain,
            "eth_getTransactionCount",
            &[json!(from), json!("pending")],
        )
        .await?
        .as_str()
        .ok_or("node returned a non-string nonce")?
        .to_string(),
    };

    let gas = match tx_field(tx, "gas") {
        Some(g) => g.to_string(),
        None => {
            let call = json!({ "from": from, "to": to, "value": value, "data": data });
            let estimate = node_rpc_call(&chain, "eth_estimateGas", &[call])
                .await?
                .as_str()
                .ok_or("node returned a non-string gas estimate")?
                .to_string();
            bump_estimated_gas(&estimate)?
        }
    };

    let (priority, max_fee) = resolve_fees_on(&chain, tx).await?;

    Ok(PreparedTx {
        chain_id: chain.id,
        chain_name: chain.name,
        symbol: chain.symbol,
        from,
        to,
        value,
        data,
        gas,
        nonce,
        max_priority_fee_per_gas: priority,
        max_fee_per_gas: max_fee,
    })
}

/// Mark the transaction a speed-up/cancel replaces as retired, and say whether
/// anything changed.
///
/// ONLY a broadcast the node acknowledged retires the original. On an unconfirmed
/// broadcast we do not know the replacement was accepted, and the two carry the
/// same nonce — so the original stays pending and whichever mines settles it.
/// Retiring it early hides a transaction that is still live.
fn retire_original(records: &mut [ActivityRecord], id: &str, sent: &Broadcast) -> bool {
    if sent.broadcast_error.is_some() {
        return false;
    }
    match records.iter_mut().find(|r| r.id == id) {
        Some(old) => {
            old.status = Some("replaced".to_string());
            true
        }
        None => false,
    }
}

/// The outcome of signing + broadcasting. `hash` is what the caller reports and
/// records; `broadcast_error` is set when the node never confirmed the broadcast,
/// in which case the hash is the one computed locally from the signed bytes —
/// the transaction is signed and may well be in flight, so it still gets recorded
/// and polled for a receipt rather than vanishing.
struct Broadcast {
    hash: String,
    broadcast_error: Option<String>,
}

/// Sign (Rust-side software key, or on the Ledger) and broadcast a fully-prepared
/// EIP-1559 transaction.
async fn finalize_tx(p: &PreparedTx) -> Result<Broadcast, String> {
    finalize_tx_within(p, BROADCAST_TIMEOUT).await
}

async fn finalize_tx_within(p: &PreparedTx, budget: Duration) -> Result<Broadcast, String> {
    use eth_tx::{parse_address, parse_data, parse_quantity, Eip1559Tx};

    let chain = find_chain(&p.chain_id)
        .ok_or_else(|| format!("no RPC configured for chain {}", p.chain_id))?;

    let tx1559 = Eip1559Tx {
        chain_id: parse_quantity(&p.chain_id)?,
        nonce: parse_quantity(&p.nonce)?,
        max_priority_fee_per_gas: parse_quantity(&p.max_priority_fee_per_gas)?,
        max_fee_per_gas: parse_quantity(&p.max_fee_per_gas)?,
        gas_limit: parse_quantity(&p.gas)?,
        to: parse_address(&p.to)?,
        value: parse_quantity(&p.value)?,
        data: parse_data(&p.data)?,
    };

    // Sign Rust-side (software) or on the device (Ledger) — never in a webview.
    // The key is looked up by `p.from` — the account the approval window showed
    // and whose nonce was prepared — never by whatever is active right now.
    let (raw_tx, local_hash) = match signer_kind_for(&p.from)? {
        ActiveKind::Local => with_key_for(&p.from, |k| tx1559.sign(k))??,
        ActiveKind::Ledger(path) => {
            let (r, s, y_parity) = ledger::sign_transaction(&path, &tx1559.unsigned_payload())?;
            tx1559.into_signed(&r, &s, y_parity)
        }
    };
    // Broadcast; the node echoes the canonical transaction hash.
    match node_rpc_try(&chain, "eth_sendRawTransaction", &[json!(raw_tx)], budget).await {
        Ok(v) => Ok(Broadcast {
            hash: v
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| local_hash.clone()),
            broadcast_error: None,
        }),
        // The node read the transaction and refused it (bad nonce, underpriced,
        // insufficient funds). Nothing is in flight, so this is a plain failure —
        // recording it as a pending transfer would invent one.
        Err(RpcFailure::Rejected(msg)) => Err(msg),
        // No answer AFTER we handed over signed bytes. The node may well have
        // taken it — that is how a mined transfer once went unrecorded — so report
        // the locally computed hash and let the receipt poller settle it.
        Err(RpcFailure::Unreachable(msg)) => Ok(Broadcast {
            hash: local_hash,
            broadcast_error: Some(msg),
        }),
    }
}

/// The shared eth_sendTransaction path: resolve the tx, ask the user (showing full
/// details + an editable fee), apply any fee override, then sign + broadcast. Used
/// by both a dApp's `eth_sendTransaction` and the wallet's own Send.
async fn approve_and_send<R: Runtime>(
    app: &AppHandle<R>,
    chain_id: &str,
    origin: &str,
    tx: &Value,
) -> Result<Value, String> {
    validate_tx_field_types(tx)?;
    ensure_tx_chain_id_matches(tx, chain_id)?;
    emit_request_phase(app, None, "preparing");
    let prepared = prepare_tx(chain_id, tx).await.inspect_err(|e| {
        log_diagnostic(app, format!("send prepare failed chain={chain_id} err={e}"));
    })?;
    let req = PendingRequest {
        id: next_request_id(),
        method: "eth_sendTransaction".to_string(),
        origin: origin.to_string(),
        signer_address: Some(prepared.from.clone()),
        signer_kind: signer_kind_for(&prepared.from)
            .ok()
            .map(|kind| signer_kind_name(&kind).to_string()),
        summary: preview_tx(tx, &prepared.symbol),
        tx: Some(prepared.clone()),
        typed_data: None,
    };

    let decision = request_approval(app, req).await?;
    if !decision.approved {
        return Err("User rejected the request (4001)".to_string());
    }

    let mut p = prepared;
    if let Some(mf) = decision.max_fee_per_gas {
        p.max_fee_per_gas = mf;
    }
    if let Some(mp) = decision.max_priority_fee_per_gas {
        p.max_priority_fee_per_gas = mp;
    }
    if let Some(data) = decision.tx_data {
        p.data = data;
    }
    // Keep priority ≤ max fee even if the user lowered the cap below it.
    if hex_to_u128(&p.max_priority_fee_per_gas).unwrap_or(0)
        > hex_to_u128(&p.max_fee_per_gas).unwrap_or(u128::MAX)
    {
        p.max_priority_fee_per_gas = p.max_fee_per_gas.clone();
    }
    emit_request_phase(app, None, "broadcasting");
    let sent = finalize_tx(&p).await?;
    record_activity(app, &p, origin, &sent, tx, decision.balance_changes);
    log_diagnostic(
        app,
        format!(
            "send broadcast chain={} nonce={} hash={} error={}",
            p.chain_id,
            p.nonce,
            sent.hash,
            sent.broadcast_error.as_deref().unwrap_or("none")
        ),
    );
    // The hash goes back either way. A signed transaction we could not get
    // acknowledged is NOT a failed request: EIP-1193 says eth_sendTransaction
    // returns the hash once the wallet has one, and answering a dApp with an error
    // invites it to offer Retry — which, if the first broadcast did land, sends the
    // money twice. The ambiguity travels as `activity-unconfirmed` instead, which
    // the shell shows as a warning while the receipt poller settles it.
    Ok(json!(sent.hash))
}

/// Wallet-initiated send (shell-only): same approval + sign + broadcast path as a
/// dApp's eth_sendTransaction, so the user confirms in the approval window with the
/// full gas/nonce details. `tx` is `{ to, value?, data? }`; native sends set
/// `value`, ERC-20 sends set `to`=token + `data`=transfer(...).
#[tauri::command]
async fn wallet_send<R: Runtime>(
    app: AppHandle<R>,
    chain_id: String,
    tx: Value,
) -> Result<Value, String> {
    if active_account_address().is_none() {
        return Err("wallet is locked".to_string());
    }
    find_chain(&chain_id).ok_or_else(|| format!("wallet_send: unknown chain {chain_id}"))?;
    approve_and_send(&app, &chain_id, "AutoDesktop Wallet", &tx).await
}

// ---------------------------------------------------------------------------
// Connected sites (EIP-2255 `eth_accounts` permission, per origin).
//
// A site learns the address, may ask for signatures, and may switch the wallet's
// network ONLY after the user approved a connection for its origin. Origins come
// from the engine-set webview URL (see `wallet_request`), never from the page.
// ---------------------------------------------------------------------------

const CONNECTED_SITES_FILE: &str = "connected-sites.json";

fn connected_sites() -> &'static Mutex<HashSet<String>> {
    static SITES: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    SITES.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Origins with a connection prompt already on screen. A dApp that asks twice
/// gets -32002 (as MetaMask answers) instead of a second prompt.
fn connecting_sites() -> &'static Mutex<HashSet<String>> {
    static SITES: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    SITES.get_or_init(|| Mutex::new(HashSet::new()))
}

fn is_site_connected(origin: &str) -> bool {
    connected_sites().lock().unwrap().contains(origin)
}

fn ensure_site_connected(origin: &str) -> Result<(), String> {
    if is_site_connected(origin) {
        Ok(())
    } else {
        Err(format!(
            "{origin} is not connected to AutoDesktop — call eth_requestAccounts first (4100)"
        ))
    }
}

fn connected_sites_path<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    // Tests must never write into the real user's app data dir.
    #[cfg(test)]
    {
        let _ = app;
        return Ok(std::env::temp_dir().join(format!(
            "autodesktop-test-{}-{CONNECTED_SITES_FILE}",
            std::process::id()
        )));
    }
    #[cfg(not(test))]
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join(CONNECTED_SITES_FILE))
}

/// Load the persisted connections at startup. A missing file means nothing is
/// connected; an unreadable one is logged and also treated as nothing connected
/// (the safe side: sites simply ask again).
fn load_connected_sites<R: Runtime>(app: &AppHandle<R>) {
    let path = match connected_sites_path(app) {
        Ok(path) => path,
        Err(e) => {
            log_diagnostic(app, format!("connected sites path unavailable: {e}"));
            return;
        }
    };
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            log_diagnostic(app, format!("reading {}: {e}", path.display()));
            return;
        }
    };
    match serde_json::from_slice::<Vec<String>>(&bytes) {
        Ok(list) => *connected_sites().lock().unwrap() = list.into_iter().collect(),
        Err(e) => log_diagnostic(app, format!("parsing {}: {e}", path.display())),
    }
}

fn save_connected_sites<R: Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    let path = connected_sites_path(app)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut list: Vec<String> = connected_sites().lock().unwrap().iter().cloned().collect();
    list.sort();
    let json = serde_json::to_vec_pretty(&list).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| format!("writing connected sites: {e}"))
}

fn connect_site<R: Runtime>(app: &AppHandle<R>, origin: &str) -> Result<(), String> {
    connected_sites().lock().unwrap().insert(origin.to_string());
    save_connected_sites(app)?;
    let _ = app.emit("connected-sites-changed", ());
    Ok(())
}

/// Forget a site's connection and tell its open tabs they no longer see an account.
fn disconnect_site<R: Runtime>(app: &AppHandle<R>, origin: &str) -> Result<(), String> {
    connected_sites().lock().unwrap().remove(origin);
    save_connected_sites(app)?;
    let js = "window.__autoWalletPush && window.__autoWalletPush('accountsChanged', []);";
    for (label, webview) in app.webviews() {
        if label.starts_with("dapp-") && webview_origin(&webview).as_deref() == Some(origin) {
            let _ = webview.eval(js);
        }
    }
    let _ = app.emit("connected-sites-changed", ());
    Ok(())
}

fn webview_origin<R: Runtime>(webview: &tauri::Webview<R>) -> Option<String> {
    webview
        .url()
        .ok()
        .map(|url| url.origin().ascii_serialization())
}

/// Ask the user to connect `origin`. Only the active tab may ask, and only while
/// an account is available to show.
async fn request_site_connection<R: Runtime>(
    app: &AppHandle<R>,
    origin: &str,
    webview_label: &str,
) -> Result<(), String> {
    ensure_signing_webview_is_active(webview_label)?;
    let account = dapp_account_address()
        .ok_or("the wallet is locked — unlock AutoDesktop, then connect again (4100)")?;
    if !connecting_sites().lock().unwrap().insert(origin.to_string()) {
        return Err(format!(
            "a connection request from {origin} is already pending (code -32002)"
        ));
    }
    let req = PendingRequest {
        id: next_request_id(),
        method: "eth_requestAccounts".to_string(),
        origin: origin.to_string(),
        signer_address: Some(account.clone()),
        signer_kind: signer_kind_for(&account)
            .ok()
            .map(|kind| signer_kind_name(&kind).to_string()),
        summary: format!("{origin} wants to see your address {account}"),
        tx: None,
        typed_data: None,
    };
    let decision = request_approval(app, req).await;
    connecting_sites().lock().unwrap().remove(origin);
    if !decision?.approved {
        return Err("User rejected the connection request (4001)".to_string());
    }
    connect_site(app, origin)
}

/// Connected sites, sorted, for Settings. Shell-only.
#[tauri::command]
fn get_connected_sites() -> Vec<String> {
    let mut list: Vec<String> = connected_sites().lock().unwrap().iter().cloned().collect();
    list.sort();
    list
}

/// Disconnect a site from Settings. Shell-only.
#[tauri::command]
fn disconnect_connected_site<R: Runtime>(app: AppHandle<R>, origin: String) -> Result<(), String> {
    disconnect_site(&app, &origin)
}

/// The single wallet backend entry point. `origin` is the trustworthy caller
/// origin derived from the webview context (see `wallet_request`).
async fn handle_rpc<R: Runtime>(
    app: &AppHandle<R>,
    method: &str,
    params: &[Value],
    origin: &str,
    webview_label: &str,
) -> Result<Value, String> {
    println!("[AutoDesktop] rpc  method={method}  origin={origin}");
    match route_method(method) {
        Route::Wallet => {
            match method {
                "eth_requestAccounts" | "wallet_requestPermissions"
                    if !is_site_connected(origin) =>
                {
                    request_site_connection(app, origin, webview_label).await?;
                }
                // Switching is global: it moves the wallet UI and every other tab.
                "wallet_switchEthereumChain" | "wallet_addEthereumChain" => {
                    ensure_site_connected(origin)?;
                    ensure_signing_webview_is_active(webview_label)?;
                }
                "wallet_getPermissions" if !is_site_connected(origin) => {
                    return Ok(json!([]));
                }
                "wallet_revokePermissions" => {
                    disconnect_site(app, origin)?;
                    return Ok(Value::Null);
                }
                _ => {}
            }
            let current = current_chain().lock().unwrap().clone();
            let account = if is_site_connected(origin) {
                dapp_account_address()
            } else {
                None
            };
            match handle_wallet_method(method, params, &current, account.as_deref())? {
                WalletOutcome::Reply(v) => Ok(v),
                WalletOutcome::SwitchChain(new_id) => {
                    *current_chain().lock().unwrap() = new_id.clone();
                    println!("[AutoDesktop] switched chain -> {new_id}");
                    // A dApp switched the network: make the wallet UI (shell) follow
                    // (event the activeChain store listens for), and re-push
                    // chainChanged to every dApp tab so they all agree.
                    let _ = app.emit("active-chain-changed", new_id.clone());
                    push_chain_changed(app, &new_id);
                    Ok(Value::Null) // EIP-3326: null on success
                }
                WalletOutcome::AddChain(chain) => {
                    let new_id = chain.id.clone();
                    let summary = format!(
                        "Network: {}\nChain ID: {}\nRPC: {}\nCurrency: {}",
                        chain.name, chain.id, chain.rpc, chain.symbol
                    );
                    let req = PendingRequest {
                        id: next_request_id(),
                        method: "wallet_addEthereumChain".to_string(),
                        origin: origin.to_string(),
                        signer_address: None,
                        signer_kind: None,
                        summary,
                        tx: None,
                        typed_data: None,
                    };
                    if !request_approval(app, req).await?.approved {
                        return Err("User rejected adding the network (code 4001)".to_string());
                    }
                    {
                        let mut chains = chains_state().lock().unwrap();
                        if !chains.iter().any(|c| c.id.eq_ignore_ascii_case(&new_id)) {
                            chains.push(chain);
                        }
                    }
                    save_chains(app)?;
                    println!("[AutoDesktop] dApp added chain -> {new_id}");
                    // Refresh the shell's network list, then switch to the new chain.
                    let _ = app.emit("chains-changed", ());
                    *current_chain().lock().unwrap() = new_id.clone();
                    let _ = app.emit("active-chain-changed", new_id.clone());
                    push_chain_changed(app, &new_id);
                    Ok(Value::Null) // EIP-3085: null on success
                }
            }
        }
        Route::Signing => {
            ensure_site_connected(origin)?;
            handle_signing(app, method, params, origin, webview_label).await
        }
        Route::Forward => {
            if !is_forwardable_method(method) {
                return Err(format!(
                    "The method \"{method}\" is not supported by AutoDesktop (code 4200)"
                ));
            }
            forward_to_node(method, params).await
        }
    }
}

/// Approve a pending request. Scoped to the "approval" webview (ACL). For a
/// transaction the window may pass fee overrides (wei hex) the user typed in;
/// they're absent (None) for message signing or an unchanged fee.
#[tauri::command]
fn approve_request<R: Runtime>(
    app: AppHandle<R>,
    id: String,
    max_fee_per_gas: Option<String>,
    max_priority_fee_per_gas: Option<String>,
    tx_data: Option<String>,
    balance_changes: Option<Vec<ActivityBalanceChange>>,
) -> Result<(), String> {
    note_approval_ui_alive(); // proof the window is up, same as get_pending_requests
    resolve_request(
        &app,
        &id,
        ApprovalDecision {
            approved: true,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            tx_data,
            balance_changes: balance_changes.unwrap_or_default(),
        },
    )
}

/// Reject a pending request. Scoped to the "approval" webview (ACL).
#[tauri::command]
fn reject_request<R: Runtime>(app: AppHandle<R>, id: String) -> Result<(), String> {
    note_approval_ui_alive();
    resolve_request(
        &app,
        &id,
        ApprovalDecision {
            approved: false,
            ..Default::default()
        },
    )
}

/// List requests awaiting approval, for the approval window to render.
#[tauri::command]
fn get_pending_requests() -> Vec<PendingRequest> {
    note_approval_ui_alive(); // only the approval window may call this (ACL)
    pending()
        .lock()
        .unwrap()
        .values()
        .map(|e| e.req.clone())
        .collect()
}

/// Local IPC command — the entire attack surface exposed to untrusted dApps
/// (capabilities/dapp.json grants only this command).
///
/// SECURITY: the caller origin is derived from the `webview` that actually sent
/// the IPC (engine-set, unforgeable), NOT from a JS-supplied parameter. This is
/// the fix for the spike TODO where `handle_rpc` trusted a page-sent origin.
#[tauri::command]
async fn wallet_request<R: tauri::Runtime>(
    webview: tauri::Webview<R>,
    method: String,
    params: Option<Vec<Value>>,
) -> Result<Value, String> {
    note_activity(); // a dApp in use keeps the wallet unlocked
    let origin = match webview.url() {
        Ok(url) => url.origin().ascii_serialization(),
        // No page URL yet — fall back to the (still engine-set) webview label,
        // never to anything the page could control.
        Err(_) => format!("webview://{}", webview.label()),
    };
    let app = webview.app_handle().clone();
    handle_rpc(
        &app,
        &method,
        &params.unwrap_or_default(),
        &origin,
        webview.label(),
    )
    .await
}

// ---------------------------------------------------------------------------
// dApp JavaScript dialog bridge.
//
// Remote WKWebView child pages do not reliably show native alert/confirm/prompt
// sheets. The injected script replaces those APIs with this narrow command; Rust
// derives the origin from the calling webview, forwards a display-only request to
// the trusted shell, then waits briefly for the shell overlay to resolve it.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
struct DappDialogRequest {
    id: String,
    kind: String,
    origin: String,
    message: String,
    default_value: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct DappDialogResult {
    action: String,
    value: Option<String>,
}

fn dapp_dialog_pending(
) -> &'static Mutex<HashMap<String, tokio::sync::oneshot::Sender<DappDialogResult>>> {
    static PENDING: OnceLock<
        Mutex<HashMap<String, tokio::sync::oneshot::Sender<DappDialogResult>>>,
    > = OnceLock::new();
    PENDING.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Labels of dApp tabs that have a dialog on screen — one per tab at a time.
fn dapp_dialog_owners() -> &'static Mutex<HashSet<String>> {
    static OWNERS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    OWNERS.get_or_init(|| Mutex::new(HashSet::new()))
}

fn next_dapp_dialog_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    format!("dlg-{}", COUNTER.fetch_add(1, Ordering::Relaxed))
}

#[tauri::command]
async fn dapp_dialog<R: tauri::Runtime>(
    webview: tauri::Webview<R>,
    kind: String,
    message: String,
    default_value: Option<String>,
) -> Result<DappDialogResult, String> {
    if !matches!(kind.as_str(), "alert" | "confirm" | "prompt" | "print") {
        return Err(format!("dapp_dialog: unsupported kind {kind:?}"));
    }
    // A background tab's dialog would sit over the visible site and look as if
    // it came from there.
    ensure_signing_webview_is_active(webview.label())?;
    let label = webview.label().to_string();
    if !dapp_dialog_owners().lock().unwrap().insert(label.clone()) {
        return Err("dapp_dialog: a dialog from this page is already open".to_string());
    }
    let result = show_dapp_dialog(&webview, kind, message, default_value).await;
    dapp_dialog_owners().lock().unwrap().remove(&label);
    result
}

async fn show_dapp_dialog<R: tauri::Runtime>(
    webview: &tauri::Webview<R>,
    kind: String,
    message: String,
    default_value: Option<String>,
) -> Result<DappDialogResult, String> {
    let origin = match webview.url() {
        Ok(url) => url.origin().ascii_serialization(),
        Err(_) => format!("webview://{}", webview.label()),
    };
    let id = next_dapp_dialog_id();
    let (tx, rx) = tokio::sync::oneshot::channel::<DappDialogResult>();
    dapp_dialog_pending().lock().unwrap().insert(id.clone(), tx);

    let req = DappDialogRequest {
        id: id.clone(),
        kind,
        origin,
        message,
        default_value,
    };
    if let Err(e) = webview.app_handle().emit("dapp-dialog-request", req) {
        dapp_dialog_pending().lock().unwrap().remove(&id);
        return Err(format!("dapp_dialog: failed to notify shell: {e}"));
    }

    match tokio::time::timeout(Duration::from_secs(300), rx).await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(_)) => Ok(DappDialogResult::default()),
        Err(_) => {
            dapp_dialog_pending().lock().unwrap().remove(&id);
            Ok(DappDialogResult::default())
        }
    }
}

#[tauri::command]
fn resolve_dapp_dialog(id: String, action: String, value: Option<String>) -> Result<(), String> {
    let Some(sender) = dapp_dialog_pending().lock().unwrap().remove(&id) else {
        return Ok(());
    };
    let _ = sender.send(DappDialogResult { action, value });
    Ok(())
}

// ---------------------------------------------------------------------------
// Embedded dApp browser control (VISION feature ③).
//
// The shell drives the native `dapp` child webview: navigate it to the chosen
// dApp and place it over the `.browser-content` rect (measured in JS, sent here).
// These commands are reachable ONLY from the trusted shell — their permissions
// in permissions/dapp-browser.toml are granted only by capabilities/default.json,
// scoped to the shell webview.
// So an untrusted dApp can never reposition or navigate any webview; the e2e
// tests assert that denial.
// ---------------------------------------------------------------------------

/// A child webview's `set_position` is relative to the window FRAME (includes the
/// macOS title bar), but the rect the shell measures with getBoundingClientRect is
/// relative to the CONTENT area. Bridge the two by adding the title-bar inset
/// (inner_position − outer_position). Without this the dapp webview sits one
/// title-bar too high and clips the browser bar.
fn content_to_frame<R: Runtime>(dapp: &tauri::Webview<R>, x: f64, y: f64) -> (f64, f64) {
    // The frame/content mismatch is a macOS (NSView-in-window-frame) artifact.
    // On Windows/Linux child-webview bounds are relative to the client area —
    // the same space the shell measured with getBoundingClientRect — so the
    // rect must pass through unchanged. Applying the macOS compensation there
    // shifts the dapp webview down by a full title bar (visible in the Windows
    // CI smoke screenshots).
    if !cfg!(target_os = "macos") {
        return (x, y);
    }
    let win = dapp.window();
    let scale = win.scale_factor().unwrap_or(1.0);
    // Title-bar inset, in logical px. The position delta is the principled source
    // but reports 0 for a container Window on macOS here, so fall back to the
    // outer/inner *size* height delta (title bar = the only frame chrome on macOS).
    let dy_pos = match (win.inner_position(), win.outer_position()) {
        (Ok(i), Ok(o)) => (i.y - o.y) as f64 / scale,
        _ => 0.0,
    };
    let dy_size = match (win.inner_size(), win.outer_size()) {
        (Ok(i), Ok(o)) => (o.height as f64 - i.height as f64) / scale,
        _ => 0.0,
    };
    // Under macOS fullSizeContentView the container window reports inner == outer
    // (no inset), yet child-webview set_position renders one title-bar too high.
    // Fall back to the title-bar constant when the dynamic deltas are ~0.
    // 32pt measured empirically via screencapture (the standard 28pt left a 4px
    // gap); make this dynamic via NSWindow.contentLayoutRect if it ever varies.
    const MACOS_TITLEBAR_PT: f64 = 32.0;
    let dy = if dy_pos > 0.5 {
        dy_pos
    } else if dy_size > 0.5 {
        dy_size
    } else {
        MACOS_TITLEBAR_PT
    };
    println!("[AutoDesktop] content_to_frame in=({x:.0},{y:.0}) -> dy={dy:.1}");
    (x, y + dy)
}

/// Each open dApp tab is its own child webview, labeled `dapp-<id>`. The
/// shell-only controls may target ONLY these — a strict label shape stops a shell
/// bug from being turned into hiding/closing the trusted "shell"/"approval"
/// webviews.
fn validate_dapp_label(label: &str) -> Result<(), String> {
    let ok = label.starts_with("dapp-")
        && label.len() > 5
        && label[5..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if ok {
        Ok(())
    } else {
        Err(format!("invalid dapp label: {label:?}"))
    }
}

#[derive(Clone, Copy, Debug)]
struct DappBounds {
    x: f64,
    y: f64,
    w: f64,
    h: f64,
}

fn dapp_bounds_state() -> &'static Mutex<HashMap<String, DappBounds>> {
    static BOUNDS: OnceLock<Mutex<HashMap<String, DappBounds>>> = OnceLock::new();
    BOUNDS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn remember_dapp_bounds(label: &str, bounds: DappBounds) {
    dapp_bounds_state()
        .lock()
        .unwrap()
        .insert(label.to_string(), bounds);
}

fn forget_dapp_bounds(label: &str) {
    dapp_bounds_state().lock().unwrap().remove(label);
}

fn last_dapp_bounds(label: &str) -> Option<DappBounds> {
    dapp_bounds_state().lock().unwrap().get(label).copied()
}

fn apply_dapp_bounds<R: Runtime>(
    dapp: &tauri::Webview<R>,
    bounds: DappBounds,
) -> Result<(), String> {
    let (fx, fy) = content_to_frame(dapp, bounds.x, bounds.y);
    dapp.set_position(LogicalPosition::new(fx, fy))
        .map_err(|e| e.to_string())?;
    dapp.set_size(LogicalSize::new(bounds.w.max(1.0), bounds.h.max(1.0)))
        .map_err(|e| e.to_string())
}

/// Serializes webview creation across the async commands (open_dapp + the two
/// overlays). Async commands run concurrently on the runtime's thread pool, so
/// two rapid invokes for the same label could otherwise race get-or-create into
/// a duplicate add_child. No await ever happens while this is held.
fn webview_creation_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn repair_active_dapp_after_shell_resize<R: Runtime>(app: &AppHandle<R>) {
    let Some(label) = active_dapp_label().lock().unwrap().clone() else {
        return;
    };
    let Some(bounds) = last_dapp_bounds(&label) else {
        return;
    };
    let Some(dapp) = app.get_webview(&label) else {
        return;
    };
    if let Err(e) = apply_dapp_bounds(&dapp, bounds) {
        println!("[AutoDesktop] dapp resize repair failed for {label}: {e}");
    }
    if let Err(e) = dapp.show() {
        println!("[AutoDesktop] dapp resize show failed for {label}: {e}");
    }
}

fn repair_dapp_bounds_after_devtools<R: Runtime + 'static>(app: AppHandle<R>, label: String) {
    const REPAIR_DELAYS_MS: [u64; 7] = [0, 50, 150, 300, 700, 1200, 2000];

    tauri::async_runtime::spawn(async move {
        for delay_ms in REPAIR_DELAYS_MS {
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            let Some(bounds) = last_dapp_bounds(&label) else {
                println!("[AutoDesktop] dapp devtools repair: no bounds for {label}");
                return;
            };
            let Some(dapp) = app.get_webview(&label) else {
                println!("[AutoDesktop] dapp devtools repair: webview {label:?} not found");
                return;
            };
            if let Err(e) = apply_dapp_bounds(&dapp, bounds) {
                println!("[AutoDesktop] dapp devtools repair failed for {label}: {e}");
            }
        }
    });
}

/// Chromium flags for every Windows WebView2.
///
/// WebView2 forbids mixing `additional_browser_args` across webviews that share
/// a user-data directory, so the trusted shell, overlays, approval window, and
/// untrusted dApp tabs all get this same string. AutoDesktop talks to Ledger via
/// Rust `hidapi`; no webview needs WebHID/WebUSB. A remote page that obtained
/// WebHID could race APDUs against a Ledger during on-device review.
///
/// `additional_browser_args` *replaces* wry's defaults, so the ms* flags and
/// autoplay policy must be restated.
const WINDOWS_WEBVIEW_BROWSER_ARGS: &str = concat!(
    "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection,WebHID,WebUSB ",
    "--autoplay-policy=no-user-gesture-required",
);

fn harden_webview<R: Runtime>(builder: WebviewBuilder<R>) -> WebviewBuilder<R> {
    builder.additional_browser_args(WINDOWS_WEBVIEW_BROWSER_ARGS)
}

fn harden_window<'a, R: Runtime, M: Manager<R>>(
    builder: tauri::WebviewWindowBuilder<'a, R, M>,
) -> tauri::WebviewWindowBuilder<'a, R, M> {
    builder.additional_browser_args(WINDOWS_WEBVIEW_BROWSER_ARGS)
}

/// Create a tab webview (remote, untrusted) as a child of the main window, with
/// the EIP-1193 provider injected. capabilities/dapp.json (`webviews: ["dapp-*"]`)
/// grants it ONLY allow-wallet-request.
///
/// ⚠️ Must never run on the main thread inside an IPC/event handler: webview
/// creation deadlocks there on Windows (see the async note on `open_dapp`).
fn create_dapp_webview<R: Runtime>(
    app: &AppHandle<R>,
    label: &str,
    url: tauri::Url,
    x: f64,
    y: f64,
    w: f64,
    h: f64,
) -> Result<tauri::Webview<R>, String> {
    println!(
        "[AutoDesktop] create dapp webview label={label} url={url} bounds=({x:.0},{y:.0},{w:.0},{h:.0})"
    );
    let window = app
        .get_window("main")
        .ok_or("create_dapp_webview: main window not found")?;
    let builder = harden_webview(
        WebviewBuilder::new(label, WebviewUrl::External(url))
            .on_page_load(|webview, payload| {
                println!(
                    "[AutoDesktop] dapp page-load {:?}  url={}",
                    payload.event(),
                    payload.url()
                );
                if payload.event() == PageLoadEvent::Finished {
                    // It has a page to draw now, so it may cover the shell.
                    mark_dapp_loaded(webview.label());
                    let should_show =
                        active_dapp_label().lock().unwrap().as_deref() == Some(webview.label());
                    if should_show {
                        let _ = webview.show();
                    }
                    let _ = webview.app_handle().emit(
                        "dapp-load-finished",
                        DappNavigationEvent {
                            label: webview.label().to_string(),
                            url: payload.url().to_string(),
                        },
                    );
                }
            })
            .initialization_script(INPAGE_PROVIDER),
    );
    window
        .add_child(
            builder,
            LogicalPosition::new(x, y),
            LogicalSize::new(w.max(1.0), h.max(1.0)),
        )
        .map_err(|e| e.to_string())
}

/// Tab webviews that have finished loading a page at least once.
fn loaded_dapp_labels() -> &'static Mutex<HashSet<String>> {
    static LOADED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    LOADED.get_or_init(|| Mutex::new(HashSet::new()))
}

fn mark_dapp_loaded(label: &str) {
    loaded_dapp_labels()
        .lock()
        .unwrap()
        .insert(label.to_string());
}

/// Closing a tab destroys its webview, so the next one starts blank again.
fn forget_dapp_loaded(label: &str) {
    loaded_dapp_labels().lock().unwrap().remove(label);
}

/// Whether `open_dapp` may show the tab webview straight away.
///
/// A webview that has not painted a page yet draws a blank white rectangle, and
/// child webviews sit ON TOP of the shell — so showing one too early covers the
/// shell's loading animation with that blank rect, which is then all the user
/// sees while the dApp loads. It stays hidden until `on_page_load(Finished)`
/// shows it (or the shell's 20s timeout re-opens it). A tab that already has its
/// page must show at once, otherwise switching tabs would flash empty.
fn show_dapp_on_open(label: &str) -> bool {
    loaded_dapp_labels().lock().unwrap().contains(label)
}

/// Open (create-or-show) tab webview `label` over the content rect. Navigates to
/// `url` only on first creation, so re-activating a tab preserves its page.
///
/// `async` is load-bearing, not cosmetic: synchronous commands execute on the
/// main thread inside a webview event handler, where creating a webview
/// deadlocks on Windows (tauri builder docs / wry#583) — the app froze exactly
/// this way whenever a dApp was opened. Async commands run on the runtime's
/// thread pool, from which creation is dispatched safely to the event loop.
#[tauri::command]
async fn open_dapp<R: Runtime>(
    app: AppHandle<R>,
    label: String,
    url: String,
    x: f64,
    y: f64,
    w: f64,
    h: f64,
) -> Result<(), String> {
    validate_dapp_label(&label)?;
    println!(
        "[AutoDesktop] open_dapp label={label} url={url} bounds=({x:.0},{y:.0},{w:.0},{h:.0})"
    );
    let parsed: tauri::Url = url
        .parse()
        .map_err(|e| format!("open_dapp: invalid url {url}: {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(format!("open_dapp: refusing non-http(s) url: {url}"));
    }
    let bounds = DappBounds { x, y, w, h };
    remember_dapp_bounds(&label, bounds);
    let _guard = webview_creation_lock().lock().unwrap();
    let (dapp, newly_created) = match app.get_webview(&label) {
        Some(wv) => (wv, false),
        None => (create_dapp_webview(&app, &label, parsed, x, y, w, h)?, true),
    };
    // A resize can land while creation is in flight; apply the freshest rect.
    let bounds = last_dapp_bounds(&label).unwrap_or(bounds);
    apply_dapp_bounds(&dapp, bounds)?;
    set_active_dapp_label(label.clone());
    if show_dapp_on_open(&label) {
        dapp.show().map_err(|e| e.to_string())?;
    } else {
        dapp.hide().map_err(|e| e.to_string())?;
    }
    println!("[AutoDesktop] dapp webview ready label={label} newly_created={newly_created}");
    Ok(())
}

/// Reposition/resize the active tab webview to track the content rect (resize).
/// Idempotent: a no-op if the tab webview no longer exists.
#[tauri::command]
fn set_dapp_bounds<R: Runtime>(
    app: AppHandle<R>,
    label: String,
    x: f64,
    y: f64,
    w: f64,
    h: f64,
) -> Result<(), String> {
    validate_dapp_label(&label)?;
    let bounds = DappBounds { x, y, w, h };
    remember_dapp_bounds(&label, bounds);
    if let Some(dapp) = app.get_webview(&label) {
        apply_dapp_bounds(&dapp, bounds)?;
    }
    Ok(())
}

/// A tiny transparent local child webview used only to draw shell toasts above a
/// remote dApp child webview. It is positioned to the measured toast stack rect,
/// so it does not steal clicks from the rest of the dApp page.
///
/// `async` for the same reason as `open_dapp`: it creates a webview, which
/// deadlocks on Windows when done from a synchronous command.
#[tauri::command]
async fn sync_toast_overlay<R: Runtime>(
    app: AppHandle<R>,
    visible: bool,
    x: Option<f64>,
    y: Option<f64>,
    w: Option<f64>,
    h: Option<f64>,
) -> Result<(), String> {
    const LABEL: &str = "toast-overlay";

    if !visible {
        if let Some(overlay) = app.get_webview(LABEL) {
            overlay.hide().map_err(|e| e.to_string())?;
        }
        return Ok(());
    }

    let x = x.unwrap_or(0.0);
    let y = y.unwrap_or(0.0);
    let w = w.unwrap_or(1.0).max(1.0);
    let h = h.unwrap_or(1.0).max(1.0);

    let window = app
        .get_window("main")
        .ok_or("sync_toast_overlay: main window not found")?;
    let _guard = webview_creation_lock().lock().unwrap();
    let overlay = match app.get_webview(LABEL) {
        Some(wv) => {
            // Child webviews stack in creation order. A dApp opened after the
            // toast overlay was first created can cover it, so reparent the
            // existing overlay to the same window before showing it. This
            // matches the menu overlay's topmost behavior.
            wv.reparent(&window).map_err(|e| e.to_string())?;
            wv
        }
        None => {
            let builder = harden_webview(
                WebviewBuilder::new(
                    LABEL,
                    WebviewUrl::App("index.html?view=toast-overlay".into()),
                )
                .transparent(true),
            );
            window
                .add_child(builder, LogicalPosition::new(x, y), LogicalSize::new(w, h))
                .map_err(|e| e.to_string())?
        }
    };

    let (fx, fy) = content_to_frame(&overlay, x, y);
    overlay
        .set_position(LogicalPosition::new(fx, fy))
        .map_err(|e| e.to_string())?;
    overlay
        .set_size(LogicalSize::new(w, h))
        .map_err(|e| e.to_string())?;
    overlay.show().map_err(|e| e.to_string())?;
    Ok(())
}

/// A transparent local child webview that renders the browser top-bar dropdown
/// menus (account / chain switcher) ABOVE the remote dApp child webview — native
/// child webviews stack over the shell, so an in-shell dropdown would be covered
/// by the page. Unlike the toast overlay it spans the whole window while a menu
/// is open: the transparent area doubles as the click-away backdrop (the overlay
/// page posts a dismiss action back to the shell over a BroadcastChannel).
///
/// `async` for the same reason as `open_dapp`: it creates a webview, which
/// deadlocks on Windows when done from a synchronous command.
#[tauri::command]
async fn sync_menu_overlay<R: Runtime>(
    app: AppHandle<R>,
    visible: bool,
    x: Option<f64>,
    y: Option<f64>,
    w: Option<f64>,
    h: Option<f64>,
) -> Result<(), String> {
    const LABEL: &str = "menu-overlay";

    if !visible {
        if let Some(overlay) = app.get_webview(LABEL) {
            overlay.hide().map_err(|e| e.to_string())?;
        }
        return Ok(());
    }

    let x = x.unwrap_or(0.0);
    let y = y.unwrap_or(0.0);
    let w = w.unwrap_or(1.0).max(1.0);
    let h = h.unwrap_or(1.0).max(1.0);

    let window = app
        .get_window("main")
        .ok_or("sync_menu_overlay: main window not found")?;
    let _guard = webview_creation_lock().lock().unwrap();
    let overlay = match app.get_webview(LABEL) {
        Some(wv) => {
            // Child webviews stack in creation order, so a dApp tab opened after
            // this overlay was first created would cover it. Re-adding the
            // overlay's native view to the window (reparent to the SAME window)
            // puts it back on top of every webview created since.
            wv.reparent(&window).map_err(|e| e.to_string())?;
            wv
        }
        None => {
            let builder = harden_webview(
                WebviewBuilder::new(
                    LABEL,
                    WebviewUrl::App("index.html?view=menu-overlay".into()),
                )
                .transparent(true),
            );
            window
                .add_child(builder, LogicalPosition::new(x, y), LogicalSize::new(w, h))
                .map_err(|e| e.to_string())?
        }
    };

    let (fx, fy) = content_to_frame(&overlay, x, y);
    overlay
        .set_position(LogicalPosition::new(fx, fy))
        .map_err(|e| e.to_string())?;
    overlay
        .set_size(LogicalSize::new(w, h))
        .map_err(|e| e.to_string())?;
    overlay.show().map_err(|e| e.to_string())?;
    Ok(())
}

/// Navigate an existing tab. Shell-only; dApps are never granted this command.
#[tauri::command]
fn navigate_dapp<R: Runtime>(
    app: AppHandle<R>,
    label: String,
    url: String,
) -> Result<(), String> {
    validate_dapp_label(&label)?;
    let target: tauri::Url = url
        .parse()
        .map_err(|e| format!("navigate_dapp: invalid url {url}: {e}"))?;
    if !matches!(target.scheme(), "http" | "https") {
        return Err(format!("navigate_dapp: refusing non-http(s) url: {url}"));
    }
    let dapp = app
        .get_webview(&label)
        .ok_or_else(|| format!("navigate_dapp: webview not found: {label}"))?;
    dapp.navigate(target).map_err(|e| e.to_string())?;
    app.emit("dapp-navigated", DappNavigationEvent { label, url })
        .map_err(|e| e.to_string())
}

/// Reload a tab webview. Shell-only; dApps are never granted this command.
#[tauri::command]
fn reload_dapp<R: Runtime>(app: AppHandle<R>, label: String) -> Result<(), String> {
    validate_dapp_label(&label)?;
    if let Some(dapp) = app.get_webview(&label) {
        dapp.reload().map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Navigate back inside a tab webview. Shell-only; dApps are never granted this
/// command. `history.back()` is a no-op when the tab has no earlier page, so the
/// browser stays open instead of returning to the dApps list.
#[tauri::command]
fn go_back_dapp<R: Runtime>(app: AppHandle<R>, label: String) -> Result<(), String> {
    validate_dapp_label(&label)?;
    if let Some(dapp) = app.get_webview(&label) {
        dapp.eval("window.history.back()")
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Show a tab webview whose page never reported a finished load — the shell's
/// timeout escape hatch. Without it, a page that never fires `Finished` (a dead
/// host, a redirect loop) would sit behind the loading animation forever, since
/// `open_dapp` keeps an unloaded webview hidden. Shell-only. Idempotent.
#[tauri::command]
fn show_dapp<R: Runtime>(app: AppHandle<R>, label: String) -> Result<(), String> {
    validate_dapp_label(&label)?;
    if let Some(dapp) = app.get_webview(&label) {
        // Whatever it has drawn is now what the user gets; stop hiding it on
        // later tab switches too.
        mark_dapp_loaded(&label);
        dapp.show().map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Hide a tab webview (switching to another tab or to Wallet/dApps). Idempotent.
#[tauri::command]
fn hide_dapp<R: Runtime>(app: AppHandle<R>, label: String) -> Result<(), String> {
    validate_dapp_label(&label)?;
    if let Some(dapp) = app.get_webview(&label) {
        dapp.hide().map_err(|e| e.to_string())?;
    }
    clear_active_dapp_label(&label);
    Ok(())
}

/// Close (destroy) a tab webview when its tab is closed. Idempotent.
#[tauri::command]
fn close_dapp<R: Runtime>(app: AppHandle<R>, label: String) -> Result<(), String> {
    validate_dapp_label(&label)?;
    if let Some(dapp) = app.get_webview(&label) {
        dapp.close().map_err(|e| e.to_string())?;
    }
    forget_dapp_bounds(&label);
    forget_dapp_loaded(&label);
    clear_active_dapp_label(&label);
    Ok(())
}

#[derive(Serialize, Clone)]
struct DappNavigationEvent {
    label: String,
    url: String,
}

#[derive(Serialize, Clone)]
struct DappLayoutInvalidatedEvent {
    label: String,
}

fn registrable_site(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host == "localhost" || host.parse::<std::net::IpAddr>().is_ok() {
        return host;
    }
    let parts: Vec<&str> = host.split('.').filter(|part| !part.is_empty()).collect();
    if parts.len() <= 2 {
        return host;
    }
    let second_last = parts[parts.len() - 2];
    let last = parts[parts.len() - 1];
    let public_second_level = matches!(second_last, "co" | "com" | "net" | "org" | "gov" | "edu");
    if public_second_level && last.len() == 2 && parts.len() >= 3 {
        parts[parts.len() - 3..].join(".")
    } else {
        parts[parts.len() - 2..].join(".")
    }
}

fn is_same_registrable_site(a: &tauri::Url, b: &tauri::Url) -> bool {
    match (a.host_str(), b.host_str()) {
        (Some(a_host), Some(b_host)) => registrable_site(a_host) == registrable_site(b_host),
        _ => false,
    }
}

/// Open an http(s) URL from a webview. For dApp-initiated "new window" intents,
/// same-site subdomains (e.g. www.pendle.finance -> app.pendle.finance) navigate
/// in the current dApp webview so the injected wallet stays available. Cross-site
/// links still land in the OS default browser. SECURITY: only http/https is
/// honored; a dApp can't coerce us into file://, custom schemes, or shell
/// execution.
#[tauri::command]
fn open_external_url<R: Runtime>(
    app: AppHandle<R>,
    webview: tauri::Webview<R>,
    url: String,
) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    let u: tauri::Url = url
        .trim()
        .parse()
        .map_err(|e| format!("invalid url {url}: {e}"))?;
    if !matches!(u.scheme(), "http" | "https") {
        return Err(format!("refusing to open non-http(s) url: {u}"));
    }

    let label = webview.label().to_string();
    if label.starts_with("dapp-") {
        // Only the tab the user is looking at may open links.
        ensure_signing_webview_is_active(&label)?;
        if let Ok(current) = webview.url() {
            if is_same_registrable_site(&current, &u) {
                let target = u.to_string();
                let js_target =
                    serde_json::to_string(&target).map_err(|e| format!("encode url: {e}"))?;
                webview
                    .eval(format!("window.location.assign({js_target});"))
                    .map_err(|e| e.to_string())?;
                let _ = app.emit("dapp-navigated", DappNavigationEvent { label, url: target });
                return Ok(());
            }
        }
    }

    let u = u.to_string();
    println!("[AutoDesktop] open external -> {u}");
    app.opener()
        .open_url(u, None::<&str>)
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Active wallet network (the chain dApps see via eth_chainId).
// ---------------------------------------------------------------------------

/// Push an EIP-1193 `chainChanged` to every open dApp tab by eval'ing the
/// provider's `window.__autoWalletPush` (see inpage.tauri.ts). Avoids granting the
/// dapp webviews any event capability — they keep ONLY allow-wallet-request.
fn push_chain_changed<R: Runtime>(app: &AppHandle<R>, chain_id: &str) {
    let payload = serde_json::to_string(chain_id).unwrap_or_else(|_| "\"0x1\"".into());
    let js =
        format!("window.__autoWalletPush && window.__autoWalletPush('chainChanged', {payload});");
    let mut pushed = 0;
    for (label, webview) in app.webviews() {
        if label.starts_with("dapp-") {
            let _ = webview.eval(js.clone());
            pushed += 1;
        }
    }
    println!("[AutoDesktop] chainChanged -> {pushed} dApp(s), chain={chain_id}");
}

/// Set the active wallet network (shell-only). Updates the chain dApps see via
/// `eth_chainId`/forwarded reads and pushes `chainChanged` to all open dApps.
#[tauri::command]
fn set_active_chain<R: Runtime>(app: AppHandle<R>, chain_id: String) -> Result<(), String> {
    let chain = find_chain(&chain_id)
        .ok_or_else(|| format!("set_active_chain: unknown chain {chain_id}"))?;
    *current_chain().lock().unwrap() = chain.id.clone();
    push_chain_changed(&app, &chain.id);
    Ok(())
}

/// The active wallet network as a 0x-hex chain id (for the shell's chain selector).
#[tauri::command]
fn get_active_chain() -> String {
    current_chain().lock().unwrap().clone()
}

// ---------------------------------------------------------------------------
// Chain registry CRUD (Settings → manage networks). Shell-only. Built-in chains
// can be edited (rpc/name/symbol) but not removed; user chains are full CRUD. The
// effective list is persisted (non-sensitive) to chains.json in the app-data dir.
// ---------------------------------------------------------------------------

const CHAINS_FILE: &str = "chains.json";

fn chains_path<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join(CHAINS_FILE))
}

/// Load the persisted chain list (built-ins + user edits) at startup, if present.
fn load_chains<R: Runtime>(app: &AppHandle<R>) {
    let Ok(path) = chains_path(app) else { return };
    if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(list) = serde_json::from_slice::<Vec<ChainCfg>>(&bytes) {
            if !list.is_empty() {
                // Merge (not replace): a snapshot from an older version is missing
                // built-ins added since, and must not freeze the registry.
                *chains_state().lock().unwrap() = merge_persisted_chains(list);
            }
        }
    }
}

fn save_chains<R: Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    let path = chains_path(app)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let list = chains_state().lock().unwrap().clone();
    let json = serde_json::to_vec_pretty(&list).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| format!("writing chains: {e}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum CloseBehavior {
    Hide,
    Quit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
struct AppPrefs {
    close_behavior: CloseBehavior,
    /// Lock the wallet after this many idle minutes; 0 = never.
    auto_lock_minutes: u32,
}

const DEFAULT_AUTO_LOCK_MINUTES: u32 = 15;

impl Default for AppPrefs {
    fn default() -> Self {
        Self {
            close_behavior: default_close_behavior(),
            auto_lock_minutes: DEFAULT_AUTO_LOCK_MINUTES,
        }
    }
}

fn default_close_behavior() -> CloseBehavior {
    #[cfg(target_os = "macos")]
    {
        CloseBehavior::Hide
    }
    #[cfg(not(target_os = "macos"))]
    {
        CloseBehavior::Quit
    }
}

const APP_PREFS_FILE: &str = "app-prefs.json";

fn app_prefs_path<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join(APP_PREFS_FILE))
}

fn load_app_prefs<R: Runtime>(app: &AppHandle<R>) -> AppPrefs {
    let Ok(path) = app_prefs_path(app) else {
        return AppPrefs::default();
    };
    let Ok(bytes) = std::fs::read(path) else {
        return AppPrefs::default();
    };
    serde_json::from_slice::<AppPrefs>(&bytes).unwrap_or_default()
}

fn save_app_prefs<R: Runtime>(app: &AppHandle<R>, prefs: &AppPrefs) -> Result<(), String> {
    let path = app_prefs_path(app)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_vec_pretty(prefs).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| format!("writing app prefs: {e}"))
}

const ACTIVITY_FILE: &str = "activity.json";

fn activity_path<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join(ACTIVITY_FILE))
}

fn load_activity_records<R: Runtime>(app: &AppHandle<R>) -> Vec<ActivityRecord> {
    let Ok(path) = activity_path(app) else {
        return Vec::new();
    };
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    serde_json::from_slice::<Vec<ActivityRecord>>(&bytes).unwrap_or_default()
}

fn save_activity_records<R: Runtime>(
    app: &AppHandle<R>,
    records: &[ActivityRecord],
) -> Result<(), String> {
    let path = activity_path(app)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_vec_pretty(records).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| format!("writing activity: {e}"))
}

const PORTFOLIO_HISTORY_FILE: &str = "portfolio-history.json";
const PORTFOLIO_HISTORY_MAX_AGE_SECS: u64 = 90 * 24 * 60 * 60;
const PORTFOLIO_HISTORY_REPLACE_WINDOW_SECS: u64 = 10 * 60;

fn portfolio_history_path<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join(PORTFOLIO_HISTORY_FILE))
}

fn load_portfolio_snapshots<R: Runtime>(app: &AppHandle<R>) -> Vec<PortfolioSnapshot> {
    let Ok(path) = portfolio_history_path(app) else {
        return Vec::new();
    };
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    serde_json::from_slice::<Vec<PortfolioSnapshot>>(&bytes).unwrap_or_default()
}

fn save_portfolio_snapshots<R: Runtime>(
    app: &AppHandle<R>,
    snapshots: &[PortfolioSnapshot],
) -> Result<(), String> {
    let path = portfolio_history_path(app)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_vec_pretty(snapshots).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| format!("writing portfolio history: {e}"))
}

fn normalized_address(address: &str) -> Result<String, String> {
    let address = address.trim();
    if address.len() == 42
        && address.starts_with("0x")
        && address[2..].chars().all(|c| c.is_ascii_hexdigit())
    {
        Ok(address.to_lowercase())
    } else {
        Err("invalid address".to_string())
    }
}

#[tauri::command]
fn get_portfolio_history<R: Runtime>(
    app: AppHandle<R>,
    address: String,
) -> Result<Vec<PortfolioSnapshot>, String> {
    let address = normalized_address(&address)?;
    let mut snapshots: Vec<PortfolioSnapshot> = load_portfolio_snapshots(&app)
        .into_iter()
        .filter(|s| s.address.eq_ignore_ascii_case(&address))
        .collect();
    snapshots.sort_by_key(|s| s.timestamp);
    Ok(snapshots)
}

/// Drops the reading one address recorded at `timestamp`. Returns the survivors
/// and how many rows went, so a delete that matched nothing can be refused
/// rather than reported as a success the history never saw.
fn without_snapshot(
    snapshots: Vec<PortfolioSnapshot>,
    address: &str,
    timestamp: u64,
) -> (Vec<PortfolioSnapshot>, usize) {
    let before = snapshots.len();
    let kept: Vec<PortfolioSnapshot> = snapshots
        .into_iter()
        .filter(|s| !(s.timestamp == timestamp && s.address.eq_ignore_ascii_case(address)))
        .collect();
    let removed = before - kept.len();
    (kept, removed)
}

/// Forget one recorded reading. A total captured while a source was still in
/// flight is not a smaller portfolio, and it stays in the chart as a crash that
/// never happened — this is how the user takes it back out.
#[tauri::command]
fn delete_portfolio_snapshot<R: Runtime>(
    app: AppHandle<R>,
    address: String,
    timestamp: u64,
) -> Result<Vec<PortfolioSnapshot>, String> {
    let address = normalized_address(&address)?;
    let (kept, removed) = without_snapshot(load_portfolio_snapshots(&app), &address, timestamp);
    if removed == 0 {
        return Err(format!("no snapshot recorded at {timestamp}"));
    }
    save_portfolio_snapshots(&app, &kept)?;
    get_portfolio_history(app, address)
}

#[tauri::command]
fn record_portfolio_snapshot<R: Runtime>(
    app: AppHandle<R>,
    address: String,
    total_usd: f64,
) -> Result<Vec<PortfolioSnapshot>, String> {
    if !total_usd.is_finite() || total_usd < 0.0 {
        return Err("invalid total".to_string());
    }
    let address = normalized_address(&address)?;
    let now = now_secs();
    let cutoff = now.saturating_sub(PORTFOLIO_HISTORY_MAX_AGE_SECS);
    let mut snapshots: Vec<PortfolioSnapshot> = load_portfolio_snapshots(&app)
        .into_iter()
        .filter(|s| s.timestamp >= cutoff)
        .collect();

    if let Some(last) = snapshots
        .iter_mut()
        .filter(|s| s.address.eq_ignore_ascii_case(&address))
        .max_by_key(|s| s.timestamp)
    {
        if now.saturating_sub(last.timestamp) < PORTFOLIO_HISTORY_REPLACE_WINDOW_SECS {
            last.total_usd = total_usd;
            last.timestamp = now;
            save_portfolio_snapshots(&app, &snapshots)?;
            return get_portfolio_history(app, address);
        }
    }

    snapshots.push(PortfolioSnapshot {
        address: address.clone(),
        total_usd,
        timestamp: now,
    });
    snapshots.sort_by_key(|s| s.timestamp);
    save_portfolio_snapshots(&app, &snapshots)?;
    get_portfolio_history(app, address)
}

#[derive(Default)]
struct ActivityMeta {
    kind: Option<String>,
    counterparty: Option<String>,
    asset_symbol: Option<String>,
    asset_decimals: Option<u32>,
    amount: Option<String>,
    token_address: Option<String>,
    swap: Option<ActivitySwap>,
}

fn tx_activity_meta(tx: &Value) -> ActivityMeta {
    let Some(meta) = tx.get("activity").and_then(|v| v.as_object()) else {
        return ActivityMeta::default();
    };
    ActivityMeta {
        kind: meta
            .get("kind")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        counterparty: meta
            .get("counterparty")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        asset_symbol: meta
            .get("assetSymbol")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        asset_decimals: meta
            .get("assetDecimals")
            .and_then(|v| v.as_u64())
            .and_then(|n| u32::try_from(n).ok()),
        amount: meta
            .get("amount")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        token_address: meta
            .get("tokenAddress")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        swap: meta
            .get("swap")
            .cloned()
            .and_then(|v| serde_json::from_value::<ActivitySwap>(v).ok()),
    }
}

fn parse_erc20_transfer(data: &str) -> Option<(String, String)> {
    let hex = data.strip_prefix("0x").unwrap_or(data);
    if hex.len() < 8 + 64 + 64 || !hex[..8].eq_ignore_ascii_case("a9059cbb") {
        return None;
    }
    let to_word = &hex[8..72];
    let amount_word = &hex[72..136];
    let to = format!("0x{}", &to_word[24..64]);
    let amount = format!("0x{}", amount_word.trim_start_matches('0'));
    Some((
        to,
        if amount == "0x" {
            "0x0".to_string()
        } else {
            amount
        },
    ))
}

fn record_activity<R: Runtime>(
    app: &AppHandle<R>,
    prepared: &PreparedTx,
    origin: &str,
    sent: &Broadcast,
    tx: &Value,
    balance_changes: Vec<ActivityBalanceChange>,
) {
    let hash = sent.hash.as_str();
    let has_data = prepared.data.trim() != "0x" && !prepared.data.trim().is_empty();
    let mut meta = tx_activity_meta(tx);
    let parsed_transfer = parse_erc20_transfer(&prepared.data);
    if parsed_transfer.is_some() && meta.kind.is_none() {
        meta.kind = Some("token_send".to_string());
    }
    if let Some((to, amount)) = parsed_transfer {
        meta.counterparty.get_or_insert(to);
        meta.amount.get_or_insert(amount);
        meta.token_address.get_or_insert(prepared.to.clone());
    }
    let kind = meta.kind.clone().unwrap_or_else(|| {
        if has_data {
            "contract".to_string()
        } else {
            "send".to_string()
        }
    });
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let record = ActivityRecord {
        id: format!(
            "{}:{}",
            prepared.chain_id.to_lowercase(),
            hash.to_lowercase()
        ),
        hash: hash.to_string(),
        chain_id: prepared.chain_id.clone(),
        chain_name: prepared.chain_name.clone(),
        symbol: prepared.symbol.clone(),
        from: prepared.from.clone(),
        to: prepared.to.clone(),
        value: prepared.value.clone(),
        data: prepared.data.clone(),
        gas: prepared.gas.clone(),
        nonce: prepared.nonce.clone(),
        max_priority_fee_per_gas: prepared.max_priority_fee_per_gas.clone(),
        max_fee_per_gas: prepared.max_fee_per_gas.clone(),
        origin: origin.to_string(),
        kind,
        counterparty: meta.counterparty.or_else(|| {
            if prepared.to.is_empty() {
                None
            } else {
                Some(prepared.to.clone())
            }
        }),
        asset_symbol: meta.asset_symbol.or_else(|| {
            if has_data {
                None
            } else {
                Some(prepared.symbol.clone())
            }
        }),
        asset_decimals: meta
            .asset_decimals
            .or_else(|| if has_data { None } else { Some(18) }),
        amount: meta.amount.or_else(|| {
            if prepared.value != "0x0" {
                Some(prepared.value.clone())
            } else {
                None
            }
        }),
        token_address: meta.token_address,
        swap: meta.swap,
        balance_changes,
        status: Some("submitted".to_string()),
        timestamp: now,
    };

    let mut records = load_activity_records(app);
    records.retain(|r| {
        !r.hash.eq_ignore_ascii_case(hash) || !r.chain_id.eq_ignore_ascii_case(&prepared.chain_id)
    });
    records.insert(0, record);
    records.truncate(500);
    if let Err(e) = save_activity_records(app, &records) {
        println!("[AutoDesktop] warn: failed to save activity: {e}");
    } else {
        let _ = app.emit("activity-changed", ());
    }
    let event = match sent.broadcast_error {
        None => "activity-recorded",
        // Recorded and polled like any other submission, but the node never said
        // it took it — the shell warns instead of announcing a clean submit.
        Some(_) => "activity-unconfirmed",
    };
    let _ = app.emit(event, &records[0]);
}

#[tauri::command]
fn get_activity<R: Runtime>(app: AppHandle<R>) -> Vec<ActivityRecord> {
    load_activity_records(&app)
}

async fn receipt_status(chain: &ChainCfg, hash: &str) -> Result<Option<String>, String> {
    let receipt = node_rpc_call(chain, "eth_getTransactionReceipt", &[json!(hash)]).await?;
    if receipt.is_null() {
        return Ok(None);
    }
    let status = receipt
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("0x0");
    Ok(Some(if status == "0x1" {
        "confirmed".to_string()
    } else {
        "failed".to_string()
    }))
}

#[tauri::command]
async fn sync_activity_receipts<R: Runtime>(
    app: AppHandle<R>,
) -> Result<Vec<ActivityRecord>, String> {
    let mut records = load_activity_records(&app);
    let pending: Vec<(usize, String, String)> = records
        .iter()
        .enumerate()
        .filter(|(_, r)| r.status.as_deref().unwrap_or("submitted") == "submitted")
        .map(|(idx, r)| (idx, r.chain_id.clone(), r.hash.clone()))
        .collect();

    let mut changed = false;
    let mut completed = Vec::new();
    for (idx, chain_id, hash) in pending {
        let Some(chain) = find_chain(&chain_id) else {
            continue;
        };
        match receipt_status(&chain, &hash).await {
            Ok(Some(status)) => {
                if records[idx].status.as_deref() != Some(status.as_str()) {
                    records[idx].status = Some(status.clone());
                    completed.push((status, records[idx].clone()));
                    changed = true;
                }
            }
            Ok(None) => {}
            Err(e) => println!("[AutoDesktop] warn: failed to sync receipt {hash}: {e}"),
        }
    }

    if changed {
        save_activity_records(&app, &records)?;
        let _ = app.emit("activity-changed", ());
        for (status, record) in completed {
            if status == "confirmed" {
                let _ = app.emit("activity-confirmed", &record);
            } else if status == "failed" {
                let _ = app.emit("activity-failed", &record);
            }
        }
    }
    Ok(records)
}

#[tauri::command]
async fn replace_activity_transaction<R: Runtime>(
    app: AppHandle<R>,
    activity_id: String,
    action: String,
    max_fee_per_gas: String,
    max_priority_fee_per_gas: String,
) -> Result<Value, String> {
    let records = load_activity_records(&app);
    let original = records
        .iter()
        .find(|r| r.id == activity_id)
        .cloned()
        .ok_or("activity record not found")?;
    if original.status.as_deref().unwrap_or("submitted") != "submitted" {
        return Err("only pending transactions can be replaced".to_string());
    }
    if original.nonce.is_empty() || original.gas.is_empty() {
        return Err("this activity record is missing nonce/gas; it cannot be replaced".to_string());
    }
    let active = active_account_address().ok_or("wallet is locked")?;
    if !original.from.eq_ignore_ascii_case(&active) {
        return Err("only the active sender can replace this transaction".to_string());
    }
    if hex_to_u128(&max_priority_fee_per_gas).unwrap_or(0)
        > hex_to_u128(&max_fee_per_gas).unwrap_or(u128::MAX)
    {
        return Err("priority fee cannot exceed max fee".to_string());
    }
    let chain = find_chain(&original.chain_id)
        .ok_or_else(|| format!("no RPC configured for chain {}", original.chain_id))?;

    let is_cancel = action == "cancel" || action == "revoke";
    let prepared = if is_cancel {
        PreparedTx {
            chain_id: chain.id,
            chain_name: chain.name,
            symbol: chain.symbol,
            from: original.from.clone(),
            to: original.from.clone(),
            value: "0x0".to_string(),
            data: "0x".to_string(),
            gas: "0x5208".to_string(),
            nonce: original.nonce.clone(),
            max_priority_fee_per_gas,
            max_fee_per_gas,
        }
    } else {
        PreparedTx {
            chain_id: original.chain_id.clone(),
            chain_name: original.chain_name.clone(),
            symbol: original.symbol.clone(),
            from: original.from.clone(),
            to: original.to.clone(),
            value: original.value.clone(),
            data: original.data.clone(),
            gas: original.gas.clone(),
            nonce: original.nonce.clone(),
            max_priority_fee_per_gas,
            max_fee_per_gas,
        }
    };

    let req = PendingRequest {
        id: next_request_id(),
        method: "eth_sendTransaction".to_string(),
        origin: "AutoDesktop Wallet".to_string(),
        signer_address: Some(prepared.from.clone()),
        signer_kind: signer_kind_for(&prepared.from)
            .ok()
            .map(|kind| signer_kind_name(&kind).to_string()),
        summary: if is_cancel {
            format!("Cancel pending transaction\nOriginal: {}", original.hash)
        } else {
            format!("Speed up pending transaction\nOriginal: {}", original.hash)
        },
        tx: Some(prepared.clone()),
        typed_data: None,
    };
    let decision = request_approval(&app, req).await?;
    if !decision.approved {
        return Err("User rejected the request (4001)".to_string());
    }
    let mut p = prepared;
    if let Some(mf) = decision.max_fee_per_gas {
        p.max_fee_per_gas = mf;
    }
    if let Some(mp) = decision.max_priority_fee_per_gas {
        p.max_priority_fee_per_gas = mp;
    }
    if hex_to_u128(&p.max_priority_fee_per_gas).unwrap_or(0)
        > hex_to_u128(&p.max_fee_per_gas).unwrap_or(u128::MAX)
    {
        p.max_priority_fee_per_gas = p.max_fee_per_gas.clone();
    }

    let sent = finalize_tx(&p).await?;
    let tx = json!({
        "to": p.to,
        "value": p.value,
        "data": p.data,
        "activity": {
            "kind": if is_cancel { "cancel" } else { "speedup" },
            "counterparty": original.counterparty,
            "assetSymbol": original.asset_symbol,
            "assetDecimals": original.asset_decimals,
            "amount": original.amount,
            "tokenAddress": original.token_address
        }
    });
    record_activity(&app, &p, "AutoDesktop Wallet", &sent, &tx, Vec::new());

    let mut records = load_activity_records(&app);
    if retire_original(&mut records, &activity_id, &sent) {
        save_activity_records(&app, &records)?;
    }
    let _ = app.emit("activity-changed", ());

    // As in approve_and_send: the hash goes back either way, and an unacknowledged
    // broadcast surfaces as a warning rather than an error that invites a retry.
    Ok(json!(sent.hash))
}

#[tauri::command]
fn get_close_behavior<R: Runtime>(app: AppHandle<R>) -> CloseBehavior {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = app;
        return CloseBehavior::Quit;
    }
    load_app_prefs(&app).close_behavior
}

#[tauri::command]
fn set_close_behavior<R: Runtime>(
    app: AppHandle<R>,
    close_behavior: CloseBehavior,
) -> Result<CloseBehavior, String> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = app;
        let _ = close_behavior;
        return Ok(CloseBehavior::Quit);
    }
    let prefs = AppPrefs {
        close_behavior,
        ..load_app_prefs(&app)
    };
    save_app_prefs(&app, &prefs)?;
    Ok(close_behavior)
}

// ---------------------------------------------------------------------------
// Auto-lock: drop the keys after a stretch with no user or dApp activity.
// ---------------------------------------------------------------------------

static LAST_ACTIVITY_MS: AtomicU64 = AtomicU64::new(0);

fn last_activity_ms() -> u64 {
    LAST_ACTIVITY_MS.load(Ordering::Relaxed)
}

fn note_activity_at(ms: u64) {
    LAST_ACTIVITY_MS.store(ms, Ordering::Relaxed);
}

fn note_activity() {
    note_activity_at(unix_time_ms());
}

/// Whether an idle wallet should lock now. Only a wallet unlocked with a password
/// is lockable (a Ledger-only setup holds no secret). A clock that went
/// backwards (`now < last`) never counts as idle time.
fn auto_lock_due(now_ms: u64, last_ms: u64, minutes: u32, lockable: bool) -> bool {
    lockable
        && minutes > 0
        && now_ms >= last_ms
        && now_ms - last_ms >= u64::from(minutes) * 60_000
}

/// One check of the idle timer at `now_ms`. An open approval counts as activity:
/// the user is looking at it, and locking would fail the request they are reading.
fn auto_lock_tick_at<R: Runtime>(app: &AppHandle<R>, minutes: u32, now_ms: u64) {
    if !pending().lock().unwrap().is_empty() {
        return;
    }
    let lockable = store_state()
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|s| s.password.is_some());
    if auto_lock_due(now_ms, last_activity_ms(), minutes, lockable) {
        log_diagnostic(app, format!("auto-lock after {minutes} idle minutes"));
        lock_vault(app.clone());
        let _ = app.emit("vault-locked", ());
    }
}

/// The shell reports user input (throttled on its side) so reading the wallet
/// keeps it unlocked.
#[tauri::command]
fn note_user_activity() {
    note_activity();
}

#[tauri::command]
fn get_auto_lock_minutes<R: Runtime>(app: AppHandle<R>) -> u32 {
    load_app_prefs(&app).auto_lock_minutes
}

#[tauri::command]
fn set_auto_lock_minutes<R: Runtime>(app: AppHandle<R>, minutes: u32) -> Result<u32, String> {
    if minutes > 24 * 60 {
        return Err(format!("auto-lock must be at most 1440 minutes, got {minutes}"));
    }
    let prefs = AppPrefs {
        auto_lock_minutes: minutes,
        ..load_app_prefs(&app)
    };
    save_app_prefs(&app, &prefs)?;
    note_activity(); // changing the setting is activity; don't lock mid-click
    Ok(minutes)
}

fn version_parts(version: &str) -> Vec<u64> {
    version
        .trim_start_matches('v')
        .split('.')
        .map(|part| {
            part.chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
                .parse::<u64>()
                .unwrap_or(0)
        })
        .collect()
}

fn is_newer_version(latest: &str, current: &str) -> bool {
    let mut l = version_parts(latest);
    let mut c = version_parts(current);
    let n = l.len().max(c.len());
    l.resize(n, 0);
    c.resize(n, 0);
    l > c
}

fn matching_release_asset(assets: &[GithubAsset]) -> Option<&GithubAsset> {
    #[cfg(target_os = "macos")]
    {
        let arch = if cfg!(target_arch = "aarch64") {
            "aarch64"
        } else {
            "x64"
        };
        return assets.iter().find(|asset| {
            let name = asset.name.to_ascii_lowercase();
            name.contains("macos") && name.contains(arch) && name.ends_with(".dmg")
        });
    }
    #[cfg(target_os = "windows")]
    {
        return assets.iter().find(|asset| {
            let name = asset.name.to_ascii_lowercase();
            name.contains("windows") && name.contains("x64") && name.ends_with(".zip")
        });
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        assets.first()
    }
}

#[tauri::command]
async fn check_for_update() -> Result<UpdateInfo, String> {
    const LATEST_URL: &str =
        "https://api.github.com/repos/Auto-Wallet/auto-desktop/releases/latest";
    let current = env!("CARGO_PKG_VERSION").to_string();
    let release: GithubRelease = reqwest::Client::new()
        .get(LATEST_URL)
        .header(reqwest::header::USER_AGENT, "AutoDesktop")
        .send()
        .await
        .map_err(|e| format!("checking updates: {e}"))?
        .error_for_status()
        .map_err(|e| format!("checking updates: {e}"))?
        .json()
        .await
        .map_err(|e| format!("reading update response: {e}"))?;
    let latest = release.tag_name.trim_start_matches('v').to_string();
    let available = is_newer_version(&latest, &current);
    let download_url = if available {
        matching_release_asset(&release.assets)
            .map(|asset| asset.browser_download_url.clone())
            .or_else(|| Some(release.html_url.clone()))
    } else {
        None
    };
    Ok(UpdateInfo {
        current_version: current,
        latest_version: latest,
        available,
        release_url: release.html_url,
        download_url,
    })
}

fn read_env_file_value(name: &str) -> Option<String> {
    let mut dirs = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        dirs.push(cwd.clone());
        if let Some(parent) = cwd.parent() {
            dirs.push(parent.to_path_buf());
        }
    }
    for dir in dirs {
        let path = dir.join(".env.local");
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let Some((key, value)) = trimmed.split_once('=') else {
                continue;
            };
            if key.trim() != name {
                continue;
            }
            let value = value
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

fn zerion_api_key() -> Option<String> {
    std::env::var("ZERION_APIKEY")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            std::env::var("ZERION_API_KEY")
                .ok()
                .filter(|v| !v.trim().is_empty())
        })
        .or_else(|| read_env_file_value("ZERION_APIKEY"))
        .or_else(|| read_env_file_value("ZERION_API_KEY"))
        .or_else(|| {
            option_env!("ZERION_APIKEY")
                .filter(|v| !v.trim().is_empty())
                .map(str::to_string)
        })
        .or_else(|| {
            option_env!("ZERION_API_KEY")
                .filter(|v| !v.trim().is_empty())
                .map(str::to_string)
        })
}

/// PublicNode RPC API key. Same resolution order as the other providers:
/// process env (CI/release builds) → `.env.local` (dev) → compile-time
/// `option_env!` so a packaged binary carries the key the release job built with.
///
/// Cached, unlike its siblings: this one is consulted on every forwarded JSON-RPC
/// call, and `read_env_file_value` hits the disk. Changing the key needs a restart.
fn public_node_key() -> Option<&'static str> {
    static KEY: OnceLock<Option<String>> = OnceLock::new();
    KEY.get_or_init(|| {
        std::env::var("PUBLIC_NODE_KEY")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .or_else(|| read_env_file_value("PUBLIC_NODE_KEY"))
            .or_else(|| {
                option_env!("PUBLIC_NODE_KEY")
                    .filter(|v| !v.trim().is_empty())
                    .map(str::to_string)
            })
            .map(|v| v.trim().to_string())
    })
    .as_deref()
}

fn debank_api_key() -> Option<String> {
    std::env::var("DEBANK_APIKEY")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            std::env::var("DEBANK_API_KEY")
                .ok()
                .filter(|v| !v.trim().is_empty())
        })
        .or_else(|| read_env_file_value("DEBANK_APIKEY"))
        .or_else(|| read_env_file_value("DEBANK_API_KEY"))
        .or_else(|| {
            option_env!("DEBANK_APIKEY")
                .filter(|v| !v.trim().is_empty())
                .map(str::to_string)
        })
        .or_else(|| {
            option_env!("DEBANK_API_KEY")
                .filter(|v| !v.trim().is_empty())
                .map(str::to_string)
        })
}

fn okx_api_key() -> Option<String> {
    std::env::var("OKX_API_KEY")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| read_env_file_value("OKX_API_KEY"))
        .or_else(|| {
            option_env!("OKX_API_KEY")
                .filter(|v| !v.trim().is_empty())
                .map(str::to_string)
        })
}

fn okx_secret_key() -> Option<String> {
    std::env::var("OKX_SECRET_KEY")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| read_env_file_value("OKX_SECRET_KEY"))
        .or_else(|| {
            option_env!("OKX_SECRET_KEY")
                .filter(|v| !v.trim().is_empty())
                .map(str::to_string)
        })
}

fn okx_passphrase() -> Option<String> {
    std::env::var("OKX_PASSPHRASE")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| read_env_file_value("OKX_PASSPHRASE"))
        .or_else(|| {
            option_env!("OKX_PASSPHRASE")
                .filter(|v| !v.trim().is_empty())
                .map(str::to_string)
        })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OkxQuoteRequest {
    chain_index: String,
    amount: String,
    from_token_address: String,
    to_token_address: String,
    swap_mode: Option<String>,
    price_impact_protection_percent: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OkxSwapRequest {
    chain_index: String,
    amount: String,
    from_token_address: String,
    to_token_address: String,
    swap_mode: Option<String>,
    slippage_percent: String,
    user_wallet_address: String,
    price_impact_protection_percent: Option<String>,
}

type HmacSha256 = Hmac<Sha256>;

fn okx_credentials() -> Result<(String, String, String), String> {
    let api_key = okx_api_key().ok_or_else(|| "OKX_API_KEY is not configured".to_string())?;
    let secret_key =
        okx_secret_key().ok_or_else(|| "OKX_SECRET_KEY is not configured".to_string())?;
    let passphrase =
        okx_passphrase().ok_or_else(|| "OKX_PASSPHRASE is not configured".to_string())?;
    Ok((api_key, secret_key, passphrase))
}

fn utc_timestamp_millis() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = now.as_secs() as i64;
    let millis = now.subsec_millis();
    let days = total_secs.div_euclid(86_400);
    let secs_of_day = total_secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

// Howard Hinnant's civil-from-days algorithm, adapted for UTC timestamp formatting.
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year, m as u32, d as u32)
}

fn okx_query(params: &[(&str, String)]) -> String {
    params
        .iter()
        .filter(|(_, value)| !value.trim().is_empty())
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

async fn okx_get(path: &str, params: Vec<(&str, String)>) -> Result<Value, String> {
    let (api_key, secret_key, passphrase) = okx_credentials()?;
    let query = okx_query(&params);
    let request_path = if query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{query}")
    };
    let url = format!("https://web3.okx.com{request_path}");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("building OKX DEX client: {e}"))?;

    let mut last_rate_limit = None;
    for attempt in 0..=3 {
        let timestamp = utc_timestamp_millis();
        let prehash = format!("{timestamp}GET{request_path}");
        let mut mac =
            HmacSha256::new_from_slice(secret_key.as_bytes()).map_err(|e| e.to_string())?;
        mac.update(prehash.as_bytes());
        let sign = B64.encode(mac.finalize().into_bytes());

        let response = client
            .get(&url)
            .header(reqwest::header::ACCEPT, "application/json")
            .header("OK-ACCESS-KEY", &api_key)
            .header("OK-ACCESS-SIGN", sign)
            .header("OK-ACCESS-TIMESTAMP", timestamp)
            .header("OK-ACCESS-PASSPHRASE", &passphrase)
            .send()
            .await
            .map_err(|e| format!("querying OKX DEX: {e}"))?;

        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let wait = okx_retry_after(response.headers(), attempt);
            last_rate_limit = Some(wait);
            if attempt < 3 {
                tokio::time::sleep(wait).await;
                continue;
            }
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("querying OKX DEX: HTTP {status}: {body}"));
        }

        return response
            .json()
            .await
            .map_err(|e| format!("reading OKX DEX response: {e}"));
    }

    Err(format!(
        "OKX DEX rate limited. Retry after about {}s.",
        last_rate_limit
            .unwrap_or_else(|| Duration::from_secs(4))
            .as_secs()
            .max(1)
    ))
}

fn okx_retry_after(headers: &reqwest::header::HeaderMap, attempt: u32) -> Duration {
    if let Some(seconds) = headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
    {
        return Duration::from_secs(seconds.clamp(1, 20));
    }
    let backoff_ms = match attempt {
        0 => 900,
        1 => 1_800,
        2 => 3_600,
        _ => 5_000,
    };
    Duration::from_millis(backoff_ms)
}

#[tauri::command]
async fn okx_dex_supported_chains(chain_index: Option<String>) -> Result<Value, String> {
    let mut params = Vec::new();
    if let Some(chain_index) = chain_index {
        params.push(("chainIndex", chain_index));
    }
    okx_get("/api/v6/dex/aggregator/supported/chain", params).await
}

#[tauri::command]
async fn okx_dex_tokens(chain_index: String) -> Result<Value, String> {
    okx_get(
        "/api/v6/dex/aggregator/all-tokens",
        vec![("chainIndex", chain_index)],
    )
    .await
}

#[tauri::command]
async fn okx_dex_quote(req: OkxQuoteRequest) -> Result<Value, String> {
    let mut params = vec![
        ("chainIndex", req.chain_index),
        ("amount", req.amount),
        ("fromTokenAddress", req.from_token_address),
        ("toTokenAddress", req.to_token_address),
        (
            "swapMode",
            req.swap_mode.unwrap_or_else(|| "exactIn".to_string()),
        ),
    ];
    if let Some(value) = req.price_impact_protection_percent {
        params.push(("priceImpactProtectionPercent", value));
    }
    okx_get("/api/v6/dex/aggregator/quote", params).await
}

#[tauri::command]
async fn okx_dex_swap(req: OkxSwapRequest) -> Result<Value, String> {
    let mut params = vec![
        ("chainIndex", req.chain_index),
        ("amount", req.amount),
        ("fromTokenAddress", req.from_token_address),
        ("toTokenAddress", req.to_token_address),
        (
            "swapMode",
            req.swap_mode.unwrap_or_else(|| "exactIn".to_string()),
        ),
        ("slippagePercent", req.slippage_percent),
        ("userWalletAddress", req.user_wallet_address),
    ];
    if let Some(value) = req.price_impact_protection_percent {
        params.push(("priceImpactProtectionPercent", value));
    }
    okx_get("/api/v6/dex/aggregator/swap", params).await
}

#[tauri::command]
async fn okx_dex_approve_transaction(
    chain_index: String,
    token_contract_address: String,
    approve_amount: String,
) -> Result<Value, String> {
    okx_get(
        "/api/v6/dex/aggregator/approve-transaction",
        vec![
            ("chainIndex", chain_index),
            ("tokenContractAddress", token_contract_address),
            ("approveAmount", approve_amount),
        ],
    )
    .await
}

#[tauri::command]
async fn okx_dex_history(chain_index: String, tx_hash: String) -> Result<Value, String> {
    okx_get(
        "/api/v6/dex/aggregator/history",
        vec![
            ("chainIndex", chain_index),
            ("txHash", tx_hash),
            ("isFromMyProject", "true".to_string()),
        ],
    )
    .await
}

fn value_as_f64(value: Option<&Value>) -> Option<f64> {
    match value {
        Some(Value::Number(n)) => n.as_f64(),
        Some(Value::String(s)) => s.parse::<f64>().ok(),
        _ => None,
    }
}

fn value_as_string(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        _ => None,
    }
}

/// Zerion chain slug -> (display name, external hex chain id), from GET /v1/chains/.
type ZerionChainMap = HashMap<String, (String, String)>;

fn zerion_chains_cache() -> &'static Mutex<Option<ZerionChainMap>> {
    static C: OnceLock<Mutex<Option<ZerionChainMap>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

/// Prettify a Zerion chain slug ("binance-smart-chain" -> "Binance Smart Chain")
/// for the rare case the /v1/chains/ lookup is unavailable.
fn prettify_chain_slug(slug: &str) -> String {
    slug.split('-')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

async fn zerion_chain_map(key: &str) -> ZerionChainMap {
    if let Some(map) = zerion_chains_cache().lock().unwrap().clone() {
        return map;
    }
    let fetched: Result<Value, String> = async {
        reqwest::Client::builder()
            .timeout(DEFI_PROVIDER_TIMEOUT)
            .build()
            .map_err(|e| format!("building Zerion client: {e}"))?
            .get("https://api.zerion.io/v1/chains/")
            .basic_auth(key, Some(""))
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| format!("querying Zerion chains: {e}"))?
            .error_for_status()
            .map_err(|e| format!("querying Zerion chains: {e}"))?
            .json()
            .await
            .map_err(|e| format!("reading Zerion chains response: {e}"))
    }
    .await;
    match fetched {
        Ok(data) => {
            let mut map = ZerionChainMap::new();
            for item in data
                .get("data")
                .and_then(Value::as_array)
                .unwrap_or(&Vec::new())
            {
                let Some(id) = value_as_string(item.get("id")) else {
                    continue;
                };
                let name = value_as_string(item.pointer("/attributes/name"))
                    .unwrap_or_else(|| prettify_chain_slug(&id));
                let external_id = value_as_string(item.pointer("/attributes/external_id"))
                    .unwrap_or_else(|| id.clone());
                map.insert(id, (name, external_id));
            }
            *zerion_chains_cache().lock().unwrap() = Some(map.clone());
            map
        }
        Err(err) => {
            println!("[AutoDesktop] defi Zerion chains lookup failed error={err}");
            ZerionChainMap::new()
        }
    }
}

fn zerion_position_label(attributes: &Value) -> String {
    value_as_string(attributes.get("name"))
        .filter(|name| name != "Asset")
        .or_else(|| {
            value_as_string(attributes.get("position_type")).map(|t| prettify_chain_slug(&t))
        })
        .unwrap_or_else(|| "Position".to_string())
}

fn parse_zerion_positions(data: &Value, chains: &ZerionChainMap) -> (Vec<DefiPosition>, f64) {
    let Some(items) = data.get("data").and_then(Value::as_array) else {
        return (Vec::new(), 0.0);
    };
    let mut positions = Vec::new();
    let mut total_usd = 0.0;
    for (index, item) in items.iter().enumerate() {
        let attributes = item.get("attributes").unwrap_or(item);
        let balance_usd = value_as_f64(attributes.get("value")).unwrap_or(0.0);
        if balance_usd <= 0.0 {
            continue;
        }
        total_usd += balance_usd;
        let app_name = value_as_string(attributes.pointer("/application_metadata/name"))
            .or_else(|| value_as_string(attributes.get("protocol")))
            .unwrap_or_else(|| "DeFi app".to_string());
        let app_image_url = value_as_string(attributes.pointer("/application_metadata/icon/url"));
        let app_url = value_as_string(attributes.pointer("/application_metadata/url"));
        let chain_slug = value_as_string(item.pointer("/relationships/chain/data/id"))
            .unwrap_or_else(|| "unknown".to_string());
        let (network_name, chain_id) = chains
            .get(&chain_slug)
            .cloned()
            .unwrap_or_else(|| (prettify_chain_slug(&chain_slug), chain_slug.clone()));
        let mut tokens = Vec::new();
        if let Some(symbol) = value_as_string(attributes.pointer("/fungible_info/symbol")) {
            tokens.push(DefiPositionToken {
                symbol,
                balance: value_as_string(attributes.pointer("/quantity/numeric")),
                balance_usd: Some(balance_usd),
            });
        }
        let symbols = tokens.iter().map(|t| t.symbol.clone()).collect();
        let id = value_as_string(item.get("id"))
            .unwrap_or_else(|| format!("{app_name}:{chain_slug}:{index}"));
        positions.push(DefiPosition {
            id,
            app_name,
            app_image_url,
            app_url,
            network_name,
            chain_id,
            label: zerion_position_label(attributes),
            group_label: value_as_string(attributes.get("position_type"))
                .map(|t| prettify_chain_slug(&t)),
            balance_usd,
            symbols,
            tokens,
        });
    }
    positions.sort_by(|a, b| {
        b.balance_usd
            .partial_cmp(&a.balance_usd)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    (positions, total_usd)
}

/// An error plus everything that caused it, `": "`-joined.
///
/// A bare `{e}` on a reqwest error prints "error sending request for url (…)"
/// and stops — the part that matters (dns error, connection refused, operation
/// timed out, tls handshake) sits one level down in the source chain. Without
/// this, a provider failure in the log is unactionable.
fn error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut out = err.to_string();
    let mut cause = err.source();
    while let Some(e) = cause {
        out.push_str(": ");
        out.push_str(&e.to_string());
        cause = e.source();
    }
    out
}

async fn fetch_zerion_defi_positions(address: &str) -> Result<(Vec<DefiPosition>, f64), String> {
    let key = zerion_api_key().ok_or_else(|| "ZERION_APIKEY is not configured".to_string())?;
    println!("[AutoDesktop] defi Zerion start address={address}");
    let data: Value = reqwest::Client::builder()
        .timeout(DEFI_PROVIDER_TIMEOUT)
        .build()
        .map_err(|e| format!("building Zerion client: {e}"))?
        .get(format!(
            "https://api.zerion.io/v1/wallets/{address}/positions/"
        ))
        .query(&[
            ("filter[positions]", "only_complex"),
            ("currency", "usd"),
            ("filter[trash]", "only_non_trash"),
            ("sort", "value"),
        ])
        .basic_auth(&key, Some(""))
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| format!("querying Zerion: {}", error_chain(&e)))?
        .error_for_status()
        .map_err(|e| format!("querying Zerion: {}", error_chain(&e)))?
        .json()
        .await
        .map_err(|e| format!("reading Zerion response: {}", error_chain(&e)))?;
    if let Some(errors) = data.get("errors").and_then(Value::as_array) {
        let msg = errors
            .first()
            .and_then(|e| e.get("title").or_else(|| e.get("detail")))
            .and_then(Value::as_str)
            .unwrap_or("Zerion returned an error");
        return Err(msg.to_string());
    }
    let chains = zerion_chain_map(&key).await;
    let (positions, app_balance) = parse_zerion_positions(&data, &chains);
    println!(
        "[AutoDesktop] defi Zerion done address={address} positions={} appBalanceUsd={app_balance}",
        positions.len()
    );
    Ok((positions, app_balance))
}

type ZerionDefiResult = Result<(Vec<DefiPosition>, f64), String>;
type ZerionCache = HashMap<String, (Instant, Vec<DefiPosition>, f64)>;

/// How long a good Zerion answer may stand in for a failed one. Zerion's free
/// tier rate-limits often (429); falling back to DeBank then makes the DeFi
/// list and total swap between two providers' views of the same positions.
const ZERION_REUSE_MAX_AGE: Duration = Duration::from_secs(30 * 60);

fn zerion_cache() -> &'static Mutex<ZerionCache> {
    static C: OnceLock<Mutex<ZerionCache>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Remember a successful Zerion answer, or replace a failed one with the last
/// good answer for the same wallet when it is recent enough.
fn zerion_result_or_cached(
    cache: &mut ZerionCache,
    address: &str,
    result: ZerionDefiResult,
    now: Instant,
) -> ZerionDefiResult {
    let key = address.to_ascii_lowercase();
    match result {
        Ok((positions, app_balance)) => {
            cache.insert(key, (now, positions.clone(), app_balance));
            Ok((positions, app_balance))
        }
        Err(err) => match cache.get(&key) {
            Some((at, positions, app_balance))
                if now.saturating_duration_since(*at) <= ZERION_REUSE_MAX_AGE =>
            {
                println!(
                    "[AutoDesktop] defi Zerion reuse address={address} ageSecs={} error={err}",
                    now.saturating_duration_since(*at).as_secs()
                );
                Ok((positions.clone(), *app_balance))
            }
            _ => Err(err),
        },
    }
}

fn debank_chain_name(chain: &str) -> String {
    match chain {
        "eth" => "Ethereum",
        "bsc" => "BSC",
        "arb" => "Arbitrum",
        "op" => "Optimism",
        "matic" => "Polygon",
        "base" => "Base",
        "avax" => "Avalanche",
        "ftm" => "Fantom",
        "xdai" => "Gnosis",
        "linea" => "Linea",
        "zksync" => "zkSync Era",
        "scroll" => "Scroll",
        _ => chain,
    }
    .to_string()
}

fn debank_token_from_value(value: &Value) -> Option<DefiPositionToken> {
    let symbol = value_as_string(value.get("optimized_symbol"))
        .or_else(|| value_as_string(value.get("display_symbol")))
        .or_else(|| value_as_string(value.get("symbol")))?;
    let balance = value_as_string(value.get("amount"))
        .or_else(|| value_as_string(value.get("balance")))
        .or_else(|| value_as_string(value.get("raw_amount")));
    let balance_usd = value_as_f64(value.get("usd_value"))
        .or_else(|| value_as_f64(value.get("net_usd_value")))
        .or_else(|| {
            let amount = value_as_f64(value.get("amount"))?;
            let price = value_as_f64(value.get("price"))?;
            Some(amount * price)
        });
    Some(DefiPositionToken {
        symbol,
        balance,
        balance_usd,
    })
}

fn is_debank_token_list_key(key: &str) -> bool {
    key.ends_with("token_list") || key.ends_with("tokens") || key == "token"
}

/// What a position is beats what it earned. Left to serde_json's alphabetical key
/// order an LP would lead with `reward_token_list`, and since the card shows only
/// the first few tokens the fees would push the liquidity itself out of sight.
fn debank_token_list_rank(key: &str) -> u8 {
    match key {
        "supply_token_list" => 0,
        "borrow_token_list" => 1,
        "reward_token_list" => 3,
        _ => 2,
    }
}

/// True when this object holds at least one non-empty DeBank token list.
fn has_debank_token_list(value: &Value) -> bool {
    value.as_object().is_some_and(|map| {
        map.iter().any(|(key, child)| {
            is_debank_token_list_key(key) && child.as_array().is_some_and(|items| !items.is_empty())
        })
    })
}

fn collect_debank_tokens(value: &Value, out: &mut Vec<DefiPositionToken>) {
    match value {
        Value::Array(items) => {
            for item in items {
                if let Some(token) = debank_token_from_value(item) {
                    out.push(token);
                }
                collect_debank_tokens(item, out);
            }
        }
        Value::Object(map) => {
            // A position states its tokens twice: `asset_token_list` is the flat
            // holding, `detail` splits the same liquidity into supply and rewards.
            // `detail` is the richer answer — an LP's uncollected fees only show
            // up there — so when it carries token lists it wins outright, rather
            // than adding a second near-identical row per token.
            if let Some(detail) = map.get("detail").filter(|d| has_debank_token_list(d)) {
                collect_debank_tokens(detail, out);
                return;
            }
            let mut keys: Vec<&String> =
                map.keys().filter(|k| is_debank_token_list_key(k)).collect();
            keys.sort_by_key(|k| (debank_token_list_rank(k), (*k).clone()));
            for key in keys {
                collect_debank_tokens(&map[key], out);
            }
        }
        _ => {}
    }
}

fn parse_debank_positions(data: &Value) -> Result<Vec<DefiPosition>, String> {
    let apps = data
        .as_array()
        .ok_or_else(|| "DeBank returned an unexpected response".to_string())?;
    let mut positions = Vec::new();
    for (app_index, app) in apps.iter().enumerate() {
        let app_name = value_as_string(app.get("name")).unwrap_or_else(|| "DeFi app".to_string());
        let app_id = value_as_string(app.get("id")).unwrap_or_else(|| app_name.clone());
        let app_image_url = value_as_string(app.get("logo_url"));
        let app_url = value_as_string(app.get("site_url"));
        let Some(items) = app.get("portfolio_item_list").and_then(Value::as_array) else {
            continue;
        };
        for (position_index, item) in items.iter().enumerate() {
            let net_usd = value_as_f64(item.pointer("/stats/net_usd_value"))
                .or_else(|| value_as_f64(item.pointer("/stats/asset_usd_value")))
                .unwrap_or(0.0);
            if net_usd <= 0.0 {
                continue;
            }
            let chain_id = value_as_string(item.pointer("/base/chain"))
                .or_else(|| value_as_string(app.get("chain")))
                .unwrap_or_else(|| "unknown".to_string());
            let mut tokens = Vec::new();
            collect_debank_tokens(item, &mut tokens);
            let mut symbols = Vec::new();
            tokens.retain(|token| {
                let key = format!(
                    "{}:{}:{}",
                    token.symbol,
                    token.balance.as_deref().unwrap_or(""),
                    token.balance_usd.unwrap_or(0.0)
                );
                if symbols.iter().any(|s| s == &key) {
                    false
                } else {
                    symbols.push(key);
                    true
                }
            });
            let symbols = tokens.iter().fold(Vec::new(), |mut out, token| {
                if !out.iter().any(|s| s == &token.symbol) {
                    out.push(token.symbol.clone());
                }
                out
            });
            positions.push(DefiPosition {
                id: format!("debank:{app_id}:{chain_id}:{app_index}:{position_index}"),
                app_name: app_name.clone(),
                app_image_url: app_image_url.clone(),
                app_url: app_url.clone(),
                network_name: debank_chain_name(&chain_id),
                chain_id,
                label: value_as_string(item.get("name")).unwrap_or_else(|| "Position".to_string()),
                group_label: value_as_string(item.get("detail_types"))
                    .or_else(|| value_as_string(item.get("position_index"))),
                balance_usd: net_usd,
                symbols,
                tokens,
            });
        }
    }
    positions.sort_by(|a, b| {
        b.balance_usd
            .partial_cmp(&a.balance_usd)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok(positions)
}

/// GET a DeBank Pro endpoint and hand back its JSON.
///
/// DeBank answers a rejected request with a 400 and a body that names the reason
/// ("Protocol not found"), so the body is read before the status is judged —
/// `error_for_status()` alone throws that sentence away and leaves an unactionable
/// "HTTP status client error" in the log.
async fn debank_get(key: &str, url: String) -> Result<Value, String> {
    let response = reqwest::Client::builder()
        .timeout(DEFI_PROVIDER_TIMEOUT)
        .build()
        .map_err(|e| format!("building DeBank client: {e}"))?
        .get(&url)
        .header(reqwest::header::ACCEPT, "application/json")
        .header("AccessKey", key)
        .send()
        .await
        .map_err(|e| format!("querying DeBank: {}", error_chain(&e)))?;
    let status = response.status();
    let data: Value = response
        .json()
        .await
        .map_err(|e| format!("reading DeBank response: {}", error_chain(&e)))?;
    let message =
        value_as_string(data.get("message")).or_else(|| value_as_string(data.get("error_msg")));
    if !status.is_success() {
        return Err(message.unwrap_or_else(|| format!("DeBank returned HTTP {status}")));
    }
    match message {
        Some(msg) => Err(msg),
        None => Ok(data),
    }
}

async fn fetch_debank_defi_positions(address: &str) -> Result<Vec<DefiPosition>, String> {
    let key = debank_api_key().ok_or_else(|| "DEBANK_APIKEY is not configured".to_string())?;
    println!("[AutoDesktop] defi DeBank start address={address}");
    let data = debank_get(
        &key,
        format!("https://pro-openapi.debank.com/v1/user/all_complex_protocol_list?id={address}"),
    )
    .await?;
    let positions = parse_debank_positions(&data)?;
    println!(
        "[AutoDesktop] defi DeBank done address={address} positions={}",
        positions.len()
    );
    Ok(positions)
}

// ---------------------------------------------------------------------------
// Uniswap v4 supplement — buying only the part of DeBank that Zerion can't answer
//
// Zerion is the free primary source but reports no Uniswap v4 liquidity. DeBank
// does, and the sweep we fall back to today is what costs: measured against the
// live API, `all_complex_protocol_list` (every chain, every protocol) bills ~300
// units, `/v1/user/protocol` (one protocol, one chain) bills 4, and the two id
// lookups bill 1 each.
//
// So the supplement pays per position instead of per wallet. Zerion's free
// portfolio call says which chains the wallet holds anything on; DeBank's
// protocol list says which of those run Uniswap v4; only that intersection gets
// probed. Both id lookups barely move, so they persist to disk for a month, and
// probe results are held for a few minutes so remounting the wallet page or
// flipping between accounts doesn't re-bill.
// ---------------------------------------------------------------------------

const DEBANK_REGISTRY_FILE: &str = "debank-registry.json";
/// DeBank's chain list and per-chain protocol list are near-static. A month
/// between lookups keeps them current without spending a unit on every refresh.
const DEBANK_REGISTRY_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// How long a set of probe results stands in for a fresh set. The manual refresh
/// button bypasses this; only incidental re-renders are served from it.
const UNISWAP_V4_CACHE_TTL_MS: u64 = 3 * 60 * 1000;
/// Cost ceiling per address, in chains probed. Uniswap v4 runs on ~13 chains
/// today, so this bites only a wallet spread wider than the protocol itself.
const UNISWAP_V4_MAX_PROBES: usize = 16;
/// Time ceiling for the whole supplement, well inside the 30s the caller allows
/// the DeFi request. A cold registry costs a round of list lookups on top of the
/// probes; overrunning that budget must lose the supplement, never the portfolio.
const UNISWAP_V4_TIMEOUT: Duration = Duration::from_secs(18);
/// How DeBank names the protocol in `/v1/protocol/list`.
const UNISWAP_V4_PROTOCOL_NAME: &str = "Uniswap V4";

/// The DeBank id lookups, persisted so a restart doesn't re-buy them.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DebankRegistryCache {
    /// EVM chain id in decimal (`"1"`) -> DeBank chain id (`"eth"`).
    #[serde(default)]
    chains: HashMap<String, String>,
    #[serde(default)]
    chains_updated_at_ms: u64,
    /// DeBank chain id -> what `/v1/protocol/list` said about Uniswap v4 there.
    #[serde(default)]
    uniswap_v4: HashMap<String, DebankProtocolLookup>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DebankProtocolLookup {
    /// `None` records "asked, DeBank has no Uniswap v4 on this chain". That is an
    /// answer worth keeping — re-asking every refresh is how a cheap lookup turns
    /// back into a recurring bill.
    protocol_id: Option<String>,
    updated_at_ms: u64,
}

#[derive(Clone)]
struct DebankRegistry {
    path: Option<PathBuf>,
}

/// Serializes registry updates so two concurrent refreshes can't both pay for the
/// same lookup, and can't interleave writes to the cache file.
fn debank_registry_lock() -> &'static tokio::sync::Mutex<()> {
    static L: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    L.get_or_init(|| tokio::sync::Mutex::new(()))
}

type UniswapV4Cache = HashMap<String, (u64, Vec<DefiPosition>)>;

fn uniswap_v4_cache() -> &'static Mutex<UniswapV4Cache> {
    static C: OnceLock<Mutex<UniswapV4Cache>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(UniswapV4Cache::new()))
}

impl DebankRegistry {
    fn from_app<R: Runtime>(app: &AppHandle<R>) -> Self {
        Self {
            path: app
                .path()
                .app_data_dir()
                .ok()
                .map(|base| base.join(DEBANK_REGISTRY_FILE)),
        }
    }

    #[cfg(test)]
    fn at(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn load(&self) -> DebankRegistryCache {
        let Some(path) = &self.path else {
            return DebankRegistryCache::default();
        };
        let Ok(bytes) = std::fs::read(path) else {
            return DebankRegistryCache::default();
        };
        match serde_json::from_slice(&bytes) {
            Ok(cache) => cache,
            Err(err) => {
                println!("[AutoDesktop] defi DeBank registry parse failed error={err}");
                DebankRegistryCache::default()
            }
        }
    }

    fn save(&self, cache: &DebankRegistryCache) {
        let Some(path) = &self.path else { return };
        if let Some(parent) = path.parent() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                println!("[AutoDesktop] defi DeBank registry mkdir failed error={err}");
                return;
            }
        }
        match serde_json::to_vec_pretty(cache) {
            Ok(json) => {
                if let Err(err) = std::fs::write(path, json) {
                    println!("[AutoDesktop] defi DeBank registry write failed error={err}");
                }
            }
            Err(err) => println!("[AutoDesktop] defi DeBank registry serialize failed error={err}"),
        }
    }

    /// Resolve EVM chain ids to the DeBank Uniswap v4 protocol ids worth probing,
    /// buying whichever lookups the cache can't answer. Chains DeBank doesn't
    /// carry, and chains without Uniswap v4, drop out here rather than costing a
    /// probe.
    async fn uniswap_v4_targets(&self, key: &str, evm_chain_ids: &[u64]) -> Vec<(u64, String)> {
        let _guard = debank_registry_lock().lock().await;
        let mut cache = self.load();
        let now = unix_time_ms();
        let mut dirty = false;

        if cache.chains.is_empty()
            || now.saturating_sub(cache.chains_updated_at_ms) > DEBANK_REGISTRY_TTL_MS
        {
            match debank_get(
                key,
                "https://pro-openapi.debank.com/v1/chain/list".to_string(),
            )
            .await
            {
                Ok(data) => {
                    let chains = parse_debank_chain_ids(&data);
                    if chains.is_empty() {
                        println!("[AutoDesktop] defi DeBank chain list returned no chains");
                    } else {
                        println!(
                            "[AutoDesktop] defi DeBank chain list refreshed chains={}",
                            chains.len()
                        );
                        cache.chains = chains;
                        cache.chains_updated_at_ms = now;
                        dirty = true;
                    }
                }
                Err(err) => println!("[AutoDesktop] defi DeBank chain list failed error={err}"),
            }
        }

        let mut targets = Vec::new();
        let mut pending = Vec::new();
        for evm_chain_id in evm_chain_ids {
            let Some(debank_chain) = cache.chains.get(&evm_chain_id.to_string()).cloned() else {
                continue;
            };
            match cache
                .uniswap_v4
                .get(&debank_chain)
                .filter(|entry| now.saturating_sub(entry.updated_at_ms) <= DEBANK_REGISTRY_TTL_MS)
            {
                Some(entry) => {
                    if let Some(protocol_id) = &entry.protocol_id {
                        targets.push((*evm_chain_id, protocol_id.clone()));
                    }
                }
                None => pending.push((*evm_chain_id, debank_chain)),
            }
        }

        // A cold cache owes one lookup per active chain. Run them together: served
        // one at a time they take longer than the whole DeFi request is allowed.
        let lookups: Vec<_> = pending
            .into_iter()
            .map(|(evm_chain_id, debank_chain)| {
                let key = key.to_string();
                tauri::async_runtime::spawn(async move {
                    let url = format!(
                        "https://pro-openapi.debank.com/v1/protocol/list?chain_id={debank_chain}"
                    );
                    let found = debank_get(&key, url)
                        .await
                        .map(|data| find_uniswap_v4_protocol_id(&data));
                    (evm_chain_id, debank_chain, found)
                })
            })
            .collect();
        for lookup in lookups {
            let Ok((evm_chain_id, debank_chain, found)) = lookup.await else {
                println!("[AutoDesktop] defi DeBank protocol list task failed");
                continue;
            };
            match found {
                Ok(protocol_id) => {
                    println!(
                        "[AutoDesktop] defi DeBank protocol list chain={debank_chain} uniswapV4={}",
                        protocol_id.as_deref().unwrap_or("none")
                    );
                    if let Some(id) = &protocol_id {
                        targets.push((evm_chain_id, id.clone()));
                    }
                    cache.uniswap_v4.insert(
                        debank_chain,
                        DebankProtocolLookup {
                            protocol_id,
                            updated_at_ms: now,
                        },
                    );
                    dirty = true;
                }
                Err(err) => println!(
                    "[AutoDesktop] defi DeBank protocol list failed chain={debank_chain} error={err}"
                ),
            }
        }

        // Back into the caller's order — richest chain first — so that if the
        // probe ceiling clips the tail it clips the least valuable chains.
        let rank: HashMap<u64, usize> = evm_chain_ids
            .iter()
            .enumerate()
            .map(|(index, id)| (*id, index))
            .collect();
        targets.sort_by_key(|(id, _)| rank.get(id).copied().unwrap_or(usize::MAX));

        if dirty {
            self.save(&cache);
        }
        targets
    }
}

/// `/v1/chain/list` -> decimal EVM chain id -> DeBank chain id.
fn parse_debank_chain_ids(data: &Value) -> HashMap<String, String> {
    let Some(items) = data.as_array() else {
        return HashMap::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let debank_id = value_as_string(item.get("id"))?;
            let community_id = value_as_f64(item.get("community_id"))?;
            Some((format!("{}", community_id as u64), debank_id))
        })
        .collect()
}

/// `/v1/protocol/list` -> the chain's Uniswap v4 protocol id, when it has one.
///
/// Matched on both the name and the id shape (`uniswap4` on Ethereum,
/// `{chain}_uniswap4` elsewhere) so a restyled label or a renamed id on its own
/// doesn't silently drop a chain. `has_supported_portfolio: false` means DeBank
/// can't answer a position query there, so that chain is not worth probing.
fn find_uniswap_v4_protocol_id(data: &Value) -> Option<String> {
    let items = data.as_array()?;
    items.iter().find_map(|item| {
        let id = value_as_string(item.get("id"))?;
        let named = value_as_string(item.get("name"))
            .is_some_and(|name| name.eq_ignore_ascii_case(UNISWAP_V4_PROTOCOL_NAME));
        let shaped = id == "uniswap4" || id.ends_with("_uniswap4");
        let supported = item
            .get("has_supported_portfolio")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        ((named || shaped) && supported).then_some(id)
    })
}

/// Zerion's free portfolio call -> the chain slugs the wallet holds value on,
/// richest first. A chain the wallet has nothing on can't hold an LP either, so
/// leaving it out of the probe set costs no coverage.
fn parse_zerion_active_chain_slugs(data: &Value) -> Vec<String> {
    let Some(map) = data
        .pointer("/data/attributes/positions_distribution_by_chain")
        .and_then(Value::as_object)
    else {
        return Vec::new();
    };
    let mut chains: Vec<(String, f64)> = map
        .iter()
        .filter_map(|(slug, value)| {
            let usd = value_as_f64(Some(value))?;
            (usd > 0.0).then(|| (slug.clone(), usd))
        })
        .collect();
    chains.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    chains.into_iter().map(|(slug, _)| slug).collect()
}

async fn fetch_zerion_active_chain_slugs(key: &str, address: &str) -> Result<Vec<String>, String> {
    let data: Value = reqwest::Client::builder()
        .timeout(DEFI_PROVIDER_TIMEOUT)
        .build()
        .map_err(|e| format!("building Zerion client: {e}"))?
        .get(format!(
            "https://api.zerion.io/v1/wallets/{address}/portfolio"
        ))
        // Without `no_filter` Zerion answers with simple positions only, and a
        // wallet whose whole balance on a chain sits inside a protocol would look
        // inactive there.
        .query(&[("currency", "usd"), ("filter[positions]", "no_filter")])
        .basic_auth(key, Some(""))
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| format!("querying Zerion portfolio: {}", error_chain(&e)))?
        .error_for_status()
        .map_err(|e| format!("querying Zerion portfolio: {}", error_chain(&e)))?
        .json()
        .await
        .map_err(|e| format!("reading Zerion portfolio response: {}", error_chain(&e)))?;
    Ok(parse_zerion_active_chain_slugs(&data))
}

/// `/v1/user/protocol` answers with one protocol object; `parse_debank_positions`
/// speaks the array shape the `*_protocol_list` endpoints return.
fn parse_debank_protocol_positions(data: &Value) -> Result<Vec<DefiPosition>, String> {
    if data.get("portfolio_item_list").is_none() {
        return Err("DeBank returned an unexpected protocol response".to_string());
    }
    parse_debank_positions(&Value::Array(vec![data.clone()]))
}

/// Restate a supplemented position in the primary source's chain vocabulary, so
/// "eth" doesn't sit next to "0x1" in one list.
fn relabel_position_chain(
    mut position: DefiPosition,
    chain_id: &str,
    network_name: &str,
) -> DefiPosition {
    position.chain_id = chain_id.to_string();
    position.network_name = network_name.to_string();
    position
}

/// Fold the supplement into the primary set, dropping anything the primary source
/// already reports for the same app on the same chain. Zerion has no Uniswap v4
/// coverage today; the guard is what keeps the day it gains some from double-
/// counting the same liquidity. Returns how many positions were added.
fn merge_uniswap_v4_positions(
    primary: &mut Vec<DefiPosition>,
    supplement: Vec<DefiPosition>,
) -> usize {
    let existing: Vec<(String, String)> = primary
        .iter()
        .map(|p| (p.chain_id.to_lowercase(), p.app_name.to_lowercase()))
        .collect();
    let added: Vec<DefiPosition> = supplement
        .into_iter()
        .filter(|p| {
            let key = (p.chain_id.to_lowercase(), p.app_name.to_lowercase());
            !existing.contains(&key)
        })
        .collect();
    let count = added.len();
    if count > 0 {
        primary.extend(added);
        primary.sort_by(|a, b| {
            b.balance_usd
                .partial_cmp(&a.balance_usd)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }
    count
}

fn cached_uniswap_v4_positions(address: &str) -> Option<Vec<DefiPosition>> {
    let cache = uniswap_v4_cache().lock().unwrap();
    let (stored_at, positions) = cache.get(&address.to_lowercase())?;
    (unix_time_ms().saturating_sub(*stored_at) <= UNISWAP_V4_CACHE_TTL_MS)
        .then(|| positions.clone())
}

fn store_uniswap_v4_positions(address: &str, positions: &[DefiPosition]) {
    let now = unix_time_ms();
    let mut cache = uniswap_v4_cache().lock().unwrap();
    // Browsing watch-only addresses would otherwise pile up entries nothing ever
    // reads again; an expired one has no value to anyone.
    cache.retain(|_, (stored_at, _)| now.saturating_sub(*stored_at) <= UNISWAP_V4_CACHE_TTL_MS);
    cache.insert(address.to_lowercase(), (now, positions.to_vec()));
}

/// The Uniswap v4 positions Zerion left out, for the chains the wallet is active
/// on. Errors are returned, not swallowed: the caller logs them and still serves
/// the Zerion set, because a supplement that fails must not cost the user their
/// primary portfolio.
async fn fetch_uniswap_v4_positions(
    registry: &DebankRegistry,
    zerion_key: &str,
    debank_key: &str,
    address: &str,
    force: bool,
) -> Result<Vec<DefiPosition>, String> {
    if !force {
        if let Some(cached) = cached_uniswap_v4_positions(address) {
            println!(
                "[AutoDesktop] defi Uniswap v4 source=cache address={address} positions={}",
                cached.len()
            );
            return Ok(cached);
        }
    }

    let slugs = fetch_zerion_active_chain_slugs(zerion_key, address).await?;
    let zerion_chains = zerion_chain_map(zerion_key).await;
    // Zerion names chains by slug and DeBank by its own id; the EVM chain id is
    // what both agree on, so it is the hinge between the two vocabularies.
    let mut by_evm_chain_id: HashMap<u64, (String, String)> = HashMap::new();
    let mut evm_chain_ids = Vec::new();
    for slug in &slugs {
        let Some((network_name, external_id)) = zerion_chains.get(slug) else {
            continue;
        };
        let Ok(evm_chain_id) = u64::from_str_radix(external_id.trim_start_matches("0x"), 16) else {
            continue;
        };
        if by_evm_chain_id
            .insert(evm_chain_id, (external_id.clone(), network_name.clone()))
            .is_none()
        {
            evm_chain_ids.push(evm_chain_id);
        }
    }

    let mut targets = registry
        .uniswap_v4_targets(debank_key, &evm_chain_ids)
        .await;
    if targets.len() > UNISWAP_V4_MAX_PROBES {
        println!(
            "[AutoDesktop] defi Uniswap v4 probe limit address={address} candidates={} probing={UNISWAP_V4_MAX_PROBES}",
            targets.len()
        );
        targets.truncate(UNISWAP_V4_MAX_PROBES);
    }
    println!(
        "[AutoDesktop] defi Uniswap v4 start address={address} activeChains={} probes={} estimatedUnits={}",
        slugs.len(),
        targets.len(),
        targets.len() * 4
    );
    if targets.is_empty() {
        store_uniswap_v4_positions(address, &[]);
        return Ok(Vec::new());
    }

    let probes: Vec<_> = targets
        .into_iter()
        .map(|(evm_chain_id, protocol_id)| {
            let key = debank_key.to_string();
            let address = address.to_string();
            tauri::async_runtime::spawn(async move {
                let url = format!(
                    "https://pro-openapi.debank.com/v1/user/protocol?id={address}&protocol_id={protocol_id}"
                );
                let result = debank_get(&key, url)
                    .await
                    .and_then(|data| parse_debank_protocol_positions(&data));
                (evm_chain_id, protocol_id, result)
            })
        })
        .collect();

    let mut positions = Vec::new();
    for probe in probes {
        let Ok((evm_chain_id, protocol_id, result)) = probe.await else {
            println!("[AutoDesktop] defi Uniswap v4 probe task failed address={address}");
            continue;
        };
        match result {
            Ok(found) => {
                let Some((chain_id, network_name)) = by_evm_chain_id.get(&evm_chain_id) else {
                    continue;
                };
                positions.extend(
                    found
                        .into_iter()
                        .map(|p| relabel_position_chain(p, chain_id, network_name)),
                );
            }
            Err(err) => println!(
                "[AutoDesktop] defi Uniswap v4 probe failed address={address} protocol={protocol_id} error={err}"
            ),
        }
    }
    positions.sort_by(|a, b| {
        b.balance_usd
            .partial_cmp(&a.balance_usd)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    println!(
        "[AutoDesktop] defi Uniswap v4 done address={address} positions={}",
        positions.len()
    );
    store_uniswap_v4_positions(address, &positions);
    Ok(positions)
}

fn custom_defi_providers() -> &'static [CustomDefiProvider] {
    &[CustomDefiProvider {
        name: "XStake Farming",
        fetch: |price_oracle, address| {
            Box::pin(fetch_xstake_farming_positions(price_oracle, address))
        },
    }]
}

async fn fetch_custom_defi_positions(
    price_oracle: PriceOracleStore,
    address: &str,
) -> Result<Vec<DefiPosition>, String> {
    let mut positions = Vec::new();
    for provider in custom_defi_providers() {
        let provider_positions = (provider.fetch)(price_oracle.clone(), address.to_string())
            .await
            .map_err(|e| format!("{}: {e}", provider.name))?;
        positions.extend(provider_positions);
    }
    positions.sort_by(|a, b| {
        b.balance_usd
            .partial_cmp(&a.balance_usd)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok(positions)
}

fn merge_defi_positions(
    primary_source: &str,
    primary: Vec<DefiPosition>,
    custom: Result<Vec<DefiPosition>, String>,
) -> DefiPositionsResponse {
    match custom {
        Ok(custom_positions) if !custom_positions.is_empty() => {
            let mut positions = primary;
            positions.extend(custom_positions);
            positions.sort_by(|a, b| {
                b.balance_usd
                    .partial_cmp(&a.balance_usd)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            DefiPositionsResponse {
                source: format!("{primary_source} + Custom"),
                positions,
            }
        }
        Ok(_) => DefiPositionsResponse {
            source: primary_source.to_string(),
            positions: primary,
        },
        Err(err) => {
            println!("[AutoDesktop] defi custom failed source={primary_source} error={err}");
            DefiPositionsResponse {
                source: primary_source.to_string(),
                positions: primary,
            }
        }
    }
}

fn custom_only_defi_response(
    custom: Result<Vec<DefiPosition>, String>,
) -> Result<DefiPositionsResponse, String> {
    let positions = custom?;
    if positions.is_empty() {
        return Err("no custom DeFi positions detected".to_string());
    }
    Ok(DefiPositionsResponse {
        source: "Custom".to_string(),
        positions,
    })
}

const XSTAKE_APP_URL: &str = "https://xstake.wanchain.org";
const XSTAKE_CHAIN_ID: &str = "0x378";
const XSTAKE_CHAIN_NAME: &str = "Wanchain";
const WANCHAIN_MULTICALL3: &str = "0xcA11bde05977b3631167028862bE2a173976CA11";
const XWAN_PRICE_ID: &str = "wanchain";

const XSTAKE_FARMING_POOLS: &[XStakeFarmingPool] = &[
    XStakeFarmingPool {
        key: "BTC",
        contract: "0x9E2C89d3b48ecB0761764D6a17594dA74f20f3Bb",
        staking_symbol: "xWAN",
        staking_decimals: 18,
        staking_price_id: XWAN_PRICE_ID,
        reward_symbol: "wanBTC",
        reward_decimals: 8,
        reward_price_id: "bitcoin",
        reward_addr: "0x50c439B6d602297252505a6799d84eA5928bCFb6",
    },
    XStakeFarmingPool {
        key: "ETH",
        contract: "0xaeC46cd03C3489EF8C2061E66D3d57FA0171387D",
        staking_symbol: "xWAN",
        staking_decimals: 18,
        staking_price_id: XWAN_PRICE_ID,
        reward_symbol: "wanETH",
        reward_decimals: 18,
        reward_price_id: "ethereum",
        reward_addr: "0xE3aE74D1518A76715aB4C7BeDF1af73893cd435A",
    },
    XStakeFarmingPool {
        key: "USDT",
        contract: "0x3167219355f3532B8B37e24213118A0898AdcdFB",
        staking_symbol: "xWAN",
        staking_decimals: 18,
        staking_price_id: XWAN_PRICE_ID,
        reward_symbol: "wanUSDT",
        reward_decimals: 6,
        reward_price_id: "tether",
        reward_addr: "0x11e77E27Af5539872efEd10abaA0b408cfd9fBBD",
    },
    XStakeFarmingPool {
        key: "USDC",
        contract: "0x47047A990523F08743245160BD07dEcC442efA9C",
        staking_symbol: "xWAN",
        staking_decimals: 18,
        staking_price_id: XWAN_PRICE_ID,
        reward_symbol: "wanUSDC",
        reward_decimals: 6,
        reward_price_id: "usd-coin",
        reward_addr: "0x52A9CEA01c4CBDd669883e41758B8eB8e8E2B34b",
    },
    XStakeFarmingPool {
        key: "wanBTC",
        contract: "0x6bcae52a20d3E7C1a2eBFfEf11e0026501979F03",
        staking_symbol: "wanBTC",
        staking_decimals: 8,
        staking_price_id: "bitcoin",
        reward_symbol: "xWAN",
        reward_decimals: 18,
        reward_price_id: XWAN_PRICE_ID,
        reward_addr: "0x2eA407Aa69be7367BF231E76B51fab9eC436766c",
    },
    XStakeFarmingPool {
        key: "wanETH",
        contract: "0x2C2dffc78340068c61A706d900578Cf6Fd3Bc07F",
        staking_symbol: "wanETH",
        staking_decimals: 18,
        staking_price_id: "ethereum",
        reward_symbol: "xWAN",
        reward_decimals: 18,
        reward_price_id: XWAN_PRICE_ID,
        reward_addr: "0x2eA407Aa69be7367BF231E76B51fab9eC436766c",
    },
    XStakeFarmingPool {
        key: "wanUSDT",
        contract: "0x812C7F30a67598e32a351a64495F8426AB83Ff20",
        staking_symbol: "wanUSDT",
        staking_decimals: 6,
        staking_price_id: "tether",
        reward_symbol: "xWAN",
        reward_decimals: 18,
        reward_price_id: XWAN_PRICE_ID,
        reward_addr: "0x2eA407Aa69be7367BF231E76B51fab9eC436766c",
    },
    XStakeFarmingPool {
        key: "wanUSDC",
        contract: "0x45eda9edA919c5977f0a55f2BD69494B72cc232F",
        staking_symbol: "wanUSDC",
        staking_decimals: 6,
        staking_price_id: "usd-coin",
        reward_symbol: "xWAN",
        reward_decimals: 18,
        reward_price_id: XWAN_PRICE_ID,
        reward_addr: "0x2eA407Aa69be7367BF231E76B51fab9eC436766c",
    },
];

async fn fetch_xstake_farming_positions(
    price_oracle: PriceOracleStore,
    address: String,
) -> Result<Vec<DefiPosition>, String> {
    println!("[AutoDesktop] defi custom XStake start address={address}");
    let chain = find_chain(XSTAKE_CHAIN_ID)
        .ok_or_else(|| "Wanchain chain config is missing".to_string())?;
    let prices = match price_oracle
        .prices(&["wanchain", "bitcoin", "ethereum", "tether", "usd-coin"])
        .await
    {
        Ok(prices) => prices,
        Err(err) => {
            println!("[AutoDesktop] defi custom XStake prices unavailable error={err}");
            HashMap::new()
        }
    };
    let pool_amounts = fetch_xstake_pool_amounts(&chain, &address).await?;
    let mut positions = Vec::new();
    for (pool, (staked_raw, reward_raw)) in XSTAKE_FARMING_POOLS.iter().zip(pool_amounts) {
        if staked_raw == 0.0 && reward_raw == 0.0 {
            continue;
        }
        positions.push(xstake_position_from_amounts(
            pool, staked_raw, reward_raw, &prices,
        ));
    }
    println!(
        "[AutoDesktop] defi custom XStake done address={address} positions={}",
        positions.len()
    );
    Ok(positions)
}

async fn fetch_xstake_pool_amounts(
    chain: &ChainCfg,
    address: &str,
) -> Result<Vec<(f64, f64)>, String> {
    let mut calls = Vec::new();
    for pool in XSTAKE_FARMING_POOLS {
        calls.push(Multicall3Call {
            target: pool.contract.to_string(),
            call_data: call_data("userInfo(address)", &[address]),
        });
        calls.push(Multicall3Call {
            target: pool.contract.to_string(),
            call_data: call_data(
                "pendingReward(address,address)",
                &[address, pool.reward_addr],
            ),
        });
    }
    let return_data = eth_call_multicall3(chain, &calls).await?;
    let mut amounts = Vec::new();
    for (pool_index, pair) in return_data.chunks_exact(2).enumerate() {
        let staked = match &pair[0] {
            Some(data) => first_u256_word_as_f64(data)?,
            None => {
                println!(
                    "[AutoDesktop] defi custom XStake multicall userInfo failed pool={}",
                    XSTAKE_FARMING_POOLS[pool_index].key
                );
                0.0
            }
        };
        let reward = match &pair[1] {
            Some(data) => first_u256_word_as_f64(data)?,
            None => {
                println!(
                    "[AutoDesktop] defi custom XStake multicall pendingReward failed pool={}",
                    XSTAKE_FARMING_POOLS[pool_index].key
                );
                0.0
            }
        };
        amounts.push((staked, reward));
    }
    Ok(amounts)
}

fn xstake_position_from_amounts(
    pool: &XStakeFarmingPool,
    staked_raw: f64,
    reward_raw: f64,
    prices: &HashMap<String, f64>,
) -> DefiPosition {
    let staked_amount = raw_token_amount(staked_raw, pool.staking_decimals);
    let reward_amount = raw_token_amount(reward_raw, pool.reward_decimals);
    let staked_usd = prices
        .get(pool.staking_price_id)
        .map(|price| staked_amount * price);
    let reward_usd = prices
        .get(pool.reward_price_id)
        .map(|price| reward_amount * price);
    let mut tokens = Vec::new();
    if staked_raw > 0.0 {
        tokens.push(DefiPositionToken {
            symbol: pool.staking_symbol.to_string(),
            balance: Some(format_token_amount(staked_amount)),
            balance_usd: staked_usd,
        });
    }
    if reward_raw > 0.0 {
        tokens.push(DefiPositionToken {
            symbol: pool.reward_symbol.to_string(),
            balance: Some(format_token_amount(reward_amount)),
            balance_usd: reward_usd,
        });
    }
    let mut symbols = Vec::new();
    for token in &tokens {
        if !symbols.iter().any(|s| s == &token.symbol) {
            symbols.push(token.symbol.clone());
        }
    }
    DefiPosition {
        id: format!("custom:xstake:{XSTAKE_CHAIN_ID}:{}", pool.key),
        app_name: "XStake Farming".to_string(),
        app_image_url: Some(xstake_logo_data_uri()),
        app_url: Some(XSTAKE_APP_URL.to_string()),
        network_name: XSTAKE_CHAIN_NAME.to_string(),
        chain_id: XSTAKE_CHAIN_ID.to_string(),
        label: format!("{} farming", pool.staking_symbol),
        group_label: Some(format!("Earn {}", pool.reward_symbol)),
        balance_usd: staked_usd.unwrap_or(0.0) + reward_usd.unwrap_or(0.0),
        symbols,
        tokens,
    }
}

fn call_data(signature: &str, address_args: &[&str]) -> String {
    let mut data = evm_function_selector(signature);
    for address in address_args {
        data.push_str(&encode_evm_address_arg(address));
    }
    data
}

fn evm_function_selector(signature: &str) -> String {
    let hash = Keccak256::digest(signature.as_bytes());
    format!("0x{}", hex::encode(&hash[..4]))
}

fn encode_evm_address_arg(address: &str) -> String {
    let hex = address
        .strip_prefix("0x")
        .or_else(|| address.strip_prefix("0X"))
        .expect("validated EVM address must be 0x-prefixed");
    format!("{:0>64}", hex.to_ascii_lowercase())
}

async fn eth_call_multicall3(
    chain: &ChainCfg,
    calls: &[Multicall3Call],
) -> Result<Vec<Option<String>>, String> {
    let data = encode_multicall3_aggregate3(calls)?;
    let result = node_rpc_call(
        chain,
        "eth_call",
        &[
            json!({ "to": WANCHAIN_MULTICALL3, "data": data }),
            json!("latest"),
        ],
    )
    .await?;
    let raw = result
        .as_str()
        .ok_or_else(|| "eth_call returned a non-string result".to_string())?;
    decode_multicall3_aggregate3(raw, calls.len())
}

fn encode_multicall3_aggregate3(calls: &[Multicall3Call]) -> Result<String, String> {
    let mut tails = String::new();
    let mut offsets = String::new();
    let mut tail_offset = calls.len() * 32;
    for call in calls {
        offsets.push_str(&encode_usize_word(tail_offset));
        let tuple = encode_multicall3_call(call)?;
        tail_offset += tuple.len() / 2;
        tails.push_str(&tuple);
    }
    let mut data = evm_function_selector("aggregate3((address,bool,bytes)[])");
    data.push_str(&encode_usize_word(32));
    data.push_str(&encode_usize_word(calls.len()));
    data.push_str(&offsets);
    data.push_str(&tails);
    Ok(data)
}

fn encode_multicall3_call(call: &Multicall3Call) -> Result<String, String> {
    let bytes = hex_payload(&call.call_data)?;
    let mut tuple = String::new();
    tuple.push_str(&encode_evm_address_arg(&call.target));
    tuple.push_str(&encode_bool_word(true));
    tuple.push_str(&encode_usize_word(96));
    tuple.push_str(&encode_usize_word(bytes.len() / 2));
    tuple.push_str(bytes);
    tuple.push_str(&"0".repeat(padded_hex_len(bytes.len()) - bytes.len()));
    Ok(tuple)
}

fn decode_multicall3_aggregate3(
    raw: &str,
    expected_len: usize,
) -> Result<Vec<Option<String>>, String> {
    let bytes = hex_payload(raw)?;
    let offset = read_word_usize(bytes, 0)?;
    let array_start = offset * 2;
    let len = read_word_usize(bytes, array_start)?;
    if len != expected_len {
        return Err(format!(
            "multicall returned {len} results, expected {expected_len}"
        ));
    }
    let head_start = array_start + 64;
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        let tuple_offset = read_word_usize(bytes, head_start + i * 64)?;
        let tuple_start = head_start + tuple_offset * 2;
        let success = read_word_usize(bytes, tuple_start)? == 1;
        let return_offset = read_word_usize(bytes, tuple_start + 64)?;
        let return_start = tuple_start + return_offset * 2;
        let return_len = read_word_usize(bytes, return_start)?;
        let data_start = return_start + 64;
        let data_end = data_start + return_len * 2;
        if data_end > bytes.len() {
            return Err("multicall return data is truncated".to_string());
        }
        out.push(if success {
            Some(format!("0x{}", &bytes[data_start..data_end]))
        } else {
            None
        });
    }
    Ok(out)
}

fn first_u256_word_as_f64(raw: &str) -> Result<f64, String> {
    let hex = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .ok_or_else(|| format!("invalid uint256 return: {raw}"))?;
    if hex.len() < 64 {
        return Err(format!("short uint256 return: {raw}"));
    }
    u256_hex_to_f64(&hex[..64])
}

fn u256_hex_to_f64(hex: &str) -> Result<f64, String> {
    let mut out = 0.0;
    for c in hex.chars() {
        let digit = c
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex digit in uint256: {hex}"))?;
        out = out * 16.0 + f64::from(digit);
    }
    Ok(out)
}

fn read_word_usize(hex: &str, start: usize) -> Result<usize, String> {
    let end = start + 64;
    if end > hex.len() {
        return Err("ABI word is truncated".to_string());
    }
    usize::from_str_radix(&hex[start..end], 16)
        .map_err(|_| format!("ABI word is too large or invalid: {}", &hex[start..end]))
}

fn encode_usize_word(value: usize) -> String {
    format!("{value:064x}")
}

fn encode_bool_word(value: bool) -> String {
    encode_usize_word(if value { 1 } else { 0 })
}

fn hex_payload(value: &str) -> Result<&str, String> {
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .ok_or_else(|| format!("hex value must be 0x-prefixed: {value}"))?;
    if hex.len() % 2 != 0 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("invalid hex payload: {value}"));
    }
    Ok(hex)
}

fn padded_hex_len(len: usize) -> usize {
    ((len + 63) / 64) * 64
}

fn raw_token_amount(raw: f64, decimals: u8) -> f64 {
    raw / 10_f64.powi(i32::from(decimals))
}

fn format_token_amount(amount: f64) -> String {
    let mut s = format!("{amount:.8}");
    while s.contains('.') && s.ends_with('0') {
        s.pop();
    }
    if s.ends_with('.') {
        s.pop();
    }
    s
}

const PRICE_ORACLE_FILE: &str = "price-oracle.json";
const PRICE_ORACLE_TTL_MS: u64 = 30 * 60 * 1000;
const DIAGNOSTIC_LOG_FILE: &str = "autodesktop.log";
const PRICE_ORACLE_USER_AGENT: &str = concat!(
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AutoDesktop/",
    env!("CARGO_PKG_VERSION")
);

impl PriceOracleStore {
    fn from_app<R: Runtime>(app: &AppHandle<R>) -> Self {
        let app_data_dir = app.path().app_data_dir().ok();
        Self {
            path: app_data_dir
                .as_ref()
                .map(|base| base.join(PRICE_ORACLE_FILE)),
            log_path: app_data_dir
                .as_ref()
                .map(|base| base.join(DIAGNOSTIC_LOG_FILE)),
        }
    }

    #[cfg(test)]
    fn in_memory() -> Self {
        Self {
            path: None,
            log_path: None,
        }
    }

    fn log(&self, message: impl AsRef<str>) {
        if let Some(path) = &self.log_path {
            append_diagnostic_log(path, message.as_ref());
        }
    }

    async fn prices(&self, ids: &[&str]) -> Result<HashMap<String, f64>, String> {
        Ok(self
            .entries(ids)
            .await?
            .into_iter()
            .map(|(id, entry)| (id, entry.usd))
            .collect())
    }

    async fn entries(&self, ids: &[&str]) -> Result<HashMap<String, PriceOracleEntry>, String> {
        let mut cache = self.load_cache();
        let now = unix_time_ms();
        let fresh_enough = now.saturating_sub(cache.updated_at_ms) <= PRICE_ORACLE_TTL_MS;
        if fresh_enough && price_cache_has_all(&cache, ids) {
            self.log(format!(
                "version={} price oracle source=cache ids={} cached_count={}",
                env!("CARGO_PKG_VERSION"),
                ids.join(","),
                cache.prices.len()
            ));
            println!(
                "[AutoDesktop] price oracle source=cache ids={}",
                ids.join(",")
            );
            return Ok(price_cache_entries(&cache, ids));
        }

        self.log(format!(
            "version={} price oracle fetch start ids={} cache_fresh={} cache_count={}",
            env!("CARGO_PKG_VERSION"),
            ids.join(","),
            fresh_enough,
            cache.prices.len()
        ));
        match fetch_price_oracle_entries(ids, self.log_path.as_deref()).await {
            Ok(fresh) => {
                let fresh_count = fresh.len();
                println!(
                    "[AutoDesktop] price oracle source=coingecko ids={}",
                    ids.join(",")
                );
                cache.updated_at_ms = now;
                cache.prices.extend(fresh);
                self.save_cache(&cache);
                let picked = price_cache_entries(&cache, ids);
                self.log(format!(
                    "version={} price oracle source=coingecko ids={} fresh_count={} returned_count={} cache_count={}",
                    env!("CARGO_PKG_VERSION"),
                    ids.join(","),
                    fresh_count,
                    picked.len(),
                    cache.prices.len()
                ));
                Ok(picked)
            }
            Err(err) => {
                let cached = price_cache_entries(&cache, ids);
                if cached.is_empty() {
                    self.log(format!(
                        "version={} price oracle failed ids={} error={err}",
                        env!("CARGO_PKG_VERSION"),
                        ids.join(",")
                    ));
                    Err(err)
                } else {
                    self.log(format!(
                        "version={} price oracle source=stale-cache ids={} returned_count={} error={err}",
                        env!("CARGO_PKG_VERSION"),
                        ids.join(","),
                        cached.len()
                    ));
                    println!(
                        "[AutoDesktop] price oracle source=stale-cache ids={} error={err}",
                        ids.join(",")
                    );
                    Ok(cached)
                }
            }
        }
    }

    fn load_cache(&self) -> PriceOracleCache {
        let Some(path) = &self.path else {
            self.log("price oracle load cache skipped path=none");
            return PriceOracleCache::default();
        };
        let Ok(bytes) = std::fs::read(path) else {
            self.log(format!(
                "price oracle load cache miss path={}",
                path.display()
            ));
            return PriceOracleCache::default();
        };
        match serde_json::from_slice(&bytes) {
            Ok(cache) => cache,
            Err(err) => {
                self.log(format!(
                    "price oracle load cache parse failed path={} error={err}",
                    path.display()
                ));
                PriceOracleCache::default()
            }
        }
    }

    fn save_cache(&self, cache: &PriceOracleCache) {
        let Some(path) = &self.path else {
            self.log("price oracle save cache skipped path=none");
            return;
        };
        if let Some(parent) = path.parent() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                self.log(format!(
                    "price oracle create cache dir failed path={} error={err}",
                    parent.display()
                ));
                println!("[AutoDesktop] price oracle create cache dir failed error={err}");
                return;
            }
        }
        match serde_json::to_vec_pretty(cache) {
            Ok(json) => {
                if let Err(err) = std::fs::write(path, json) {
                    self.log(format!(
                        "price oracle write cache failed path={} error={err}",
                        path.display()
                    ));
                    println!("[AutoDesktop] price oracle write cache failed error={err}");
                } else {
                    self.log(format!(
                        "price oracle write cache ok path={} cache_count={}",
                        path.display(),
                        cache.prices.len()
                    ));
                }
            }
            Err(err) => {
                self.log(format!("price oracle serialize cache failed error={err}"));
                println!("[AutoDesktop] price oracle serialize cache failed error={err}");
            }
        }
    }
}

fn diagnostic_log_path<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|base| base.join(DIAGNOSTIC_LOG_FILE))
        .map_err(|e| format!("diagnostic log path: {e}"))
}

fn log_diagnostic<R: Runtime>(app: &AppHandle<R>, message: impl AsRef<str>) {
    if let Ok(path) = diagnostic_log_path(app) {
        append_diagnostic_log(&path, message.as_ref());
    }
}

fn append_diagnostic_log(path: &Path, message: &str) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "[{}] {}", unix_time_ms(), message);
    }
}

fn append_defi_diagnostic(path: &Path, message: &str) {
    append_diagnostic_log(
        path,
        &format!("version={} {message}", env!("CARGO_PKG_VERSION")),
    );
}

fn log_defi_diagnostic<R: Runtime>(app: &AppHandle<R>, message: impl AsRef<str>) {
    if let Ok(path) = diagnostic_log_path(app) {
        append_defi_diagnostic(&path, message.as_ref());
    }
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn price_cache_has_all(cache: &PriceOracleCache, ids: &[&str]) -> bool {
    ids.iter().all(|id| cache.prices.contains_key(*id))
}

fn price_cache_entries(
    cache: &PriceOracleCache,
    ids: &[&str],
) -> HashMap<String, PriceOracleEntry> {
    let mut prices = HashMap::new();
    for id in ids {
        if let Some(entry) = cache.prices.get(*id) {
            prices.insert((*id).to_string(), entry.clone());
        }
    }
    prices
}

async fn fetch_price_oracle_entries(
    ids: &[&str],
    log_path: Option<&Path>,
) -> Result<HashMap<String, PriceOracleEntry>, String> {
    let url = format!(
        "https://api.coingecko.com/api/v3/simple/price?ids={}&vs_currencies=usd&include_24hr_change=true",
        ids.join(",")
    );
    if let Some(path) = log_path {
        append_diagnostic_log(
            path,
            &format!(
                "version={} price oracle http start ids={} user_agent={}",
                env!("CARGO_PKG_VERSION"),
                ids.join(","),
                PRICE_ORACLE_USER_AGENT
            ),
        );
    }
    let data: Value = reqwest::Client::builder()
        .timeout(DEFI_PROVIDER_TIMEOUT)
        .build()
        .map_err(|e| format!("building price client: {e}"))?
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(reqwest::header::CACHE_CONTROL, "no-cache")
        .header(reqwest::header::PRAGMA, "no-cache")
        .header(reqwest::header::USER_AGENT, PRICE_ORACLE_USER_AGENT)
        .send()
        .await
        .map_err(|e| format!("querying prices: {e}"))?
        .error_for_status()
        .map_err(|e| format!("querying prices: {e}"))?
        .json()
        .await
        .map_err(|e| format!("reading prices: {e}"))?;
    let mut prices = HashMap::new();
    for id in ids {
        let Some(price) = value_as_f64(data.pointer(&format!("/{id}/usd"))) else {
            if let Some(path) = log_path {
                append_diagnostic_log(path, &format!("price oracle missing USD price id={id}"));
            }
            println!("[AutoDesktop] price oracle missing USD price id={id}");
            continue;
        };
        let change_24h =
            value_as_f64(data.pointer(&format!("/{id}/usd_24h_change"))).unwrap_or(0.0);
        prices.insert(
            (*id).to_string(),
            PriceOracleEntry {
                usd: price,
                change_24h,
            },
        );
    }
    if let Some(path) = log_path {
        append_diagnostic_log(
            path,
            &format!(
                "price oracle http done ids={} returned_count={}",
                ids.join(","),
                prices.len()
            ),
        );
    }
    Ok(prices)
}

#[tauri::command]
fn get_diagnostic_log_path<R: Runtime>(app: AppHandle<R>) -> Result<String, String> {
    diagnostic_log_path(&app).map(|path| path.display().to_string())
}

#[tauri::command]
fn write_diagnostic_log<R: Runtime>(app: AppHandle<R>, message: String) -> Result<(), String> {
    log_diagnostic(
        &app,
        format!("version={} {}", env!("CARGO_PKG_VERSION"), message),
    );
    Ok(())
}

fn defi_provider_status_message(zerion_available: bool, debank_available: bool) -> String {
    format!("defi providers zerion={zerion_available} debank={debank_available}")
}

fn xstake_logo_data_uri() -> String {
    let svg = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#0f68aa"/><path fill="#fff" d="M20 15h8l5 8 5-8h8L37 31l10 18h-8l-6-10-6 10h-8l10-18z"/></svg>"##;
    format!("data:image/svg+xml;base64,{}", B64.encode(svg.as_bytes()))
}

#[tauri::command]
async fn get_price_oracle_prices<R: Runtime>(
    app: AppHandle<R>,
    ids: Vec<String>,
) -> Result<HashMap<String, PriceOracleEntry>, String> {
    let ids: Vec<String> = ids
        .into_iter()
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
        .collect();
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    PriceOracleStore::from_app(&app).entries(&refs).await
}

#[tauri::command]
async fn get_defi_positions<R: Runtime>(
    app: AppHandle<R>,
    address: String,
    has_wallet_assets_over_one_usd: Option<bool>,
    force: Option<bool>,
) -> Result<DefiPositionsResponse, String> {
    let address = address.trim();
    let force = force.unwrap_or(false);
    println!(
        "[AutoDesktop] defi request address={address} hasWalletAssetsOverOneUsd={} force={force}",
        has_wallet_assets_over_one_usd.unwrap_or(false)
    );
    if !(address.len() == 42
        && address.starts_with("0x")
        && address[2..].chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Err("invalid address".to_string());
    }
    let has_wallet_assets = has_wallet_assets_over_one_usd.unwrap_or(false);
    let zerion_available = zerion_api_key().is_some();
    let debank_available = debank_api_key().is_some();
    log_defi_diagnostic(
        &app,
        defi_provider_status_message(zerion_available, debank_available),
    );
    let price_oracle = PriceOracleStore::from_app(&app);
    let custom = fetch_custom_defi_positions(price_oracle, address).await;
    let fetched = fetch_zerion_defi_positions(address).await;
    let zerion = zerion_result_or_cached(
        &mut zerion_cache().lock().unwrap(),
        address,
        fetched,
        Instant::now(),
    );
    let (zerion_positions, zerion_balance_usd) = match zerion {
        Ok(result) => result,
        Err(err) => {
            if has_wallet_assets && debank_available {
                log_defi_diagnostic(
                    &app,
                    format!(
                        "defi fallback source=DeBank address={address} reason=zerion-error error={err}"
                    ),
                );
                println!(
                    "[AutoDesktop] defi fallback source=DeBank address={address} reason=zerion-error error={err}"
                );
                let positions = fetch_debank_defi_positions(address)
                    .await
                    .inspect_err(|e| {
                        log_defi_diagnostic(
                            &app,
                            format!("defi DeBank failed address={address} error={e}"),
                        );
                        println!("[AutoDesktop] defi DeBank failed address={address} error={e}")
                    })?;
                log_defi_diagnostic(
                    &app,
                    format!(
                        "defi response source=DeBank address={address} positions={}",
                        positions.len()
                    ),
                );
                println!(
                    "[AutoDesktop] defi response source=DeBank address={address} positions={}",
                    positions.len()
                );
                return Ok(merge_defi_positions("DeBank", positions, custom));
            }
            if custom.as_ref().is_ok_and(|positions| !positions.is_empty()) {
                println!(
                    "[AutoDesktop] defi fallback source=Custom address={address} reason=zerion-error error={err}"
                );
                return custom_only_defi_response(custom);
            }
            println!("[AutoDesktop] defi Zerion failed address={address} error={err}");
            return Err(err);
        }
    };
    if !zerion_positions.is_empty()
        || zerion_balance_usd > 0.0
        || !has_wallet_assets
        || !debank_available
    {
        // Zerion answered, so it stays the primary source and DeBank is charged
        // only for the one protocol Zerion cannot see. The branch below — where
        // Zerion found nothing at all — falls back to the full DeBank sweep, which
        // already covers Uniswap v4, so no supplement is bought there.
        let mut zerion_positions = zerion_positions;
        let mut source = "Zerion".to_string();
        if let (Some(zerion_key), Some(debank_key)) = (zerion_api_key(), debank_api_key()) {
            let registry = DebankRegistry::from_app(&app);
            log_defi_diagnostic(
                &app,
                format!("defi DeBank supplement start address={address} force={force}"),
            );
            let supplement = tokio::time::timeout(
                UNISWAP_V4_TIMEOUT,
                fetch_uniswap_v4_positions(&registry, &zerion_key, &debank_key, address, force),
            )
            .await
            .unwrap_or_else(|_| Err(format!("timed out after {}s", UNISWAP_V4_TIMEOUT.as_secs())));
            match supplement {
                Ok(positions) => {
                    let position_count = positions.len();
                    let added = merge_uniswap_v4_positions(&mut zerion_positions, positions);
                    log_defi_diagnostic(
                        &app,
                        format!(
                            "defi DeBank supplement done address={address} positions={position_count} added={added}"
                        ),
                    );
                    if added > 0 {
                        source = format!("Zerion + {UNISWAP_V4_PROTOCOL_NAME}");
                    }
                }
                Err(err) => {
                    log_defi_diagnostic(
                        &app,
                        format!("defi DeBank supplement failed address={address} error={err}"),
                    );
                    println!(
                        "[AutoDesktop] defi Uniswap v4 supplement failed address={address} error={err}"
                    );
                }
            }
        }
        log_defi_diagnostic(
            &app,
            format!(
                "defi response source={source} address={address} positions={}",
                zerion_positions.len()
            ),
        );
        println!(
            "[AutoDesktop] defi response source={source} address={address} positions={}",
            zerion_positions.len()
        );
        return Ok(merge_defi_positions(&source, zerion_positions, custom));
    }
    println!(
        "[AutoDesktop] defi fallback source=DeBank address={address} reason=zerion-empty-wallet-assets-present"
    );
    log_defi_diagnostic(
        &app,
        format!(
            "defi fallback source=DeBank address={address} reason=zerion-empty-wallet-assets-present"
        ),
    );
    let positions = fetch_debank_defi_positions(address)
        .await
        .inspect_err(|e| {
            log_defi_diagnostic(
                &app,
                format!("defi DeBank failed address={address} error={e}"),
            );
            println!("[AutoDesktop] defi DeBank failed address={address} error={e}")
        })?;
    log_defi_diagnostic(
        &app,
        format!(
            "defi response source=DeBank address={address} positions={}",
            positions.len()
        ),
    );
    println!(
        "[AutoDesktop] defi response source=DeBank address={address} positions={}",
        positions.len()
    );
    Ok(merge_defi_positions("DeBank", positions, custom))
}

/// Normalize a chain id (accept "0x.." or decimal) to canonical lowercase 0x-hex.
fn normalize_chain_id(id: &str) -> Result<String, String> {
    let s = id.trim();
    let value = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16).map_err(|_| format!("invalid chain id '{id}'"))?,
        None => s
            .parse::<u64>()
            .map_err(|_| format!("invalid chain id '{id}'"))?,
    };
    if value == 0 {
        return Err("chain id must be non-zero".to_string());
    }
    Ok(format!("0x{value:x}"))
}

/// http(s) only, and plaintext http only for loopback / RFC-1918 LAN hosts —
/// a wallet must never read chain state over a cleartext link an attacker can
/// MITM (fake balances, fake tx status), nor from a scheme that isn't HTTP.
fn validate_rpc(rpc: &str) -> Result<(), String> {
    let url: tauri::Url = rpc
        .parse()
        .map_err(|e| format!("invalid RPC URL '{rpc}': {e}"))?;
    match url.scheme() {
        "https" => {
            if url.host_str().unwrap_or("").is_empty() {
                return Err(format!("RPC URL '{rpc}' has no host"));
            }
            Ok(())
        }
        "http" => {
            let host = url.host_str().unwrap_or("");
            let local = host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .map(|ip| match ip {
                        std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
                        std::net::IpAddr::V6(v6) => v6.is_loopback(),
                    })
                    .unwrap_or(false);
            if local {
                Ok(())
            } else {
                Err(format!(
                    "plain http RPC is only allowed for localhost/LAN dev nodes, got '{rpc}' — use https://"
                ))
            }
        }
        _ => Err("RPC URL must start with http:// or https://".to_string()),
    }
}

fn validate_explorer_url(url: &str) -> Result<(), String> {
    let parsed: tauri::Url = url
        .parse()
        .map_err(|e| format!("invalid explorer URL '{url}': {e}"))?;
    match parsed.scheme() {
        "http" | "https" => {
            if parsed.host_str().unwrap_or("").is_empty() {
                return Err(format!("explorer URL '{url}' has no host"));
            }
            Ok(())
        }
        _ => Err("explorer URL must start with http:// or https://".to_string()),
    }
}

/// EIP-1193: if a dApp transaction carries a `chainId`, it MUST match the chain
/// the wallet will sign/broadcast on. The wallet's selected chain is global
/// state — another tab or the shell may switch it after the dApp composed the
/// tx — so a mismatch means the user would sign for the wrong network.
fn ensure_tx_chain_id_matches(tx: &Value, current: &str) -> Result<(), String> {
    let Some(requested) = tx.get("chainId") else {
        return Ok(());
    };
    let requested = match requested {
        Value::String(s) => normalize_chain_id(s)?,
        Value::Number(n) => {
            let v = n
                .as_u64()
                .ok_or_else(|| format!("eth_sendTransaction: bad chainId {n}"))?;
            normalize_chain_id(&v.to_string())?
        }
        other => return Err(format!("eth_sendTransaction: bad chainId {other}")),
    };
    let current = normalize_chain_id(current)?;
    if requested != current {
        return Err(format!(
            "eth_sendTransaction: transaction chainId {requested} does not match the wallet's selected chain {current} — switch chains and retry (4901)"
        ));
    }
    Ok(())
}

/// The full effective chain registry (for the shell's network list + selectors).
#[tauri::command]
fn get_chains() -> Vec<ChainCfg> {
    chains_state().lock().unwrap().clone()
}

/// Add a custom network. Validates id/RPC, rejects duplicates, persists.
#[tauri::command]
fn add_chain<R: Runtime>(app: AppHandle<R>, mut chain: ChainCfg) -> Result<Vec<ChainCfg>, String> {
    chain.id = normalize_chain_id(&chain.id)?;
    if chain.name.trim().is_empty() {
        return Err("network name is required".to_string());
    }
    validate_rpc(&chain.rpc)?;
    chain.builtin = false;
    if chain.decimals == 0 {
        chain.decimals = 18;
    }
    if chain.symbol.trim().is_empty() {
        chain.symbol = "ETH".to_string();
    }
    if chain.color.trim().is_empty() {
        chain.color = "#6b7280".to_string();
    }
    chain.explorer_url = match chain.explorer_url {
        Some(url) if !url.trim().is_empty() => {
            let url = url.trim().to_string();
            validate_explorer_url(&url)?;
            Some(url)
        }
        _ => None,
    };
    {
        let mut chains = chains_state().lock().unwrap();
        if chains.iter().any(|c| c.id.eq_ignore_ascii_case(&chain.id)) {
            return Err(format!("network {} already exists", chain.id));
        }
        chains.push(chain);
    }
    save_chains(&app)?;
    Ok(chains_state().lock().unwrap().clone())
}

/// Edit an existing network's params (id + builtin flag are preserved).
#[tauri::command]
fn update_chain<R: Runtime>(app: AppHandle<R>, chain: ChainCfg) -> Result<Vec<ChainCfg>, String> {
    let id = normalize_chain_id(&chain.id)?;
    if chain.name.trim().is_empty() {
        return Err("network name is required".to_string());
    }
    validate_rpc(&chain.rpc)?;
    {
        let mut chains = chains_state().lock().unwrap();
        let existing = chains
            .iter_mut()
            .find(|c| c.id.eq_ignore_ascii_case(&id))
            .ok_or_else(|| format!("network {id} not found"))?;
        existing.name = chain.name;
        existing.rpc = chain.rpc;
        existing.decimals = if chain.decimals == 0 {
            18
        } else {
            chain.decimals
        };
        if !chain.symbol.trim().is_empty() {
            existing.symbol = chain.symbol;
        }
        if !chain.color.trim().is_empty() {
            existing.color = chain.color;
        }
        existing.explorer_url = match chain.explorer_url {
            Some(url) if !url.trim().is_empty() => {
                let url = url.trim().to_string();
                validate_explorer_url(&url)?;
                Some(url)
            }
            _ => None,
        };
    }
    save_chains(&app)?;
    Ok(chains_state().lock().unwrap().clone())
}

/// Remove a user-added network (built-ins can't be removed). Falls the active
/// chain back to the first network if the removed one was active.
#[tauri::command]
fn remove_chain<R: Runtime>(app: AppHandle<R>, id: String) -> Result<Vec<ChainCfg>, String> {
    let id = normalize_chain_id(&id)?;
    {
        let mut chains = chains_state().lock().unwrap();
        let target = chains
            .iter()
            .find(|c| c.id.eq_ignore_ascii_case(&id))
            .ok_or_else(|| format!("network {id} not found"))?;
        if target.builtin {
            return Err("built-in networks can't be removed".to_string());
        }
        chains.retain(|c| !c.id.eq_ignore_ascii_case(&id));
    }
    let fallback = chains_state().lock().unwrap().first().map(|c| c.id.clone());
    {
        let mut cur = current_chain().lock().unwrap();
        if cur.eq_ignore_ascii_case(&id) {
            if let Some(f) = fallback {
                *cur = f;
            }
        }
    }
    save_chains(&app)?;
    Ok(chains_state().lock().unwrap().clone())
}

// ---------------------------------------------------------------------------
// Vault commands (shell-only).
//
// These take the user's password (typed into the TRUSTED shell UI) and manage the
// encrypted keystore. They are granted ONLY to the shell webview (default.json +
// permissions/vault.toml) — a dApp can never reach them, so a page can't create,
// unlock, or read the wallet. The keystore file lives in the OS app-data dir,
// NEVER in the repo (密钥安全).
// ---------------------------------------------------------------------------

/// Each wallet is one keystore file under `wallets/<id>.json` in the app-data dir,
/// so several independent wallets (seeds / private keys / Ledgers) coexist. A
/// pre-multi-wallet install kept a single `vault.json`; `migrate_legacy_keystore`
/// folds that into the new dir on first read.
const WALLETS_DIR: &str = "wallets";
const LEGACY_KEYSTORE_FILE: &str = "vault.json";

// Serialize vault file operations, including password rotation and recovery.
// Always acquire this before the in-memory store lock.
fn vault_io_lock() -> &'static Mutex<()> {
    static LOCK: Mutex<()> = Mutex::new(());
    &LOCK
}

fn recover_wallet_password<R: Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    password_change::recover(&wallets_dir(app)?, &touch_id_marker_file(app)?)
}

fn wallets_dir<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join(WALLETS_DIR))
}

/// Path to one wallet's keystore. `id` is our own random hex; still validate it so
/// a crafted id can never traverse out of the wallets dir.
fn wallet_file<R: Runtime>(app: &AppHandle<R>, id: &str) -> Result<PathBuf, String> {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err("invalid wallet id".to_string());
    }
    Ok(wallets_dir(app)?.join(format!("{id}.json")))
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn read_keystore(path: &Path) -> Result<Option<vault::Keystore>, String> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes).map_err(|e| format!("corrupt keystore: {e}"))?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("reading keystore: {e}")),
    }
}

fn write_keystore(path: &Path, ks: &vault::Keystore) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("creating app dir: {e}"))?;
    }
    let json = serde_json::to_vec_pretty(ks).map_err(|e| e.to_string())?;
    std::fs::write(path, json).map_err(|e| format!("writing keystore: {e}"))
}

/// Fold a legacy single-vault `vault.json` into `wallets/<id>.json` (assigning an
/// id + label) once, before any multi-wallet read. Idempotent: removes the legacy
/// file only after the new one is safely written.
fn migrate_legacy_keystore<R: Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    let base = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let legacy = base.join(LEGACY_KEYSTORE_FILE);
    if !legacy.exists() {
        return Ok(());
    }
    if let Some(mut ks) = read_keystore(&legacy)? {
        if ks.id.is_empty() {
            ks.id = vault::new_wallet_id();
        }
        if ks.label.is_empty() {
            ks.label = "Wallet 1".to_string();
        }
        let dest = wallet_file(app, &ks.id)?;
        write_keystore(&dest, &ks)?;
    }
    let _ = std::fs::remove_file(&legacy);
    Ok(())
}

/// Every wallet keystore on disk, in stable creation order (migrating the legacy
/// single vault first). The shell renders the wallet switcher from this.
fn read_all_keystores<R: Runtime>(app: &AppHandle<R>) -> Result<Vec<vault::Keystore>, String> {
    migrate_legacy_keystore(app)?;
    recover_wallet_password(app)?;
    let dir = wallets_dir(app)?;
    let mut out: Vec<vault::Keystore> = Vec::new();
    match std::fs::read_dir(&dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|x| x.to_str()) == Some("json") {
                    if let Some(ks) = read_keystore(&path)? {
                        out.push(ks);
                    }
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("reading wallets dir: {e}")),
    }
    // Stable order: by creation time, then id (creation is 0 for migrated wallets).
    out.sort_by(|a, b| a.created.cmp(&b.created).then_with(|| a.id.cmp(&b.id)));
    Ok(out)
}

/// Use the optional import name, or "Wallet N" (N = count + 1) when left blank.
fn next_wallet_label<R: Runtime>(app: &AppHandle<R>, label: Option<String>) -> Result<String, String> {
    if let Some(name) = label {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    Ok(format!("Wallet {}", read_all_keystores(app)?.len() + 1))
}

/// The app password to seal a new SOFTWARE wallet with, plus whether to record it
/// in the store (Some only when this call establishes the password). If we're
/// already unlocked with a password, reuse it (no re-prompt); otherwise the caller
/// must supply one (≥8 chars) — and if software wallets already exist on disk, it
/// must decrypt one of them, so every software wallet shares the one app password.
fn resolve_app_password<R: Runtime>(
    app: &AppHandle<R>,
    provided: Option<String>,
) -> Result<(Zeroizing<String>, Option<Zeroizing<String>>), String> {
    if let Some(pw) = store_state()
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|s| s.password.clone())
    {
        return Ok((pw, None));
    }
    let pw = provided.ok_or("a password is required to add this wallet")?;
    if pw.len() < 8 {
        return Err("password must be at least 8 characters".to_string());
    }
    if let Some(existing) = read_all_keystores(app)?
        .iter()
        .find(|k| k.kind == "hd" || k.kind == "privkey")
    {
        vault::open(&pw, existing).map_err(|_| "incorrect password".to_string())?;
    }
    let pw = Zeroizing::new(pw);
    Ok((pw.clone(), Some(pw)))
}

/// One wallet for the shell switcher: its id, label, secret kind, and account
/// addresses.
#[derive(Serialize)]
struct WalletInfo {
    id: String,
    label: String,
    /// "hd" | "privkey" | "ledger".
    kind: String,
    accounts: Vec<String>,
}

#[derive(Serialize)]
struct VaultStatus {
    /// At least one wallet keystore exists on disk.
    exists: bool,
    /// The wallets are unlocked in memory this session.
    unlocked: bool,
    /// An app password is set (any software wallet exists). When false, the only
    /// wallets are Ledgers (no password) and the shell can skip the unlock screen.
    has_password: bool,
    /// All wallets (from memory when unlocked, else on-disk metadata for display).
    wallets: Vec<WalletInfo>,
    /// The active account address, if any.
    active: Option<String>,
}

fn store_wallet_infos(store: &WalletStore) -> Vec<WalletInfo> {
    store
        .wallets
        .iter()
        .map(|w| WalletInfo {
            id: w.id.clone(),
            label: w.label.clone(),
            kind: w.kind().to_string(),
            accounts: w.accounts.iter().map(|a| a.address.clone()).collect(),
        })
        .collect()
}

fn disk_wallet_infos(disk: &[vault::Keystore]) -> Vec<WalletInfo> {
    disk.iter()
        .map(|k| WalletInfo {
            id: k.id.clone(),
            label: k.label.clone(),
            kind: k.kind.clone(),
            accounts: k.accounts.iter().map(|a| a.address.clone()).collect(),
        })
        .collect()
}

/// Newly created wallet — returns the mnemonic ONCE so the trusted shell can show
/// the backup screen. (The dApp boundary never sees this; vault commands are
/// shell-only.)
#[derive(Serialize)]
struct NewVault {
    id: String,
    address: String,
    mnemonic: String,
}

/// A newly added wallet (id + active address) for import/connect paths.
#[derive(Serialize)]
struct WalletRef {
    id: String,
    address: String,
}

/// Decrypted secret for an explicit user export. Only the trusted shell can call
/// this command, and it still requires the app password so a casual unlocked
/// session cannot leak a seed/key by accident.
#[derive(Serialize)]
struct ExportedSecret {
    /// `Zeroizing` so the decrypted plaintext is scrubbed from memory once the IPC
    /// response is serialized — matching how the rest of `mod vault` holds secrets.
    /// The caller already knows the wallet kind, so it isn't echoed back here.
    secret: Zeroizing<String>,
}

/// Whether any wallet exists / is unlocked, the full wallet list, and the active
/// account. The shell renders the switcher + gates the lock screen from this.
#[tauri::command]
fn vault_status<R: Runtime>(app: AppHandle<R>) -> Result<VaultStatus, String> {
    let _io = vault_io_lock().lock().unwrap();
    let disk = read_all_keystores(&app)?;
    let has_password = disk.iter().any(|k| k.kind == "hd" || k.kind == "privkey");
    let guard = store_state().lock().unwrap();
    let (wallets, active) = match guard.as_ref() {
        Some(store) => (
            store_wallet_infos(store),
            (!store.active.is_empty()).then(|| store.active.clone()),
        ),
        None => (
            disk_wallet_infos(&disk),
            disk.iter()
                .find_map(|k| k.accounts.first())
                .map(|a| a.address.clone()),
        ),
    };
    Ok(VaultStatus {
        exists: !disk.is_empty(),
        unlocked: guard.is_some(),
        has_password,
        wallets,
        active,
    })
}

/// Add a brand-new HD wallet: generate a mnemonic, seal it under the app password,
/// persist it as a new keystore, and add it to the unlocked store (active). The
/// `password` is required only when establishing the app password (first software
/// wallet); when already unlocked it is ignored. Returns the mnemonic for the
/// one-time backup screen.
#[tauri::command]
fn create_vault<R: Runtime>(
    app: AppHandle<R>,
    password: Option<String>,
) -> Result<NewVault, String> {
    let _io = vault_io_lock().lock().unwrap();
    let (pw, store_pw) = resolve_app_password(&app, password)?;
    let mnemonic = vault::generate_mnemonic()?;
    let id = vault::new_wallet_id();
    let label = next_wallet_label(&app, None)?;
    let (accounts, metas) = derive_hd_accounts(&mnemonic, 1)?;
    let mut ks = vault::seal(&pw, &mnemonic, "hd", metas)?;
    ks.id = id.clone();
    ks.label = label.clone();
    ks.created = now_ms();
    write_keystore(&wallet_file(&app, &id)?, &ks)?;
    let wallet = UnlockedWallet {
        id: id.clone(),
        label,
        secret: VaultSecret::Mnemonic(Zeroizing::new(mnemonic.clone())),
        accounts,
    };
    let address = store_push_wallet(wallet, store_pw);
    push_accounts_changed(&app, Some(&address));
    Ok(NewVault {
        id,
        address,
        mnemonic,
    })
}

/// Add a wallet from a recovery phrase. Returns the new wallet's id + active address.
#[tauri::command]
fn import_vault<R: Runtime>(
    app: AppHandle<R>,
    password: Option<String>,
    mnemonic: String,
    label: Option<String>,
) -> Result<WalletRef, String> {
    let _io = vault_io_lock().lock().unwrap();
    vault::validate_mnemonic(&mnemonic)?;
    let (pw, store_pw) = resolve_app_password(&app, password)?;
    let id = vault::new_wallet_id();
    let label = next_wallet_label(&app, label)?;
    let (accounts, metas) = derive_hd_accounts(&mnemonic, 1)?;
    let mut ks = vault::seal(&pw, &mnemonic, "hd", metas)?;
    ks.id = id.clone();
    ks.label = label.clone();
    ks.created = now_ms();
    write_keystore(&wallet_file(&app, &id)?, &ks)?;
    let wallet = UnlockedWallet {
        id: id.clone(),
        label,
        secret: VaultSecret::Mnemonic(Zeroizing::new(mnemonic.trim().to_string())),
        accounts,
    };
    let address = store_push_wallet(wallet, store_pw);
    push_accounts_changed(&app, Some(&address));
    Ok(WalletRef { id, address })
}

/// Add a wallet from a single raw private key (single-account — no mnemonic to
/// derive from). Returns the new wallet's id + active address.
#[tauri::command]
fn import_private_key<R: Runtime>(
    app: AppHandle<R>,
    password: Option<String>,
    private_key: String,
    label: Option<String>,
) -> Result<WalletRef, String> {
    let _io = vault_io_lock().lock().unwrap();
    let label = next_wallet_label(&app, label)?;
    // Validate + canonicalize to 0x-lowercase-hex before sealing, so unlock
    // re-derives the same address deterministically.
    let key = vault::parse_private_key(&private_key)?;
    let key_hex = Zeroizing::new(format!("0x{}", hex::encode(key.to_bytes())));
    let address = address_from_verifying_key(key.verifying_key());
    let (pw, store_pw) = resolve_app_password(&app, password)?;
    let id = vault::new_wallet_id();
    let metas = vec![vault::AccountMeta {
        index: 0,
        address: address.clone(),
    }];
    let mut ks = vault::seal(&pw, &key_hex, "privkey", metas)?;
    ks.id = id.clone();
    ks.label = label.clone();
    ks.created = now_ms();
    write_keystore(&wallet_file(&app, &id)?, &ks)?;
    let wallet = UnlockedWallet {
        id: id.clone(),
        label,
        secret: VaultSecret::PrivateKey,
        accounts: vec![UnlockedAccount {
            index: 0,
            address,
            signer: Signer::Local(key),
        }],
    };
    let address = store_push_wallet(wallet, store_pw);
    push_accounts_changed(&app, Some(&address));
    Ok(WalletRef { id, address })
}

/// Export the selected software wallet's root secret after password re-check.
/// HD wallets return their recovery phrase; imported private-key wallets return
/// the canonical 0x private key. Ledger wallets have no local secret to export.
#[tauri::command]
fn export_wallet_secret<R: Runtime>(
    app: AppHandle<R>,
    wallet_id: String,
    password: String,
) -> Result<ExportedSecret, String> {
    let _io = vault_io_lock().lock().unwrap();
    recover_wallet_password(&app)?;
    let path = wallet_file(&app, &wallet_id)?;
    let ks = read_keystore(&path)?.ok_or("wallet not found")?;
    match ks.kind.as_str() {
        "hd" | "privkey" => Ok(ExportedSecret {
            secret: vault::open(&password, &ks)?,
        }),
        "ledger" => Err("Ledger wallets do not have a local secret to export".to_string()),
        _ => Err(format!("unsupported wallet kind {}", ks.kind)),
    }
}

/// On boot, auto-load wallets ONLY when there is no app password to enter — i.e. a
/// Ledger-only (or empty) setup. Their addresses are public, so they open straight
/// to the wallet with no lock screen (matching the old single-Ledger behaviour). If
/// ANY software wallet exists, do nothing: the app stays locked until the user
/// enters the password (which also loads the Ledger wallets).
fn boot_load_ledger_only<R: Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    let _io = vault_io_lock().lock().unwrap();
    let disk = read_all_keystores(app)?;
    let has_software = disk.iter().any(|k| k.kind == "hd" || k.kind == "privkey");
    if has_software || disk.is_empty() {
        return Ok(());
    }
    let mut wallets = Vec::new();
    for ks in disk.iter().filter(|k| k.kind == "ledger") {
        wallets.push(build_ledger_wallet_from_keystore(ks)?);
    }
    let active = wallets
        .iter()
        .flat_map(|w| &w.accounts)
        .next()
        .map(|a| a.address.clone())
        .unwrap_or_default();
    *store_state().lock().unwrap() = Some(WalletStore {
        password: None,
        wallets,
        active,
    });
    Ok(())
}

/// Unlock ALL wallets with the one app `password`: decrypt every software wallet
/// (a wrong password fails the AEAD tag check → "incorrect password") and load the
/// Ledger wallets (public addresses, no secret). The password is kept in memory so
/// further software wallets can be added without re-prompting. Returns the active
/// address.
#[tauri::command]
fn unlock_vault<R: Runtime>(app: AppHandle<R>, password: String) -> Result<String, String> {
    let _io = vault_io_lock().lock().unwrap();
    unlock_vault_with_password(&app, Zeroizing::new(password))
}

/// Re-encrypt all software wallets under one new password. The transaction
/// journal makes the entire change recoverable after process or write failure.
#[tauri::command]
async fn change_password<R: Runtime>(
    app: AppHandle<R>,
    current_password: String,
    new_password: String,
) -> Result<password_change::ChangePasswordResult, String> {
    let current = Zeroizing::new(current_password);
    let new = Zeroizing::new(new_password);
    tauri::async_runtime::spawn_blocking(move || {
        let _io = vault_io_lock().lock().unwrap();
        let wallets = read_all_keystores(&app)?;
        let mut guard = store_state().lock().unwrap();
        let store = guard.as_mut().ok_or("unlock the wallet before changing the password")?;
        if store.password.is_none() {
            return Err("this wallet does not use an app password".into());
        }
        let result = password_change::change(
            &wallets_dir(&app)?,
            &touch_id_marker_file(&app)?,
            &wallets,
            &current,
            &new,
            touch_id::save_password,
        )?;
        store.password = Some(new);
        note_activity();
        Ok(result)
    }).await.map_err(|error| format!("changing wallet password: {error}"))?
}

fn unlock_vault_with_password<R: Runtime>(
    app: &AppHandle<R>,
    password: Zeroizing<String>,
) -> Result<String, String> {
    let disk = read_all_keystores(&app)?;
    if disk.is_empty() {
        return Err("no wallet to unlock".to_string());
    }
    let mut wallets = Vec::with_capacity(disk.len());
    let mut used_password = false;
    for ks in &disk {
        let wallet = match ks.kind.as_str() {
            "ledger" => build_ledger_wallet_from_keystore(ks)?,
            "privkey" => {
                let secret = vault::open(&password, ks)?;
                used_password = true;
                build_privkey_wallet_from_keystore(ks, &secret)?
            }
            // "hd" + legacy keystores with no `kind` (defaulted to "hd").
            _ => {
                let secret = vault::open(&password, ks)?;
                used_password = true;
                build_hd_wallet_from_keystore(ks, secret)?
            }
        };
        wallets.push(wallet);
    }
    let active = wallets
        .iter()
        .flat_map(|w| &w.accounts)
        .next()
        .map(|a| a.address.clone())
        .unwrap_or_default();
    let password = used_password.then_some(password);
    note_activity(); // a fresh unlock starts a fresh idle window
    *store_state().lock().unwrap() = Some(WalletStore {
        password,
        wallets,
        active: active.clone(),
    });
    if active.is_empty() {
        return Err("unlock failed".to_string());
    }
    Ok(active)
}

fn touch_id_marker_file<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|path| path.join(TOUCH_ID_MARKER_FILE))
        .map_err(|error| format!("resolving Touch ID settings path: {error}"))
}

#[tauri::command]
fn touch_id_status<R: Runtime>(app: AppHandle<R>) -> Result<touch_id::TouchIdStatus, String> {
    let _io = vault_io_lock().lock().unwrap();
    recover_wallet_password(&app)?;
    let enabled = touch_id::read_enabled_marker(&touch_id_marker_file(&app)?)?;
    Ok(touch_id::TouchIdStatus {
        available: touch_id::available(),
        enabled,
    })
}

#[tauri::command]
async fn enable_touch_id<R: Runtime>(app: AppHandle<R>, reason: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let _io = vault_io_lock().lock().unwrap();
        recover_wallet_password(&app)?;
        let password = {
            let guard = store_state().lock().unwrap();
            let store = guard.as_ref().ok_or("unlock the wallet before enabling Touch ID")?;
            let password = store.password.as_ref().ok_or("this wallet does not use an app password")?;
            Zeroizing::new(password.to_string())
        };
        touch_id::authenticate(&reason)?;
        touch_id::save_password(&password)?;
        let marker = touch_id_marker_file(&app)?;
        if let Err(error) = touch_id::write_enabled_marker(&marker) {
            let rollback = touch_id::delete_password();
            return match rollback {
                Ok(()) => Err(error),
                Err(rollback_error) => Err(format!("{error}; rollback failed: {rollback_error}")),
            };
        }
        Ok(())
    })
    .await
    .map_err(|error| format!("running Touch ID setup: {error}"))?
}

#[tauri::command]
fn disable_touch_id<R: Runtime>(app: AppHandle<R>) -> Result<(), String> {
    let _io = vault_io_lock().lock().unwrap();
    disable_touch_id_inner(&app)
}

fn disable_touch_id_inner<R: Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    touch_id::delete_password()?;
    touch_id::remove_enabled_marker(&touch_id_marker_file(app)?)
}

#[tauri::command]
async fn unlock_vault_with_touch_id<R: Runtime>(
    app: AppHandle<R>,
    reason: String,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let _io = vault_io_lock().lock().unwrap();
        recover_wallet_password(&app)?;
        if !touch_id::read_enabled_marker(&touch_id_marker_file(&app)?)? {
            return Err("Touch ID unlock is not enabled".to_string());
        }
        // One prompt: the keychain read itself asks for the fingerprint.
        let Some(password) = touch_id::load_password(&reason)? else {
            disable_touch_id_inner(&app)?;
            return Err(
                "Touch ID unlock was upgraded and must be turned on again: unlock with your password, then enable Touch ID in Settings".into(),
            );
        };
        unlock_vault_with_password(&app, password)
    }).await.map_err(|error| format!("running Touch ID unlock: {error}"))?
}

/// Lock the wallet: drop all decrypted key material (and the app password) from
/// memory.
#[tauri::command]
fn lock_vault<R: Runtime>(app: AppHandle<R>) {
    *store_state().lock().unwrap() = None;
    // Connected tabs learn the account is gone (or see the watch-only address
    // that stays exposed without keys).
    push_accounts_changed(&app, dapp_account_address().as_deref());
}

/// Reset EVERYTHING: drop in-memory keys AND delete every keystore, so the app
/// returns to first-run onboarding. This is the "忘记密码" escape hatch — it is
/// IRREVERSIBLE and destroys the only copy of every encrypted secret, so the UI must
/// gate it behind an explicit, clearly-worded confirmation (funds are unrecoverable
/// without the user's own mnemonic/key backups). To remove a single wallet, use
/// `delete_wallet`.
#[tauri::command]
fn reset_vault<R: Runtime>(app: AppHandle<R>) -> Result<(), String> {
    let _io = vault_io_lock().lock().unwrap();
    disable_touch_id_inner(&app)?;
    lock_vault(app.clone());
    let dir = wallets_dir(&app)?;
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("removing wallets dir: {e}")),
    }
    // Also drop any un-migrated legacy keystore.
    if let Ok(base) = app.path().app_data_dir() {
        let _ = std::fs::remove_file(base.join(LEGACY_KEYSTORE_FILE));
    }
    Ok(())
}

/// One Ledger account candidate for the onboarding picker.
#[derive(Serialize)]
struct LedgerAccount {
    index: u32,
    path: String,
    address: String,
}

/// List addresses from a connected Ledger (Ledger Live path `m/44'/60'/index'/0/0`)
/// for `count` accounts starting at `start`. Requires the device unlocked with the
/// Ethereum app open. No on-device confirmation (read-only address query).
#[tauri::command]
fn ledger_addresses(start: u32, count: u32) -> Result<Vec<LedgerAccount>, String> {
    // One picker page is 20 addresses; the UI fetches them in small chunks so it
    // can render each as it streams in (the device derives them sequentially).
    let count = count.clamp(1, 20);
    let indices: Vec<u32> = (start..start.saturating_add(count)).collect();
    let rows = ledger::get_addresses(&indices)?;
    Ok(rows
        .into_iter()
        .map(|(index, path, address)| LedgerAccount {
            index,
            path,
            address,
        })
        .collect())
}

/// Add a Ledger wallet at `path`: re-read its address from the device, persist a
/// Ledger keystore (path + address; no secret at rest), and add it to the store
/// (no password). Returns the new wallet's id + address.
#[tauri::command]
fn connect_ledger<R: Runtime>(
    app: AppHandle<R>,
    path: String,
    label: Option<String>,
) -> Result<WalletRef, String> {
    let _io = vault_io_lock().lock().unwrap();
    let address = ledger::get_address(&path)?;
    let id = vault::new_wallet_id();
    let label = next_wallet_label(&app, label)?;
    let metas = vec![vault::AccountMeta {
        index: 0,
        address: address.clone(),
    }];
    let mut ks = vault::ledger_keystore(&path, metas);
    ks.id = id.clone();
    ks.label = label.clone();
    ks.created = now_ms();
    write_keystore(&wallet_file(&app, &id)?, &ks)?;
    let wallet = UnlockedWallet {
        id: id.clone(),
        label,
        secret: VaultSecret::Ledger,
        accounts: vec![UnlockedAccount {
            index: 0,
            address: address.clone(),
            signer: Signer::Ledger { path },
        }],
    };
    // A Ledger adds no app password (None never overwrites an existing one).
    let address = store_push_wallet(wallet, None);
    push_accounts_changed(&app, Some(&address));
    Ok(WalletRef { id, address })
}

/// Switch the active account by ADDRESS (feature ①: 切换钱包地址), across all
/// wallets. Pushes EIP-1193 `accountsChanged` to open dApps. Returns the address.
#[tauri::command]
fn select_account<R: Runtime>(app: AppHandle<R>, address: String) -> Result<String, String> {
    let address = normalize_evm_address(&address)?;
    {
        let mut guard = store_state().lock().unwrap();
        let store = guard.as_mut().ok_or("wallet is locked")?;
        let known = store
            .wallets
            .iter()
            .flat_map(|w| &w.accounts)
            .any(|a| a.address == address);
        if !known {
            return Err(format!("unknown account {address}"));
        }
        store.active = address.clone();
    }
    *exposed_account_state().lock().unwrap() = Some(ExposedAccount::Signer(address.clone()));
    push_accounts_changed(&app, Some(&address));
    Ok(address)
}

/// Expose a public address to dApps without making it a signer. This is used for
/// watch-only accounts so portfolio dApps (DeBank, scanners, dashboards) can read
/// the selected address while signing still fails unless the active signer matches.
#[tauri::command]
fn expose_dapp_account<R: Runtime>(app: AppHandle<R>, address: String) -> Result<String, String> {
    let address = normalize_evm_address(&address)?;
    *exposed_account_state().lock().unwrap() = Some(ExposedAccount::WatchOnly(address.clone()));
    push_accounts_changed(&app, Some(&address));
    Ok(address)
}

/// Derive the next HD account in wallet `wallet_id`, persist it to that keystore's
/// (plaintext) account list, and return its address. The encrypted mnemonic is
/// unchanged, so no password is needed.
#[tauri::command]
fn add_account<R: Runtime>(app: AppHandle<R>, wallet_id: String) -> Result<String, String> {
    let _io = vault_io_lock().lock().unwrap();
    recover_wallet_password(&app)?;
    let (address, metas) = {
        let mut guard = store_state().lock().unwrap();
        let store = guard.as_mut().ok_or("wallet is locked")?;
        let w = store
            .wallets
            .iter_mut()
            .find(|w| w.id == wallet_id)
            .ok_or("wallet not found")?;
        let mnemonic = match &w.secret {
            VaultSecret::Mnemonic(m) => m.clone(),
            VaultSecret::PrivateKey => {
                return Err("imported private-key wallets can't derive more accounts".to_string())
            }
            VaultSecret::Ledger => {
                return Err("Ledger accounts are added by connecting the device".to_string())
            }
        };
        let next_index = w
            .accounts
            .iter()
            .map(|a| a.index)
            .max()
            .map_or(0, |m| m + 1);
        let (key, address) = vault::derive_account(&mnemonic, next_index)?;
        w.accounts.push(UnlockedAccount {
            index: next_index,
            address: address.clone(),
            signer: Signer::Local(key),
        });
        let metas = w
            .accounts
            .iter()
            .map(|a| vault::AccountMeta {
                index: a.index,
                address: a.address.clone(),
            })
            .collect::<Vec<_>>();
        (address, metas)
    };
    // Persist the grown account list (public metadata only — ciphertext untouched).
    let path = wallet_file(&app, &wallet_id)?;
    if let Some(mut ks) = read_keystore(&path)? {
        ks.accounts = metas;
        write_keystore(&path, &ks)?;
    }
    Ok(address)
}

/// Rename wallet `id` (label is plaintext metadata — no password needed).
#[tauri::command]
fn rename_wallet<R: Runtime>(app: AppHandle<R>, id: String, label: String) -> Result<(), String> {
    let _io = vault_io_lock().lock().unwrap();
    recover_wallet_password(&app)?;
    let label = label.trim().to_string();
    if label.is_empty() {
        return Err("wallet name cannot be empty".to_string());
    }
    let path = wallet_file(&app, &id)?;
    let mut ks = read_keystore(&path)?.ok_or("wallet not found")?;
    ks.label = label.clone();
    write_keystore(&path, &ks)?;
    if let Some(store) = store_state().lock().unwrap().as_mut() {
        if let Some(w) = store.wallets.iter_mut().find(|w| w.id == id) {
            w.label = label;
        }
    }
    Ok(())
}

/// Delete wallet `id`: remove its keystore from disk and from memory. If it held the
/// active account, the active is moved to another account (or cleared when none
/// remain). IRREVERSIBLE for a software wallet — the UI must confirm first.
#[tauri::command]
fn delete_wallet<R: Runtime>(app: AppHandle<R>, id: String) -> Result<(), String> {
    let _io = vault_io_lock().lock().unwrap();
    let disk = read_all_keystores(&app)?;
    let deleting_last_software_wallet = disk
        .iter()
        .find(|wallet| wallet.id == id)
        .is_some_and(|wallet| wallet.kind == "hd" || wallet.kind == "privkey")
        && disk
            .iter()
            .filter(|wallet| wallet.kind == "hd" || wallet.kind == "privkey")
            .count()
            == 1;
    if deleting_last_software_wallet {
        disable_touch_id_inner(&app)?;
    }
    let path = wallet_file(&app, &id)?;
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("removing keystore: {e}")),
    }
    let new_active = {
        let mut guard = store_state().lock().unwrap();
        match guard.as_mut() {
            Some(store) => {
                store.wallets.retain(|w| w.id != id);
                if store.wallets.is_empty() {
                    *guard = None;
                    Some(None) // nothing left → no active account
                } else {
                    let still = store
                        .wallets
                        .iter()
                        .flat_map(|w| &w.accounts)
                        .any(|a| a.address == store.active);
                    if !still {
                        store.active = store
                            .wallets
                            .iter()
                            .flat_map(|w| &w.accounts)
                            .next()
                            .map(|a| a.address.clone())
                            .unwrap_or_default();
                    }
                    Some(Some(store.active.clone()))
                }
            }
            None => None,
        }
    };
    if let Some(active) = new_active {
        push_accounts_changed(&app, active.as_deref());
    }
    Ok(())
}

/// Push an EIP-1193 `accountsChanged` to every open dApp tab (same eval-push
/// mechanism as `chainChanged`, so dApps keep ONLY allow-wallet-request).
/// Which dApp tabs get an `accountsChanged`, and with what. Only connected sites
/// may learn the address; the rest are told nothing. Sorted by label.
fn accounts_changed_targets<R: Runtime>(
    app: &AppHandle<R>,
    address: Option<&str>,
) -> Vec<(String, Vec<String>)> {
    let accounts: Vec<String> = address.map(|a| vec![a.to_string()]).unwrap_or_default();
    let mut targets: Vec<(String, Vec<String>)> = app
        .webviews()
        .into_iter()
        .filter(|(label, webview)| {
            label.starts_with("dapp-")
                && webview_origin(webview).is_some_and(|o| is_site_connected(&o))
        })
        .map(|(label, _)| (label, accounts.clone()))
        .collect();
    targets.sort();
    targets
}

fn push_accounts_changed<R: Runtime>(app: &AppHandle<R>, address: Option<&str>) {
    for (label, accounts) in accounts_changed_targets(app, address) {
        let Some(webview) = app.get_webview(&label) else {
            continue;
        };
        let payload = serde_json::to_string(&accounts).expect("a string list serializes");
        let _ = webview.eval(format!(
            "window.__autoWalletPush && window.__autoWalletPush('accountsChanged', {payload});"
        ));
    }
}

/// The app context (config, assets, baked-in ACL from capabilities/ + permissions/).
/// `generate_context!` defines a one-per-crate `_EMBED_INFO_PLIST` static, so it must
/// be expanded at exactly one call site. Keeping it in this single generic fn lets both
/// `run()` (Wry) and the in-process E2E tests (MockRuntime) share that one expansion.
fn build_context<R: tauri::Runtime>() -> tauri::Context<R> {
    tauri::generate_context!()
}

// ---------------------------------------------------------------------------
// Window / webview layout.
// ---------------------------------------------------------------------------
const WIN_W: f64 = 1350.0;
const WIN_H: f64 = 880.0;
const MIN_WIN_W: f64 = 940.0;
const MIN_WIN_H: f64 = 600.0;
const SMALL_SCREEN_W: f64 = 1280.0;
const SMALL_SCREEN_H: f64 = 800.0;
const MEDIUM_SCREEN_W: f64 = 1728.0;
const MEDIUM_SCREEN_H: f64 = 1117.0;
const LARGE_SCREEN_W: f64 = 2560.0;
const LARGE_SCREEN_H: f64 = 1440.0;

/// The real EIP-1193/EIP-6963 provider from the frontend wallet core, bundled to a
/// self-contained IIFE by `bun run build:injected` and embedded at compile time.
/// Injected into every dApp webview before page scripts.
const INPAGE_PROVIDER: &str = include_str!("../injected/inpage.js");

fn startup_window_size<R: Runtime>(app: &tauri::App<R>) -> (LogicalSize<f64>, bool) {
    let preferred = LogicalSize::new(WIN_W, WIN_H);
    let Ok(Some(monitor)) = app.primary_monitor() else {
        return (preferred, false);
    };
    let work_area = monitor
        .work_area()
        .size
        .to_logical::<f64>(monitor.scale_factor());
    let w = work_area.width;
    let h = work_area.height;

    // The embedded dApp browser benefits more from width than the wallet pages do.
    // Pick startup sizes by usable monitor area, keeping small screens maximized
    // and giving large displays a wider canvas without making the app feel full-screen.
    if w <= SMALL_SCREEN_W || h <= SMALL_SCREEN_H {
        // Maximized supplies the actual startup layout; the size here only sets
        // the RESTORE geometry. inner_size is the CLIENT area, so a full
        // work-area value would overflow it once the OS adds the title bar and
        // borders — on Windows an un-maximized window then hangs below the
        // taskbar and the bottom of the sidebar is clipped.
        return (LogicalSize::new(w * 0.94, h * 0.92), true);
    }

    let target = if w <= MEDIUM_SCREEN_W || h <= MEDIUM_SCREEN_H {
        LogicalSize::new((w * 0.92).min(1440.0), (h * 0.9).min(900.0))
    } else if w <= LARGE_SCREEN_W || h <= LARGE_SCREEN_H {
        LogicalSize::new((w * 0.82).min(1680.0), (h * 0.84).min(980.0))
    } else {
        LogicalSize::new((w * 0.72).min(1860.0), (h * 0.78).min(1080.0))
    };

    (
        LogicalSize::new(
            target.width.clamp(MIN_WIN_W.min(w), w),
            target.height.clamp(MIN_WIN_H.min(h), h),
        ),
        false,
    )
}

/// Post-build fitting for the main window. `inner_size` sets the CLIENT area,
/// so a window sized from the monitor work area overflows it once the OS adds
/// decorations — on Windows the extra height ends up behind the taskbar and
/// clips the bottom-left of the UI. Measure the real decoration overhead
/// (outer − inner), shrink the client size until the outer frame fits the work
/// area, and center the outer frame within it (tao's `.center()` uses the full
/// monitor, which lets the frame dip behind the taskbar). Returns the actual
/// client size so the shell webview can be sized to match exactly — for a
/// maximized window that is the maximized client area, not the requested size.
fn fit_startup_window<R: Runtime>(
    window: &tauri::Window<R>,
    requested: LogicalSize<f64>,
    maximized: bool,
) -> LogicalSize<f64> {
    let scale = window.scale_factor().unwrap_or(1.0);
    let actual_inner = window
        .inner_size()
        .map(|s| s.to_logical::<f64>(scale))
        .unwrap_or(requested);
    if maximized {
        return actual_inner;
    }
    let (Ok(inner), Ok(outer), Ok(Some(monitor))) = (
        window.inner_size(),
        window.outer_size(),
        window.current_monitor(),
    ) else {
        return actual_inner;
    };
    let mscale = monitor.scale_factor();
    let work = monitor.work_area();
    let work_size = work.size.to_logical::<f64>(mscale);
    let work_pos = work.position.to_logical::<f64>(mscale);
    let deco_w = outer.width.saturating_sub(inner.width) as f64 / scale;
    let deco_h = outer.height.saturating_sub(inner.height) as f64 / scale;
    let fitted = LogicalSize::new(
        actual_inner.width.min((work_size.width - deco_w).max(1.0)),
        actual_inner
            .height
            .min((work_size.height - deco_h).max(1.0)),
    );
    if fitted != actual_inner {
        let _ = window.set_size(fitted);
    }
    let _ = window.set_position(LogicalPosition::new(
        work_pos.x + ((work_size.width - (fitted.width + deco_w)) / 2.0).max(0.0),
        work_pos.y + ((work_size.height - (fitted.height + deco_h)) / 2.0).max(0.0),
    ));
    fitted
}

fn restore_main_window<R: Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn should_hide_on_close<R: Runtime>(app: &AppHandle<R>) -> bool {
    #[cfg(target_os = "macos")]
    {
        load_app_prefs(app).close_behavior == CloseBehavior::Hide
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = app;
        false
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default();
    #[cfg(target_os = "macos")]
    let builder = shell_startup::install(builder);
    #[cfg(all(target_os = "macos", debug_assertions))]
    let builder = startup_smoke::install(builder);
    builder
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        // Diagnostic beacon endpoint only. The wallet bridge does NOT use this
        // scheme: WebKit blocks cross-origin `fetch()` to custom schemes (one-way
        // subresource loads only), so dApps talk to the `wallet_request` command
        // via `invoke` instead. Kept as a one-way `new Image().src=...` beacon for
        // observing remote-page behaviour during development.
        .register_uri_scheme_protocol("adipc", |_ctx, request| {
            let origin = request
                .headers()
                .get("origin")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("<none>");
            println!(
                "[AutoDesktop] adipc beacon: {}  origin={origin}",
                request.uri()
            );
            tauri::http::Response::builder()
                .status(200)
                .header("Access-Control-Allow-Origin", "*")
                .header(tauri::http::header::CONTENT_TYPE, "application/json")
                .body(br#"{"ok":true}"#.to_vec())
                .unwrap()
        })
        .invoke_handler(tauri::generate_handler![
            wallet_request,
            dapp_dialog,
            resolve_dapp_dialog,
            approve_request,
            reject_request,
            get_pending_requests,
            open_dapp,
            set_dapp_bounds,
            sync_toast_overlay,
            sync_menu_overlay,
            reload_dapp,
            navigate_dapp,
            go_back_dapp,
            hide_dapp,
            show_dapp,
            close_dapp,
            open_external_url,
            node_rpc,
            inspect_safe,
            safe_pending_transactions,
            safe_confirm_transaction,
            simulate_tx,
            wallet_send,
            set_active_chain,
            get_active_chain,
            get_close_behavior,
            set_close_behavior,
            check_for_update,
            get_activity,
            sync_activity_receipts,
            replace_activity_transaction,
            get_portfolio_history,
            record_portfolio_snapshot,
            delete_portfolio_snapshot,
            get_diagnostic_log_path,
            write_diagnostic_log,
            get_price_oracle_prices,
            get_defi_positions,
            relay_chains,
            relay_quote,
            relay_status,
            okx_dex_supported_chains,
            okx_dex_tokens,
            okx_dex_quote,
            okx_dex_swap,
            okx_dex_approve_transaction,
            okx_dex_history,
            okx_connection_status,
            okx_save_credentials,
            okx_delete_credentials,
            okx_get_assets,
            okx_get_dcd_index_prices,
            okx_get_dcd_orders,
            okx_save_dcd_csv,
            get_chains,
            add_chain,
            update_chain,
            remove_chain,
            vault_status,
            create_vault,
            import_vault,
            import_private_key,
            export_wallet_secret,
            unlock_vault,
            change_password,
            unlock_vault_with_touch_id,
            touch_id_status,
            enable_touch_id,
            disable_touch_id,
            lock_vault,
            reset_vault,
            ledger_addresses,
            connect_ledger,
            select_account,
            expose_dapp_account,
            add_account,
            rename_wallet,
            delete_wallet,
            get_connected_sites,
            disconnect_connected_site,
            note_user_activity,
            get_auto_lock_minutes,
            set_auto_lock_minutes,
            set_app_menu_language
        ])
        .setup(|app| {
            // Load any persisted custom networks / RPC overrides before the UI asks.
            load_chains(app.handle());
            load_connected_sites(app.handle());
            let idle_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(20)).await;
                    let minutes = load_app_prefs(&idle_handle).auto_lock_minutes;
                    auto_lock_tick_at(&idle_handle, minutes, unix_time_ms());
                }
            });
            // A Ledger-only setup has no secret at rest, so load it on boot (paths +
            // addresses are public) — it boots straight to the wallet, no password.
            // (Migrates a legacy vault.json into wallets/ as a side effect.)
            if let Err(e) = boot_load_ledger_only(app.handle()) {
                println!("[AutoDesktop] warn: could not restore Ledger wallets: {e}");
            }
            install_app_menu(app)?;
            let (startup_size, should_maximize) = startup_window_size(app);
            // Container window (no webview of its own). Built hidden so the
            // decoration-aware fitting below never flashes a wrongly-sized frame.
            let window = WindowBuilder::new(app, "main")
                .title("AutoDesktop")
                .inner_size(startup_size.width, startup_size.height)
                .min_inner_size(
                    MIN_WIN_W.min(startup_size.width),
                    MIN_WIN_H.min(startup_size.height),
                )
                .maximized(should_maximize)
                .resizable(true)
                .visible(false)
                .center()
                .build()?;
            let shell_size = fit_startup_window(&window, startup_size, should_maximize);

            // Shell webview (local, trusted): our React UI, fills the whole window.
            // Same WebView2 args as dApp tabs — WebView2 cannot mix browser args
            // in one user-data directory.
            let shell_builder = harden_webview(WebviewBuilder::new(
                "shell",
                WebviewUrl::App("index.html".into()),
            ));
            #[cfg(target_os = "macos")]
            let shell_builder = shell_startup::configure(app.handle(), shell_builder);
            let shell =
                window.add_child(shell_builder, LogicalPosition::new(0.0, 0.0), shell_size)?;
            window.set_always_on_top(true)?;
            window.show()?;
            window.set_focus()?;
            log_diagnostic(
                app.handle(),
                format!(
                    "version={} startup main window shown always_on_top=true",
                    env!("CARGO_PKG_VERSION")
                ),
            );
            let startup_window = window.clone();
            let startup_app = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(Duration::from_secs(3)).await;
                let _ = startup_window.set_always_on_top(false);
                log_diagnostic(
                    &startup_app,
                    format!(
                        "version={} startup main window always_on_top=false",
                        env!("CARGO_PKG_VERSION")
                    ),
                );
            });

            // dApp tab webviews (remote, untrusted) are created on demand, one per
            // open tab, by `open_dapp` (see create_dapp_webview). Each is labeled
            // `dapp-<id>` and matched by capabilities/dapp.json (`webviews:
            // ["dapp-*"]`), which grants ONLY `allow-wallet-request` (+ remote URL
            // scope) — no core/fs/shell. That single command is the entire attack
            // surface. None exist at startup, so the Wallet page shows uncovered.

            // Child webviews keep fixed bounds, so make the shell fill the window
            // on resize ("可调窗口"). The dapp webview tracks the content rect
            // separately: resizing the shell resizes `.browser-content`, whose
            // ResizeObserver calls set_dapp_bounds from JS.
            let shell_for_resize = shell.clone();
            let window_for_close = window.clone();
            let app_for_window_events = app.handle().clone();
            window.on_window_event(move |event| match event {
                tauri::WindowEvent::Resized(size) => {
                    let scale = shell_for_resize.window().scale_factor().unwrap_or(1.0);
                    let logical = size.to_logical::<f64>(scale);
                    let _ =
                        shell_for_resize.set_size(LogicalSize::new(logical.width, logical.height));
                    repair_active_dapp_after_shell_resize(&app_for_window_events);
                }
                tauri::WindowEvent::CloseRequested { api, .. } => {
                    if should_hide_on_close(&app_for_window_events) {
                        api.prevent_close();
                        let _ = window_for_close.hide();
                    }
                }
                _ => {}
            });

            // CI smoke mode (no-op unless AUTODESKTOP_SMOKE_DIR is set): opens a
            // loopback-served dApp page in a real dapp-* webview and reports
            // whether the injected provider answered. See src/smoke.rs + ci.yml.
            smoke::maybe_start(app.handle());
            #[cfg(all(target_os = "macos", debug_assertions))]
            startup_smoke::start(app.handle());

            Ok(())
        })
        .build(build_context())
        .expect("error while building tauri application")
        .run(|app, event| {
            #[cfg(target_os = "macos")]
            {
                if let tauri::RunEvent::Reopen { .. } = event {
                    restore_main_window(app);
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Chain id for the loopback stubs below. Must not collide with anything in
    /// the real registry — see `stalled_node_chain`.
    pub(super) const TEST_CHAIN_ID: &str = "0xdeadbeef";

    /// A node that accepts the connection and then says nothing — the exact shape
    /// of the stall that left Send spinning with no window and no error. Returns
    /// the chain pointed at it; the listener thread holds the socket open.
    pub(super) fn stalled_node_chain() -> ChainCfg {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            let _held = listener.accept(); // keep the connection open, never reply
            std::thread::sleep(Duration::from_secs(30));
        });
        ChainCfg {
            // Deliberately not a real chain id. find_chain returns the FIRST
            // match, so "0x1" here resolved to the builtin Ethereum and sent a
            // signed transaction to the live network.
            id: TEST_CHAIN_ID.into(),
            name: "Stalled".into(),
            symbol: "ETH".into(),
            rpc: format!("http://{addr}"),
            decimals: 18,
            color: "#000".into(),
            explorer_url: None,
            builtin: false,
        }
    }

    /// A node that never answers must fail the call, not hang it. Before this,
    /// `http()` was a bare `reqwest::Client::new()` with no timeout of any kind,
    /// so one stalled socket parked the whole Send behind it forever.
    #[test]
    fn an_rpc_call_gives_up_when_the_node_never_answers() {
        let chain = stalled_node_chain();
        let started = std::time::Instant::now();
        let out = tauri::async_runtime::block_on(node_rpc_call_within(
            &chain,
            "eth_chainId",
            &[],
            Duration::from_millis(300),
        ));
        assert!(out.is_err(), "a silent node must produce an error");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "gave up only after {:?}",
            started.elapsed()
        );
    }

    /// One bad reading draws a crash the wallet never had, so it has to be
    /// removable — and by the exact row, not by value: two accounts can record
    /// the same total, and one account can revisit a total it already had.
    #[test]
    fn deleting_a_reading_drops_that_row_alone() {
        let snap = |addr: &str, usd: f64, ts: u64| PortfolioSnapshot {
            address: addr.into(),
            total_usd: usd,
            timestamp: ts,
        };
        let a = "0x7521eda00e2ce05ac4a9d8353d096ccb970d5188";
        let b = "0x2fb4d46372ea1748ec3c29bd2c7b536019df5200";
        let history = vec![
            snap(a, 141_340.53, 100),
            snap(b, 8.68, 200), // same total, same instant, different account
            snap(a, 8.68, 200), // the bogus reading
            snap(a, 143_631.42, 300),
        ];

        let (kept, removed) = without_snapshot(history.clone(), a, 200);
        assert_eq!(removed, 1);
        assert_eq!(
            kept.iter()
                .map(|s| (s.address.as_str(), s.timestamp))
                .collect::<Vec<_>>(),
            vec![(a, 100), (b, 200), (a, 300)],
        );

        // A timestamp the account never recorded must report that, so the caller
        // can refuse instead of reporting a delete the history never saw.
        let (kept, removed) = without_snapshot(history.clone(), a, 250);
        assert_eq!(removed, 0);
        assert_eq!(kept.len(), history.len());

        // Addresses compare case-insensitively, as everywhere else in the file:
        // a history written by an older version may not be lowercased.
        let (_, removed) = without_snapshot(history, &a.to_uppercase(), 100);
        assert_eq!(removed, 1);
    }

    /// `WebviewWindowBuilder::build()` only posts a CreateWindow message to the
    /// event loop and returns Ok, so its Ok is not proof the window exists. The
    /// approval UI reporting in is. With no such report the wait must fail inside
    /// its budget — never fall through to the 300s decision timer.
    #[test]
    fn waiting_for_the_approval_window_fails_when_it_never_comes_up() {
        let started = std::time::Instant::now();
        // u64::MAX as the baseline can never be exceeded, so a real approval
        // window polling in a parallel test cannot make this pass by accident.
        let out = tauri::async_runtime::block_on(wait_for_approval_ui(
            u64::MAX,
            Duration::from_millis(300),
        ));
        assert!(
            out.is_err(),
            "a window that never appears must fail the wait"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "waited {:?}",
            started.elapsed()
        );
    }

    /// …and clears as soon as the approval window's UI calls into the backend.
    #[test]
    fn waiting_for_the_approval_window_clears_once_its_ui_calls_in() {
        let baseline = approval_ui_beat();
        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(50));
            note_approval_ui_alive();
        });
        let out =
            tauri::async_runtime::block_on(wait_for_approval_ui(baseline, Duration::from_secs(5)));
        assert!(
            out.is_ok(),
            "a live approval UI must clear the wait: {out:?}"
        );
    }

    /// A speed-up whose broadcast was never acknowledged must NOT retire the
    /// transaction it replaces: same nonce, unknown outcome, so the original is
    /// still the one that might mine. Showing it as "replaced" hides a live
    /// transaction from the person who just tried to cancel it.
    #[test]
    fn only_a_confirmed_replacement_retires_the_original() {
        let original = ActivityRecord {
            id: "0x1:0xabc".into(),
            hash: "0xabc".into(),
            chain_id: "0x1".into(),
            chain_name: "Ethereum".into(),
            symbol: "ETH".into(),
            from: SPIKE_ACCOUNT.into(),
            to: SPIKE_ACCOUNT.into(),
            value: "0x1".into(),
            data: "0x".into(),
            gas: "0x5208".into(),
            nonce: "0x1".into(),
            max_priority_fee_per_gas: "0x1".into(),
            max_fee_per_gas: "0x2".into(),
            origin: "AutoDesktop Wallet".into(),
            kind: "send".into(),
            counterparty: None,
            asset_symbol: None,
            asset_decimals: None,
            amount: None,
            token_address: None,
            swap: None,
            balance_changes: Vec::new(),
            status: Some("submitted".to_string()),
            timestamp: 0,
        };

        let unconfirmed = Broadcast {
            hash: "0xdef".into(),
            broadcast_error: Some("node never answered".into()),
        };
        let mut records = vec![original.clone()];
        assert!(!retire_original(&mut records, "0x1:0xabc", &unconfirmed));
        assert_eq!(
            records[0].status.as_deref(),
            Some("submitted"),
            "an unconfirmed replacement must leave the original pending"
        );

        let confirmed = Broadcast {
            hash: "0xdef".into(),
            broadcast_error: None,
        };
        let mut records = vec![original];
        assert!(retire_original(&mut records, "0x1:0xabc", &confirmed));
        assert_eq!(records[0].status.as_deref(), Some("replaced"));
    }

    /// Broadcasting is the one call where "no answer" and "no thanks" must not be
    /// treated alike: a refusal means nothing is in flight, while silence means the
    /// signed transaction might be. Getting this backwards either invents a pending
    /// transfer or hides a real one.
    #[test]
    fn a_silent_node_and_a_refusing_node_fail_differently() {
        let silent = stalled_node_chain();
        let out = tauri::async_runtime::block_on(node_rpc_try(
            &silent,
            "eth_sendRawTransaction",
            &[json!("0x02f8")],
            Duration::from_millis(300),
        ));
        assert!(
            matches!(out, Err(RpcFailure::Unreachable(_))),
            "a node that never answers is Unreachable"
        );

        let refusing = refusing_node_chain("nonce too low", -32000);
        let out = tauri::async_runtime::block_on(node_rpc_try(
            &refusing,
            "eth_sendRawTransaction",
            &[json!("0x02f8")],
            Duration::from_secs(5),
        ));
        match out {
            Err(RpcFailure::Rejected(msg)) => assert!(
                msg.contains("nonce too low") && msg.contains("-32000"),
                "the node's own words survive: {msg}"
            ),
            other => panic!("a JSON-RPC error must be Rejected, got {:?}", other.is_ok()),
        }
    }

    /// A node that answers every call with one JSON-RPC error.
    fn refusing_node_chain(message: &str, code: i64) -> ChainCfg {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"error":{{"code":{code},"message":"{message}"}}}}"#
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            for stream in listener.incoming().take(4) {
                let Ok(mut stream) = stream else { continue };
                use std::io::{Read, Write};
                let mut scratch = [0u8; 2048];
                let _ = stream.read(&mut scratch); // drain the request line + body
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                );
            }
        });
        ChainCfg {
            id: TEST_CHAIN_ID.into(),
            name: "Refusing".into(),
            symbol: "ETH".into(),
            rpc: format!("http://{addr}"),
            decimals: 18,
            color: "#000".into(),
            explorer_url: None,
            builtin: false,
        }
    }

    /// A prompt centred at (0,0) lands on the primary display no matter which
    /// monitor the wallet is on — the multi-monitor version of "no window
    /// appeared". It has to follow the shell's monitor, including monitors whose
    /// global origin is negative (left of / above the primary).
    #[test]
    fn the_approval_window_centres_on_the_shell_s_own_monitor() {
        // A 5120x2880 display sitting to the right of a 3024x1964 primary.
        assert_eq!(
            centered_on_monitor((3024, 0), (5120, 2880), (420, 640)),
            (3024 + 2350, 1120)
        );
        // …and one placed to the LEFT, where the origin is negative.
        assert_eq!(
            centered_on_monitor((-2880, -300), (2880, 5120), (420, 640)),
            (-2880 + 1230, -300 + 2240)
        );
        // A window larger than the screen pins to the origin instead of going off it.
        assert_eq!(
            centered_on_monitor((100, 50), (400, 400), (900, 900)),
            (100, 50)
        );
    }

    /// The budget the user actually feels: click Send → window. Ten seconds is the
    /// ceiling; the 300s timer is only for reading and deciding, once the window
    /// is up and visible.
    #[test]
    fn the_pre_approval_budget_stays_within_ten_seconds() {
        assert!(TX_PREPARE_TIMEOUT <= Duration::from_secs(10));
        assert!(APPROVAL_WINDOW_TIMEOUT <= Duration::from_secs(10));
        assert!(RPC_TIMEOUT <= TX_PREPARE_TIMEOUT);
    }

    /// Known test vector — the canonical Hardhat/Anvil account #0.
    #[test]
    fn derives_known_evm_address() {
        let priv_bytes =
            hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
                .unwrap();
        let signing_key = SigningKey::from_bytes(priv_bytes.as_slice().into()).unwrap();
        let wallet = derive_wallet(&signing_key);
        assert_eq!(wallet.address, "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        assert_eq!(wallet.public_key.len(), 2 + 130);
    }

    /// WebView2 on Windows exposes Chromium WebHID. A dApp page that obtained it
    /// could race APDUs against a Ledger during on-device review. These flags
    /// are how we turn that API off; deleting WebHID from the string fails this.
    #[test]
    fn windows_webview_args_disable_webhid() {
        let args = WINDOWS_WEBVIEW_BROWSER_ARGS;
        assert!(
            args.split(|c: char| c == '=' || c == ',' || c == ' ')
                .any(|f| f == "WebHID"),
            "WebHID must be in --disable-features; got {args}"
        );
        assert!(
            args.split(|c: char| c == '=' || c == ',' || c == ' ')
                .any(|f| f == "WebUSB"),
            "WebUSB must be in --disable-features; got {args}"
        );
        // additional_browser_args replaces wry's defaults.
        assert!(args.contains("msWebOOUI"), "{args}");
        assert!(args.contains("msPdfOOUI"), "{args}");
        assert!(args.contains("msSmartScreenProtection"), "{args}");
        assert!(
            args.contains("autoplay-policy=no-user-gesture-required"),
            "{args}"
        );
    }

    /// WebView2 refuses two webviews in the same user-data dir with different
    /// additional_browser_args (blank child window). Every production builder
    /// therefore goes through harden_webview / harden_window.
    #[test]
    fn every_production_webview_gets_the_windows_hid_flags() {
        let src = include_str!("lib.rs");
        let production = src
            .split("mod tests {")
            .next()
            .expect("lib.rs has a tests module");
        let builders = production.matches("WebviewBuilder::new").count();
        let windows = production.matches("WebviewWindowBuilder::new").count();
        let hardened = production.matches("harden_webview(").count();
        let window_hardened = production.matches("harden_window(").count();
        assert_eq!(
            builders, hardened,
            "each WebviewBuilder::new must be passed through harden_webview"
        );
        assert_eq!(
            windows, window_hardened,
            "each WebviewWindowBuilder::new must be passed through harden_window"
        );
        assert!(
            builders >= 4,
            "expected shell + dapp + toast + menu builders, found {builders}"
        );
        assert!(windows >= 1, "expected the approval window builder");
    }

    /// The blank-rectangle bug: a child webview renders over the shell, so one
    /// shown before it has painted covers the shell's loading animation with
    /// white for the whole page load.
    #[test]
    fn a_dapp_webview_stays_hidden_until_its_page_has_loaded_once() {
        let label = "dapp-show-policy-test";
        forget_dapp_loaded(label);

        // Never loaded: showing it would blank out the loading animation.
        assert!(!show_dapp_on_open(label));

        // Loaded: switching back to that tab must show its page at once.
        mark_dapp_loaded(label);
        assert!(show_dapp_on_open(label));

        // Closing the tab destroys the webview, so the next one is blank again.
        forget_dapp_loaded(label);
        assert!(!show_dapp_on_open(label));
    }

    #[test]
    fn dapp_load_state_is_per_tab() {
        forget_dapp_loaded("dapp-per-tab-a");
        forget_dapp_loaded("dapp-per-tab-b");
        mark_dapp_loaded("dapp-per-tab-a");

        assert!(show_dapp_on_open("dapp-per-tab-a"));
        assert!(!show_dapp_on_open("dapp-per-tab-b"));
    }

    /// reqwest's Display stops at "error sending request for url (…)" — whether
    /// that was DNS, a refused connection or the 12s timeout only shows up in
    /// the source chain, so a log without it cannot say why a provider failed.
    #[test]
    fn error_chain_reports_the_cause_not_just_the_wrapper() {
        #[derive(Debug)]
        struct Cause;
        impl std::fmt::Display for Cause {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "operation timed out")
            }
        }
        impl std::error::Error for Cause {}

        #[derive(Debug)]
        struct Wrapper(Cause);
        impl std::fmt::Display for Wrapper {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "error sending request for url (https://api.zerion.io/)")
            }
        }
        impl std::error::Error for Wrapper {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }

        assert_eq!(
            error_chain(&Wrapper(Cause)),
            "error sending request for url (https://api.zerion.io/): operation timed out"
        );
        // An error with no cause reads exactly as before.
        assert_eq!(error_chain(&Cause), "operation timed out");
    }

    #[test]
    fn random_wallets_are_unique() {
        let a = generate_wallet();
        let b = generate_wallet();
        assert_ne!(a.address, b.address);
        assert_eq!(a.address.len(), 2 + 40);
    }

    #[test]
    fn classifies_methods() {
        // wallet state
        assert_eq!(route_method("eth_accounts"), Route::Wallet);
        assert_eq!(route_method("eth_requestAccounts"), Route::Wallet);
        assert_eq!(route_method("eth_chainId"), Route::Wallet);
        assert_eq!(route_method("wallet_switchEthereumChain"), Route::Wallet);
        // needs the private key + approval
        assert_eq!(route_method("personal_sign"), Route::Signing);
        assert_eq!(route_method("eth_sendTransaction"), Route::Signing);
        assert_eq!(route_method("eth_signTypedData_v4"), Route::Signing);
        // the read-only long tail → forwarded to the node
        assert_eq!(route_method("eth_getBalance"), Route::Forward);
        assert_eq!(route_method("eth_call"), Route::Forward);
        assert_eq!(route_method("eth_blockNumber"), Route::Forward);
        assert_eq!(route_method("eth_getTransactionReceipt"), Route::Forward);
    }

    #[test]
    fn chain_registry_lookup() {
        assert_eq!(find_chain("0x1").unwrap().name, "Ethereum");
        assert_eq!(find_chain("0x2105").unwrap().name, "Base");
        // case-insensitive id match
        assert_eq!(find_chain("0xA4B1").unwrap().name, "Arbitrum One");
        assert!(find_chain("0xdead").is_none());
        // every built-in chain has a https RPC and a unique id
        let chains = builtin_chains();
        for c in &chains {
            assert!(c.rpc.starts_with("https://"), "{} has no https rpc", c.name);
            assert_eq!(chains.iter().filter(|x| x.id == c.id).count(), 1);
            assert!(c.builtin);
        }
    }

    /// The API key must never be baked into the committed chain defaults — those
    /// URLs get written to chains.json and shown in Settings.
    #[test]
    fn builtin_chains_carry_no_api_key() {
        for c in builtin_chains() {
            if !c.rpc.contains("publicnode.com") {
                continue;
            }
            let after_scheme = c.rpc.trim_start_matches("https://").trim_end_matches('/');
            assert!(
                !after_scheme.contains('/'),
                "{} ships a keyed publicnode URL: {}",
                c.name,
                c.rpc
            );
        }
    }

    #[test]
    fn appends_public_node_key_to_publicnode_hosts_only() {
        const KEY: &str = "testkey123";

        // Every publicnode default gets the key as the last path segment.
        assert_eq!(
            apply_public_node_key("https://ethereum-rpc.publicnode.com", KEY),
            "https://ethereum-rpc.publicnode.com/testkey123"
        );
        assert_eq!(
            apply_public_node_key("https://bsc-rpc.publicnode.com/", KEY),
            "https://bsc-rpc.publicnode.com/testkey123"
        );
        assert_eq!(
            apply_public_node_key("https://publicnode.com", KEY),
            "https://publicnode.com/testkey123"
        );

        // Other providers are untouched — the key goes nowhere near them.
        for url in [
            "https://rpc.soniclabs.com",
            "https://zkevm-rpc.com",
            "https://andromeda.metis.io/?owner=1088",
            "https://gwan-ssl.wandevs.org:56891",
            "https://worldchain-mainnet.g.alchemy.com/public",
        ] {
            assert_eq!(
                apply_public_node_key(url, KEY),
                url,
                "leaked key into {url}"
            );
        }

        // A host merely *containing* the string must not match: the suffix check
        // runs on the host, not the whole URL.
        for url in [
            "https://evil.example/publicnode.com",
            "https://evil.example?x=publicnode.com",
            "https://notpublicnode.com",
            "https://publicnode.com.evil.example",
        ] {
            assert_eq!(
                apply_public_node_key(url, KEY),
                url,
                "leaked key into {url}"
            );
        }

        // Already keyed / custom-path publicnode endpoints are left as configured.
        assert_eq!(
            apply_public_node_key("https://ethereum-rpc.publicnode.com/otherkey", KEY),
            "https://ethereum-rpc.publicnode.com/otherkey"
        );
    }

    #[test]
    fn decodes_safe_owner_array_strictly() {
        let raw = json!(concat!(
            "0x",
            "0000000000000000000000000000000000000000000000000000000000000020",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000001111111111111111111111111111111111111111",
            "0000000000000000000000002222222222222222222222222222222222222222"
        ));
        assert_eq!(
            decode_abi_addresses(&raw, "owners").unwrap(),
            vec![
                "0x1111111111111111111111111111111111111111",
                "0x2222222222222222222222222222222222222222"
            ]
        );
        assert!(decode_abi_addresses(&json!("0x20"), "owners").is_err());
    }

    #[test]
    fn safe_api_key_is_scoped_to_official_https_service() {
        assert!(is_official_safe_service_url(
            "https://api.safe.global/tx-service/eth/api/v1/about/"
        ));
        assert!(!is_official_safe_service_url(
            "http://api.safe.global/tx-service/eth/api/v1/about/"
        ));
        assert!(!is_official_safe_service_url(
            "https://api.safe.global.attacker.example/tx-service/eth/api"
        ));
        assert!(!is_official_safe_service_url(
            "https://safe.internal.example/api"
        ));
    }

    #[test]
    fn safe_typed_data_matches_contract_hash_formula() {
        let safe = "0x2222222222222222222222222222222222222222";
        let to = "0x1111111111111111111111111111111111111111";
        let tx = json!({
            "safe": safe,
            "to": to,
            "value": "5",
            "data": "0x1234",
            "operation": 0,
            "safeTxGas": "0",
            "baseGas": "0",
            "gasPrice": "0",
            "gasToken": "0x0000000000000000000000000000000000000000",
            "refundReceiver": "0x0000000000000000000000000000000000000000",
            "nonce": "7",
            "safeTxHash": "0x00"
        });
        let typed = safe_transaction_typed_data("0x1", safe, &tx).unwrap();
        let actual = eip712::signing_hash(&typed).unwrap();

        let mut domain_preimage = Vec::new();
        domain_preimage.extend_from_slice(
            &hex::decode("47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218")
                .unwrap(),
        );
        let mut chain_word = [0u8; 32];
        chain_word[31] = 1;
        domain_preimage.extend_from_slice(&chain_word);
        let mut safe_word = [0u8; 32];
        safe_word[12..].copy_from_slice(&hex::decode(&safe[2..]).unwrap());
        domain_preimage.extend_from_slice(&safe_word);
        let domain_hash = Keccak256::digest(&domain_preimage);

        let mut struct_preimage = Vec::new();
        struct_preimage.extend_from_slice(
            &hex::decode("bb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8")
                .unwrap(),
        );
        let mut to_word = [0u8; 32];
        to_word[12..].copy_from_slice(&hex::decode(&to[2..]).unwrap());
        struct_preimage.extend_from_slice(&to_word);
        let mut value_word = [0u8; 32];
        value_word[31] = 5;
        struct_preimage.extend_from_slice(&value_word);
        struct_preimage.extend_from_slice(&Keccak256::digest([0x12, 0x34]));
        struct_preimage.extend_from_slice(&[0u8; 32]); // operation
        struct_preimage.extend_from_slice(&[0u8; 32]); // safeTxGas
        struct_preimage.extend_from_slice(&[0u8; 32]); // baseGas
        struct_preimage.extend_from_slice(&[0u8; 32]); // gasPrice
        struct_preimage.extend_from_slice(&[0u8; 32]); // gasToken
        struct_preimage.extend_from_slice(&[0u8; 32]); // refundReceiver
        let mut nonce_word = [0u8; 32];
        nonce_word[31] = 7;
        struct_preimage.extend_from_slice(&nonce_word);
        let struct_hash = Keccak256::digest(&struct_preimage);

        let mut digest_preimage = vec![0x19, 0x01];
        digest_preimage.extend_from_slice(&domain_hash);
        digest_preimage.extend_from_slice(&struct_hash);
        let expected = Keccak256::digest(&digest_preimage);
        assert_eq!(&actual[..], &expected[..]);
    }

    /// A chains.json written by an old app version (fewer built-ins) must not
    /// freeze the registry: built-ins added in later releases have to appear
    /// after the merge, while user RPC edits and custom chains survive.
    #[test]
    fn merge_persisted_chains_backfills_new_builtins() {
        // Simulate an old snapshot: only Ethereum (with a user-edited RPC) and
        // one custom chain — none of the extended default set.
        let mut old_eth = builtin_chains()[0].clone();
        assert_eq!(old_eth.id, "0x1");
        old_eth.rpc = "https://my-private-eth-node.example".to_string();
        let custom = ChainCfg {
            id: "0x40d9".to_string(),
            name: "0G Mainnet".to_string(),
            symbol: "0G".to_string(),
            rpc: "https://evmrpc.0g.ai".to_string(),
            decimals: 18,
            color: "#888888".to_string(),
            explorer_url: None,
            builtin: false,
        };
        let merged = merge_persisted_chains(vec![old_eth, custom]);

        // Every current built-in is present, in built-in order.
        let builtins = builtin_chains();
        assert!(merged.len() == builtins.len() + 1);
        for (i, b) in builtins.iter().enumerate() {
            assert_eq!(merged[i].id, b.id, "missing/misplaced built-in {}", b.name);
            assert!(merged[i].builtin);
        }
        // The user's RPC edit on Ethereum survives the merge.
        assert_eq!(merged[0].rpc, "https://my-private-eth-node.example");
        // Backfilled built-ins carry current defaults (e.g. BNB Chain).
        let bnb = merged.iter().find(|c| c.id == "0x38").unwrap();
        assert_eq!(bnb.name, "BNB Chain");
        assert_eq!(bnb.rpc, "https://bsc-dataseed.bnbchain.org");
        // The custom chain stays, after the built-ins.
        assert_eq!(merged.last().unwrap().id, "0x40d9");
        assert!(!merged.last().unwrap().builtin);
    }

    #[test]
    fn merge_persisted_chains_migrates_only_the_old_bnb_default_rpc() {
        let mut old_default = builtin_chains()
            .into_iter()
            .find(|c| c.id == "0x38")
            .unwrap();
        old_default.rpc = "https://bsc-rpc.publicnode.com".to_string();

        let migrated = merge_persisted_chains(vec![old_default]);
        assert_eq!(
            migrated.iter().find(|c| c.id == "0x38").unwrap().rpc,
            "https://bsc-dataseed.bnbchain.org"
        );

        let mut custom = builtin_chains()
            .into_iter()
            .find(|c| c.id == "0x38")
            .unwrap();
        custom.rpc = "https://my-bnb-node.example".to_string();

        let preserved = merge_persisted_chains(vec![custom]);
        assert_eq!(
            preserved.iter().find(|c| c.id == "0x38").unwrap().rpc,
            "https://my-bnb-node.example"
        );
    }

    /// A chain the user added manually before it became a built-in is promoted:
    /// it keeps the user's settings but becomes non-removable and sorts with the
    /// built-ins; missing explorer URLs are hydrated.
    #[test]
    fn merge_persisted_chains_promotes_formerly_custom_builtin() {
        let persisted = vec![ChainCfg {
            id: "0x38".to_string(), // BNB Chain, added by hand pre-0.2.x
            name: "BSC".to_string(),
            symbol: "BNB".to_string(),
            rpc: "https://bsc-dataseed.bnbchain.org".to_string(),
            decimals: 18,
            color: "#F3BA2F".to_string(),
            explorer_url: None,
            builtin: false,
        }];
        let merged = merge_persisted_chains(persisted);
        let bnb = merged.iter().find(|c| c.id == "0x38").unwrap();
        assert!(bnb.builtin, "matching built-in id must be promoted");
        assert_eq!(
            bnb.name, "BSC",
            "user's edits win over the built-in defaults"
        );
        assert_eq!(bnb.rpc, "https://bsc-dataseed.bnbchain.org");
        assert_eq!(
            bnb.explorer_url.as_deref(),
            Some("https://bscscan.com/tx/"),
            "missing explorer url is hydrated"
        );
        assert_eq!(merged.len(), builtin_chains().len());
    }

    #[test]
    fn provided_legacy_gas_price_maps_to_eip1559_fees() {
        let tx = json!({ "gasPrice": "0x59682f00" }); // 1.5 gwei

        assert_eq!(
            resolve_provided_fees(&tx),
            Some(("0x59682f00".to_string(), "0x59682f00".to_string()))
        );
    }

    #[test]
    fn zero_eip1559_fees_are_not_treated_as_provided() {
        let tx = json!({
            "maxPriorityFeePerGas": "0x0",
            "maxFeePerGas": "0x0",
        });

        assert_eq!(resolve_provided_fees(&tx), None);
    }

    #[test]
    fn normalize_chain_id_accepts_hex_and_decimal() {
        assert_eq!(normalize_chain_id("0x1").unwrap(), "0x1");
        assert_eq!(normalize_chain_id("0xA4B1").unwrap(), "0xa4b1"); // lowercased
        assert_eq!(normalize_chain_id("137").unwrap(), "0x89"); // decimal → hex
        assert_eq!(normalize_chain_id("  0x2105 ").unwrap(), "0x2105"); // trimmed
        assert!(normalize_chain_id("0x0").is_err()); // zero rejected
        assert!(normalize_chain_id("xyz").is_err());
    }

    #[test]
    fn validate_rpc_requires_https_except_local_dev() {
        assert!(validate_rpc("https://rpc.example.com").is_ok());
        // Plain http is fine for local/LAN dev nodes…
        assert!(validate_rpc("http://localhost:8545").is_ok());
        assert!(validate_rpc("http://127.0.0.1:8545").is_ok());
        assert!(validate_rpc("http://192.168.1.50:8545").is_ok());
        assert!(validate_rpc("http://10.0.0.7:8545").is_ok());
        // …but NOT for arbitrary internet hosts (cleartext = MITM-able RPC).
        assert!(validate_rpc("http://rpc.example.com").is_err());
        assert!(validate_rpc("http://8.8.8.8:8545").is_err());
        assert!(validate_rpc("ftp://nope").is_err());
        assert!(validate_rpc("rpc.example.com").is_err());
        assert!(validate_rpc("https://").is_err());
    }

    #[test]
    fn tx_chain_id_must_match_selected_chain() {
        // No chainId in the tx → nothing to check (wallet's chain is used).
        assert!(ensure_tx_chain_id_matches(&json!({"to": "0x00"}), "0x1").is_ok());
        // Matching chainId, any accepted notation.
        assert!(ensure_tx_chain_id_matches(&json!({"chainId": "0x1"}), "0x1").is_ok());
        assert!(ensure_tx_chain_id_matches(&json!({"chainId": "0XA4B1"}), "0xa4b1").is_ok());
        assert!(ensure_tx_chain_id_matches(&json!({"chainId": 137}), "0x89").is_ok());
        // Mismatch → hard error: the wallet's global chain may have been switched
        // (another tab / the shell) after the dApp composed this transaction.
        let err = ensure_tx_chain_id_matches(&json!({"chainId": "0x89"}), "0x1").unwrap_err();
        assert!(err.contains("0x89") && err.contains("0x1"), "got: {err}");
        // Junk chainId → error, not silently ignored.
        assert!(ensure_tx_chain_id_matches(&json!({"chainId": "zzz"}), "0x1").is_err());
        assert!(ensure_tx_chain_id_matches(&json!({"chainId": true}), "0x1").is_err());
    }

    #[test]
    fn wallet_accounts_reflect_unlock_state() {
        // Unlocked: report the active account.
        assert_eq!(
            handle_wallet_method("eth_accounts", &[], "0x1", Some(SPIKE_ACCOUNT)).unwrap(),
            WalletOutcome::Reply(json!([SPIKE_ACCOUNT]))
        );
        assert_eq!(
            handle_wallet_method("eth_coinbase", &[], "0x1", Some(SPIKE_ACCOUNT)).unwrap(),
            WalletOutcome::Reply(json!(SPIKE_ACCOUNT))
        );
        // Locked: no account is exposed (dApp shows a connect prompt).
        assert_eq!(
            handle_wallet_method("eth_accounts", &[], "0x1", None).unwrap(),
            WalletOutcome::Reply(json!([]))
        );
        assert_eq!(
            handle_wallet_method("eth_coinbase", &[], "0x1", None).unwrap(),
            WalletOutcome::Reply(Value::Null)
        );
    }

    #[test]
    fn wallet_chain_id_reflects_current() {
        // eth_chainId / net_version reflect the passed-in current chain (account irrelevant).
        assert_eq!(
            handle_wallet_method("eth_chainId", &[], "0x2105", None).unwrap(),
            WalletOutcome::Reply(json!("0x2105"))
        );
        assert_eq!(
            handle_wallet_method("net_version", &[], "0x2105", None).unwrap(),
            WalletOutcome::Reply(json!("8453")) // 0x2105 == 8453
        );
        assert_eq!(
            handle_wallet_method("net_version", &[], "0x89", None).unwrap(),
            WalletOutcome::Reply(json!("137")) // 0x89 == 137
        );
    }

    #[test]
    fn preview_tx_summarizes() {
        // A value transfer reads as "Send N ETH → 0x…", shortening the address.
        let send = json!({
            "to": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
            "value": "0xde0b6b3a7640000" // 1e18 wei = 1 ETH
        });
        let s = preview_tx(&send, "ETH");
        assert!(s.contains("Send"), "got: {s}");
        assert!(s.contains("1.0000 ETH"), "got: {s}");
        assert!(s.contains("0x7099…79c8"), "got: {s}");
        // The native symbol is the chain's, not always ETH.
        let s = preview_tx(&send, "BNB");
        assert!(s.contains("1.0000 BNB") && !s.contains("ETH"), "got: {s}");

        // A call with data reads as a contract interaction.
        let call = json!({
            "to": "0x1111111111111111111111111111111111111111",
            "data": "0xa9059cbb"
        });
        assert!(preview_tx(&call, "ETH").contains("Contract interaction"));
    }

    #[test]
    fn estimated_gas_gets_twenty_percent_margin() {
        assert_eq!(bump_estimated_gas("0x5208").unwrap(), "0x6270"); // 21000 -> 25200
        assert_eq!(bump_estimated_gas("0xc351").unwrap(), "0xea62"); // ceil(50001 * 1.2)
        assert_eq!(bump_estimated_gas("0x0").unwrap(), "0x0");
    }

    #[test]
    fn parses_debank_protocol_positions() {
        let data = json!([
            {
                "id": "arb_gmx",
                "chain": "arb",
                "name": "GMX",
                "site_url": "https://app.gmx.io",
                "logo_url": "https://example.com/gmx.png",
                "portfolio_item_list": [
                    {
                        "name": "Staked",
                        "stats": { "net_usd_value": 5.5, "asset_usd_value": 5.5, "debt_usd_value": 0 },
                        "base": { "chain": "arb" },
                        "asset_token_list": [
                            { "symbol": "GMX", "amount": 1.25, "price": 4.4, "usd_value": 5.5 }
                        ]
                    }
                ]
            }
        ]);
        let positions = parse_debank_positions(&data).unwrap();
        assert_eq!(positions.len(), 1);
        assert_eq!(positions[0].app_name, "GMX");
        assert_eq!(positions[0].network_name, "Arbitrum");
        assert_eq!(positions[0].balance_usd, 5.5);
        assert_eq!(positions[0].symbols, vec!["GMX"]);
    }

    #[test]
    fn defi_provider_status_is_fit_for_the_persistent_log() {
        assert_eq!(
            defi_provider_status_message(true, false),
            "defi providers zerion=true debank=false"
        );
        assert_eq!(
            defi_provider_status_message(false, true),
            "defi providers zerion=false debank=true"
        );
    }

    #[test]
    fn defi_events_are_appended_to_the_persistent_log() {
        let path = std::env::temp_dir().join(format!(
            "autodesktop-defi-log-{}-{}.log",
            std::process::id(),
            unix_time_ms()
        ));

        append_defi_diagnostic(&path, "defi DeBank request start");

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains(&format!(
                "version={} defi DeBank request start",
                env!("CARGO_PKG_VERSION")
            )),
            "unexpected diagnostic log: {text}"
        );
        std::fs::remove_file(path).unwrap();
    }

    /// A position states its tokens twice. `detail` is the one that carries the
    /// uncollected fees, so it must win outright — not add a second row per token.
    #[test]
    fn debank_position_detail_supersedes_the_flat_asset_list() {
        let data = json!([
            {
                "id": "uniswap4",
                "chain": "eth",
                "name": "Uniswap V4",
                "portfolio_item_list": [
                    {
                        "name": "Liquidity Pool",
                        "stats": { "net_usd_value": 9412.74 },
                        "base": { "chain": "eth" },
                        "asset_token_list": [
                            { "optimized_symbol": "USDC", "amount": 173.594132, "usd_value": 173.73 },
                            { "optimized_symbol": "WETH", "amount": 4.907786, "usd_value": 9239.01 }
                        ],
                        "detail": {
                            "supply_token_list": [
                                { "optimized_symbol": "USDC", "amount": 180.640972, "usd_value": 180.78 },
                                { "optimized_symbol": "WETH", "amount": 4.903537, "usd_value": 9231.02 }
                            ],
                            "reward_token_list": [
                                { "optimized_symbol": "USDC", "amount": 0.506408, "usd_value": 0.51 }
                            ]
                        }
                    }
                ]
            }
        ]);

        let positions = parse_debank_positions(&data).unwrap();

        assert_eq!(positions.len(), 1);
        assert_eq!(positions[0].symbols, vec!["USDC", "WETH"]);
        // Two supply rows plus one reward row — the asset_token_list amounts
        // (173.594132 / 4.907786) must not appear alongside them.
        let amounts: Vec<&str> = positions[0]
            .tokens
            .iter()
            .map(|t| t.balance.as_deref().unwrap_or(""))
            .collect();
        assert_eq!(amounts, vec!["180.640972", "4.903537", "0.506408"]);
    }

    /// An empty `detail` must not shadow the flat list — that would leave a
    /// position with no token breakdown at all.
    #[test]
    fn debank_empty_detail_falls_back_to_the_flat_asset_list() {
        let data = json!([
            {
                "id": "arb_gmx",
                "chain": "arb",
                "name": "GMX",
                "portfolio_item_list": [
                    {
                        "name": "Staked",
                        "stats": { "net_usd_value": 5.5 },
                        "base": { "chain": "arb" },
                        "detail": { "supply_token_list": [], "description": "#1" },
                        "asset_token_list": [
                            { "optimized_symbol": "GMX", "amount": 1.25, "usd_value": 5.5 }
                        ]
                    }
                ]
            }
        ]);

        let positions = parse_debank_positions(&data).unwrap();

        assert_eq!(positions[0].symbols, vec!["GMX"]);
        assert_eq!(positions[0].tokens[0].balance.as_deref(), Some("1.25"));
    }

    #[test]
    fn parses_debank_single_protocol_response() {
        let data = json!({
            "id": "base_uniswap4",
            "chain": "base",
            "name": "Uniswap V4",
            "site_url": "https://app.uniswap.org",
            "logo_url": "https://static.debank.com/uniswap4.png",
            "has_supported_portfolio": true,
            "portfolio_item_list": [
                {
                    "name": "Liquidity Pool",
                    "stats": { "net_usd_value": 812.5 },
                    "base": { "chain": "base" },
                    "detail": {
                        "supply_token_list": [
                            { "optimized_symbol": "USDC", "amount": 400.0, "usd_value": 400.0 },
                            { "optimized_symbol": "ETH", "amount": 0.22, "usd_value": 412.5 }
                        ]
                    }
                }
            ]
        });

        let positions = parse_debank_protocol_positions(&data).unwrap();

        assert_eq!(positions.len(), 1);
        assert_eq!(positions[0].app_name, "Uniswap V4");
        assert_eq!(positions[0].label, "Liquidity Pool");
        assert_eq!(positions[0].balance_usd, 812.5);
        assert_eq!(positions[0].symbols, vec!["USDC", "ETH"]);
        assert_eq!(
            positions[0].app_url.as_deref(),
            Some("https://app.uniswap.org")
        );

        // A wallet with nothing in the protocol is a valid answer, not an error.
        let empty = json!({ "id": "zora_uniswap4", "chain": "zora", "portfolio_item_list": [] });
        assert!(parse_debank_protocol_positions(&empty).unwrap().is_empty());

        // DeBank's 400 body has no portfolio list at all — that is a failure.
        let rejected = json!({ "message": "Protocol not found" });
        assert!(parse_debank_protocol_positions(&rejected).is_err());
    }

    #[test]
    fn finds_the_uniswap_v4_protocol_id() {
        let base = json!([
            { "id": "base_uniswap3", "name": "Uniswap V3", "has_supported_portfolio": true },
            { "id": "base_uniswap4", "name": "Uniswap V4", "has_supported_portfolio": true },
            { "id": "base_aave3", "name": "Aave V3", "has_supported_portfolio": true }
        ]);
        assert_eq!(
            find_uniswap_v4_protocol_id(&base).as_deref(),
            Some("base_uniswap4")
        );

        // Ethereum carries the unprefixed id.
        let eth =
            json!([{ "id": "uniswap4", "name": "Uniswap V4", "has_supported_portfolio": true }]);
        assert_eq!(
            find_uniswap_v4_protocol_id(&eth).as_deref(),
            Some("uniswap4")
        );

        // A chain without v4 must resolve to nothing rather than to a near miss.
        let without = json!([
            { "id": "op_uniswap3", "name": "Uniswap V3", "has_supported_portfolio": true },
            { "id": "op_uniswap_permit2", "name": "Uniswap Permit2", "has_supported_portfolio": false }
        ]);
        assert_eq!(find_uniswap_v4_protocol_id(&without), None);

        // Listed but unqueryable is not worth a probe.
        let unsupported = json!([{ "id": "ink_uniswap4", "name": "Uniswap V4", "has_supported_portfolio": false }]);
        assert_eq!(find_uniswap_v4_protocol_id(&unsupported), None);
    }

    #[test]
    fn parses_debank_chain_ids() {
        let data = json!([
            { "id": "eth", "community_id": 1, "name": "Ethereum" },
            { "id": "base", "community_id": 8453, "name": "Base" },
            { "id": "uni", "community_id": 130, "name": "Unichain" },
            { "id": "btc", "name": "Bitcoin" }
        ]);

        let chains = parse_debank_chain_ids(&data);

        assert_eq!(chains.get("1").map(String::as_str), Some("eth"));
        assert_eq!(chains.get("8453").map(String::as_str), Some("base"));
        assert_eq!(chains.get("130").map(String::as_str), Some("uni"));
        // No EVM chain id means nothing to key a Zerion chain against.
        assert_eq!(chains.len(), 3);
    }

    #[test]
    fn picks_zerion_active_chains_richest_first() {
        let data = json!({
            "data": {
                "attributes": {
                    "positions_distribution_by_chain": {
                        "ethereum": 414.15,
                        "base": 34.68,
                        "binance-smart-chain": 653.95,
                        "scroll": 0,
                        "xdai": 0.0
                    }
                }
            }
        });

        assert_eq!(
            parse_zerion_active_chain_slugs(&data),
            vec!["binance-smart-chain", "ethereum", "base"]
        );
        // No distribution at all means no chain is worth probing.
        assert!(parse_zerion_active_chain_slugs(&json!({ "data": {} })).is_empty());
    }

    #[test]
    fn merges_uniswap_v4_supplement_into_the_zerion_set() {
        let mut primary = vec![
            defi_position("zerion:aave", "Aave", "0x1", 7.0),
            defi_position("zerion:univ4-base", "Uniswap V4", "0x2105", 50.0),
        ];
        let supplement = vec![
            // Below the Aave position, above nothing — sorting must interleave.
            defi_position("debank:uniswap4:eth", "Uniswap V4", "0x1", 9412.74),
            // Zerion already reports this one; taking it again would double-count.
            defi_position("debank:base_uniswap4:base", "Uniswap V4", "0x2105", 50.0),
        ];

        let added = merge_uniswap_v4_positions(&mut primary, supplement);

        assert_eq!(added, 1);
        assert_eq!(primary.len(), 3);
        assert_eq!(primary[0].id, "debank:uniswap4:eth");
        assert_eq!(primary[0].balance_usd, 9412.74);
        assert_eq!(primary[1].id, "zerion:univ4-base");
        assert_eq!(primary[2].id, "zerion:aave");
    }

    #[test]
    fn relabels_a_supplemented_position_in_the_primary_chain_vocabulary() {
        let position = relabel_position_chain(
            defi_position("debank:uniswap4:eth", "Uniswap V4", "eth", 12.0),
            "0x1",
            "Ethereum",
        );

        assert_eq!(position.chain_id, "0x1");
        assert_eq!(position.network_name, "Ethereum");
        assert_eq!(position.balance_usd, 12.0);
    }

    fn defi_position(id: &str, app_name: &str, chain_id: &str, balance_usd: f64) -> DefiPosition {
        DefiPosition {
            id: id.to_string(),
            app_name: app_name.to_string(),
            app_image_url: None,
            app_url: None,
            network_name: "Network".to_string(),
            chain_id: chain_id.to_string(),
            label: "Liquidity Pool".to_string(),
            group_label: None,
            balance_usd,
            symbols: Vec::new(),
            tokens: Vec::new(),
        }
    }

    #[test]
    fn parses_zerion_positions() {
        let data = json!({
            "data": [
                {
                    "type": "positions",
                    "id": "0xabc-ethereum-asset-none-",
                    "attributes": {
                        "protocol": "aave",
                        "name": "Asset",
                        "position_type": "deposit",
                        "quantity": { "numeric": "123.45", "float": 123.45 },
                        "value": 5.38,
                        "fungible_info": { "symbol": "USDC" },
                        "application_metadata": {
                            "name": "AAVE",
                            "icon": { "url": "https://icon.example/aave.png" },
                            "url": "https://app.aave.com/"
                        }
                    },
                    "relationships": {
                        "chain": { "data": { "type": "chains", "id": "ethereum" } }
                    }
                },
                {
                    "type": "positions",
                    "id": "0xdef-base-asset-none-",
                    "attributes": {
                        "protocol": "uniswap",
                        "name": "Asset",
                        "position_type": "staked",
                        "value": null,
                        "fungible_info": { "symbol": "UNI" }
                    },
                    "relationships": {
                        "chain": { "data": { "type": "chains", "id": "base" } }
                    }
                },
                {
                    "type": "positions",
                    "id": "0x123-binance-smart-chain-asset-none-",
                    "attributes": {
                        "protocol": "pancakeswap",
                        "name": "CAKE-BNB LP",
                        "position_type": "locked",
                        "quantity": { "numeric": "2.5" },
                        "value": 11.5,
                        "fungible_info": { "symbol": "CAKE-BNB" }
                    },
                    "relationships": {
                        "chain": { "data": { "type": "chains", "id": "binance-smart-chain" } }
                    }
                }
            ]
        });
        let mut chains = ZerionChainMap::new();
        chains.insert(
            "ethereum".to_string(),
            ("Ethereum".to_string(), "0x1".to_string()),
        );
        let (positions, total_usd) = parse_zerion_positions(&data, &chains);

        // The null-value position is dropped; the rest sort by USD desc.
        assert_eq!(positions.len(), 2);
        assert_eq!(total_usd, 16.88);

        assert_eq!(positions[0].id, "0x123-binance-smart-chain-asset-none-");
        assert_eq!(positions[0].app_name, "pancakeswap");
        assert_eq!(positions[0].balance_usd, 11.5);
        assert_eq!(positions[0].label, "CAKE-BNB LP");
        assert_eq!(positions[0].group_label.as_deref(), Some("Locked"));
        // Slug missing from the chain map falls back to the prettified slug.
        assert_eq!(positions[0].network_name, "Binance Smart Chain");
        assert_eq!(positions[0].chain_id, "binance-smart-chain");

        assert_eq!(positions[1].app_name, "AAVE");
        assert_eq!(
            positions[1].app_image_url.as_deref(),
            Some("https://icon.example/aave.png")
        );
        assert_eq!(
            positions[1].app_url.as_deref(),
            Some("https://app.aave.com/")
        );
        assert_eq!(positions[1].network_name, "Ethereum");
        assert_eq!(positions[1].chain_id, "0x1");
        // The generic "Asset" name gives way to the position type.
        assert_eq!(positions[1].label, "Deposit");
        assert_eq!(positions[1].symbols, vec!["USDC"]);
        assert_eq!(positions[1].tokens.len(), 1);
        assert_eq!(positions[1].tokens[0].balance.as_deref(), Some("123.45"));
        assert_eq!(positions[1].tokens[0].balance_usd, Some(5.38));
    }

    #[test]
    fn merges_custom_defi_with_primary_source() {
        let primary = DefiPosition {
            id: "zerion:aave:0".to_string(),
            app_name: "Aave".to_string(),
            app_image_url: None,
            app_url: None,
            network_name: "Ethereum".to_string(),
            chain_id: "0x1".to_string(),
            label: "Deposit".to_string(),
            group_label: None,
            balance_usd: 7.0,
            symbols: vec!["USDC".to_string()],
            tokens: Vec::new(),
        };
        let custom = DefiPosition {
            id: "custom:xstake:wanUSDT".to_string(),
            app_name: "XStake Farming".to_string(),
            app_image_url: None,
            app_url: Some(XSTAKE_APP_URL.to_string()),
            network_name: XSTAKE_CHAIN_NAME.to_string(),
            chain_id: XSTAKE_CHAIN_ID.to_string(),
            label: "wanUSDT farming".to_string(),
            group_label: Some("Earn xWAN".to_string()),
            balance_usd: 11.0,
            symbols: vec!["wanUSDT".to_string()],
            tokens: Vec::new(),
        };

        let response = merge_defi_positions("Zerion", vec![primary], Ok(vec![custom]));

        assert_eq!(response.source, "Zerion + Custom");
        assert_eq!(response.positions.len(), 2);
        assert_eq!(response.positions[0].app_name, "XStake Farming");
        assert_eq!(response.positions[1].app_name, "Aave");
    }

    fn zerion_position(id: &str, balance_usd: f64) -> DefiPosition {
        DefiPosition {
            id: id.to_string(),
            app_name: "GMX".to_string(),
            app_image_url: None,
            app_url: None,
            network_name: "Arbitrum".to_string(),
            chain_id: "0xa4b1".to_string(),
            label: "Staked".to_string(),
            group_label: None,
            balance_usd,
            symbols: vec!["GMX".to_string()],
            tokens: Vec::new(),
        }
    }

    const RATE_LIMITED: &str = "querying Zerion: HTTP status client error (429 Too Many Requests)";

    #[test]
    fn zerion_rate_limit_reuses_last_good_result() {
        let mut cache = ZerionCache::new();
        let t0 = Instant::now();
        let first = zerion_result_or_cached(
            &mut cache,
            "0x7521EDA00E2CE05AC4A9D8353D096CCB970D5188",
            Ok((vec![zerion_position("zerion:gmx:0", 8.37)], 0.0)),
            t0,
        )
        .unwrap();
        assert_eq!(first.0[0].balance_usd, 8.37);

        // Same wallet, lower-case address, Zerion now rate-limited.
        let reused = zerion_result_or_cached(
            &mut cache,
            "0x7521eda00e2ce05ac4a9d8353d096ccb970d5188",
            Err(RATE_LIMITED.to_string()),
            t0 + Duration::from_secs(120),
        )
        .unwrap();
        assert_eq!(reused.0.len(), 1);
        assert_eq!(reused.0[0].id, "zerion:gmx:0");
        assert_eq!(reused.0[0].balance_usd, 8.37);
    }

    #[test]
    fn zerion_error_without_recent_result_still_fails() {
        let mut cache = ZerionCache::new();
        let t0 = Instant::now();
        let none = zerion_result_or_cached(&mut cache, "0xabc", Err(RATE_LIMITED.to_string()), t0);
        assert_eq!(none.unwrap_err(), RATE_LIMITED);

        zerion_result_or_cached(
            &mut cache,
            "0xabc",
            Ok((vec![zerion_position("zerion:gmx:0", 5.0)], 0.0)),
            t0,
        )
        .unwrap();
        let stale = zerion_result_or_cached(
            &mut cache,
            "0xabc",
            Err(RATE_LIMITED.to_string()),
            t0 + ZERION_REUSE_MAX_AGE + Duration::from_secs(1),
        );
        assert_eq!(stale.unwrap_err(), RATE_LIMITED);
    }

    #[test]
    fn newer_zerion_result_replaces_the_cached_one() {
        let mut cache = ZerionCache::new();
        let t0 = Instant::now();
        zerion_result_or_cached(&mut cache, "0xabc", Ok((vec![zerion_position("a", 1.0)], 0.0)), t0)
            .unwrap();
        zerion_result_or_cached(
            &mut cache,
            "0xabc",
            Ok((vec![zerion_position("b", 2.0), zerion_position("c", 3.0)], 0.0)),
            t0 + Duration::from_secs(10),
        )
        .unwrap();
        let reused = zerion_result_or_cached(
            &mut cache,
            "0xabc",
            Err(RATE_LIMITED.to_string()),
            t0 + Duration::from_secs(20),
        )
        .unwrap();
        let ids: Vec<&str> = reused.0.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["b", "c"]);
    }

    #[test]
    fn builds_xstake_position_from_staked_and_reward_amounts() {
        let mut prices = HashMap::new();
        prices.insert("tether".to_string(), 1.0);
        prices.insert(XWAN_PRICE_ID.to_string(), 0.25);
        let pool = XStakeFarmingPool {
            key: "wanUSDT",
            contract: "0x812C7F30a67598e32a351a64495F8426AB83Ff20",
            staking_symbol: "wanUSDT",
            staking_decimals: 6,
            staking_price_id: "tether",
            reward_symbol: "xWAN",
            reward_decimals: 18,
            reward_price_id: XWAN_PRICE_ID,
            reward_addr: "0x2eA407Aa69be7367BF231E76B51fab9eC436766c",
        };

        let position =
            xstake_position_from_amounts(&pool, 12_500_000.0, 2_000_000_000_000_000_000.0, &prices);

        assert_eq!(position.app_name, "XStake Farming");
        assert_eq!(position.network_name, "Wanchain");
        assert_eq!(position.label, "wanUSDT farming");
        assert_eq!(position.group_label, Some("Earn xWAN".to_string()));
        assert_eq!(
            position.symbols,
            vec!["wanUSDT".to_string(), "xWAN".to_string()]
        );
        assert_eq!(position.tokens[0].balance, Some("12.5".to_string()));
        assert_eq!(position.tokens[1].balance, Some("2".to_string()));
        assert_eq!(position.balance_usd, 13.0);
    }

    #[test]
    fn builds_xstake_position_without_prices() {
        let prices = HashMap::new();
        let pool = XStakeFarmingPool {
            key: "wanUSDT",
            contract: "0x812C7F30a67598e32a351a64495F8426AB83Ff20",
            staking_symbol: "wanUSDT",
            staking_decimals: 6,
            staking_price_id: "tether",
            reward_symbol: "xWAN",
            reward_decimals: 18,
            reward_price_id: XWAN_PRICE_ID,
            reward_addr: "0x2eA407Aa69be7367BF231E76B51fab9eC436766c",
        };

        let position =
            xstake_position_from_amounts(&pool, 12_500_000.0, 2_000_000_000_000_000_000.0, &prices);

        assert_eq!(position.balance_usd, 0.0);
        assert_eq!(position.tokens[0].balance, Some("12.5".to_string()));
        assert_eq!(position.tokens[0].balance_usd, None);
        assert_eq!(position.tokens[1].balance, Some("2".to_string()));
        assert_eq!(position.tokens[1].balance_usd, None);
    }

    #[test]
    fn price_oracle_reads_cached_prices_by_id() {
        let mut cache = PriceOracleCache {
            updated_at_ms: unix_time_ms(),
            prices: HashMap::new(),
        };
        cache.prices.insert(
            "tether".to_string(),
            PriceOracleEntry {
                usd: 1.0,
                change_24h: 0.01,
            },
        );
        cache.prices.insert(
            "ethereum".to_string(),
            PriceOracleEntry {
                usd: 3200.0,
                change_24h: -0.5,
            },
        );

        assert!(price_cache_has_all(&cache, &["tether", "ethereum"]));
        assert!(!price_cache_has_all(&cache, &["tether", "bitcoin"]));
        let prices = price_cache_entries(&cache, &["tether", "bitcoin"]);
        assert_eq!(prices.len(), 1);
        assert_eq!(prices["tether"].usd, 1.0);
    }

    #[test]
    #[ignore = "hits Wanchain RPC and CoinGecko"]
    fn xstake_live_fetches_known_address_positions() {
        let positions = tauri::async_runtime::block_on(fetch_xstake_farming_positions(
            PriceOracleStore::in_memory(),
            "0x7521eda00e2ce05ac4a9d8353d096ccb970d5188".to_string(),
        ))
        .unwrap();

        println!("positions={positions:#?}");
        assert!(
            !positions.is_empty(),
            "expected XStake Farming positions for the known address"
        );
        assert!(positions.iter().all(|p| p.app_name == "XStake Farming"));
        assert!(positions.iter().any(|p| !p.tokens.is_empty()));
        assert!(positions.iter().flat_map(|p| &p.tokens).any(|token| token
            .balance
            .as_deref()
            .is_some_and(|balance| balance != "0")));
    }

    /// Drives the whole supplement against the live APIs: Zerion says which chains
    /// the address is active on, DeBank's lists resolve the Uniswap v4 protocol
    /// ids, and `/v1/user/protocol` returns the liquidity Zerion's own positions
    /// endpoint never reports. Also checks the two things that keep it cheap —
    /// the id lookups landing on disk, and the probe cache answering the next
    /// call. Spends DeBank units, so it stays out of the default run.
    #[test]
    #[ignore = "hits the live Zerion and DeBank APIs and spends DeBank units"]
    fn uniswap_v4_live_supplements_a_known_address() {
        let zerion_key = zerion_api_key().expect("ZERION_APIKEY must be configured");
        let debank_key = debank_api_key().expect("DEBANK_APIKEY must be configured");
        let address = "0x7521eda00e2ce05ac4a9d8353d096ccb970d5188";
        let path = std::env::temp_dir().join(format!("autodesktop-debank-{}.json", unix_time_ms()));
        let registry = DebankRegistry::at(path.clone());

        let started = std::time::Instant::now();
        let positions = tauri::async_runtime::block_on(fetch_uniswap_v4_positions(
            &registry,
            &zerion_key,
            &debank_key,
            address,
            true,
        ))
        .unwrap();
        let cold = started.elapsed();

        println!("cold={cold:?} positions={positions:#?}");
        assert!(
            !positions.is_empty(),
            "expected Uniswap v4 liquidity for the known address"
        );
        assert!(positions
            .iter()
            .all(|p| p.app_name == UNISWAP_V4_PROTOCOL_NAME));
        assert!(positions.iter().all(|p| p.balance_usd > 0.0));
        // Relabelled into the Zerion vocabulary: hex chain id, display name.
        assert!(positions.iter().all(|p| p.chain_id.starts_with("0x")));
        assert!(positions.iter().any(|p| p.network_name == "Ethereum"));
        assert!(positions.iter().any(|p| !p.tokens.is_empty()));
        assert!(
            cold < UNISWAP_V4_TIMEOUT,
            "a cold run must finish inside its own budget, took {cold:?}"
        );

        // The id lookups reached disk, so a restart doesn't re-buy them.
        let saved: DebankRegistryCache =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved.chains.get("1").map(String::as_str), Some("eth"));
        assert_eq!(
            saved.uniswap_v4["eth"].protocol_id.as_deref(),
            Some("uniswap4")
        );
        assert!(saved.chains_updated_at_ms > 0);

        // And an unforced repeat is answered from the probe cache, not re-bought.
        let started = std::time::Instant::now();
        let again = tauri::async_runtime::block_on(fetch_uniswap_v4_positions(
            &registry,
            &zerion_key,
            &debank_key,
            address,
            false,
        ))
        .unwrap();
        let cached = started.elapsed();
        println!("cached={cached:?}");
        assert_eq!(again.len(), positions.len());
        assert_eq!(again[0].balance_usd, positions[0].balance_usd);
        assert!(
            cached < Duration::from_secs(1),
            "a cached repeat must not touch the network, took {cached:?}"
        );
        std::fs::remove_file(&path).ok();

        // And Zerion alone genuinely misses it — the premise of the whole thing.
        let (zerion_positions, _) =
            tauri::async_runtime::block_on(fetch_zerion_defi_positions(address)).unwrap();
        assert!(
            !zerion_positions
                .iter()
                .any(|p| p.app_name.eq_ignore_ascii_case(UNISWAP_V4_PROTOCOL_NAME)),
            "Zerion now reports Uniswap v4 itself — the supplement's dedupe is what keeps this from double-counting"
        );
    }

    #[test]
    fn encodes_multicall3_aggregate3_calls() {
        let calls = vec![Multicall3Call {
            target: "0x812C7F30a67598e32a351a64495F8426AB83Ff20".to_string(),
            call_data: call_data(
                "userInfo(address)",
                &["0x0000000000000000000000000000000000000001"],
            ),
        }];

        let data = encode_multicall3_aggregate3(&calls).unwrap();

        assert!(data.starts_with("0x82ad56cb"));
        assert!(data.contains("000000000000000000000000812c7f30a67598e32a351a64495f8426ab83ff20"));
        assert!(data.contains("0000000000000000000000000000000000000000000000000000000000000001"));
        assert!(data.contains(
            &call_data(
                "userInfo(address)",
                &["0x0000000000000000000000000000000000000001"]
            )[2..]
        ));
    }

    #[test]
    fn decodes_multicall3_aggregate3_results() {
        let success_data = format!("{}{}", encode_usize_word(42), encode_usize_word(99));
        let tuple1 = encode_mock_multicall_result(true, &success_data);
        let tuple2 = encode_mock_multicall_result(false, "");
        let tuple1_offset = 2 * 32;
        let tuple2_offset = tuple1_offset + tuple1.len() / 2;
        let raw = format!(
            "0x{}{}{}{}{}{}",
            encode_usize_word(32),
            encode_usize_word(2),
            encode_usize_word(tuple1_offset),
            encode_usize_word(tuple2_offset),
            tuple1,
            tuple2
        );

        let results = decode_multicall3_aggregate3(&raw, 2).unwrap();

        assert_eq!(results[0], Some(format!("0x{success_data}")));
        assert_eq!(
            first_u256_word_as_f64(results[0].as_deref().unwrap()).unwrap(),
            42.0
        );
        assert_eq!(results[1], None);
    }

    #[test]
    fn parses_erc20_transfer_activity() {
        let data = concat!(
            "0xa9059cbb",
            "00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8",
            "000000000000000000000000000000000000000000000000000000000012d687"
        );
        let parsed = parse_erc20_transfer(data).unwrap();
        assert_eq!(parsed.0, "0x70997970c51812dc3a010c7d01b50e0d17dc79c8");
        assert_eq!(parsed.1, "0x12d687");
        assert!(parse_erc20_transfer("0x095ea7b3").is_none());
    }

    fn encode_mock_multicall_result(success: bool, return_data: &str) -> String {
        let mut tuple = String::new();
        tuple.push_str(&encode_bool_word(success));
        tuple.push_str(&encode_usize_word(64));
        tuple.push_str(&encode_usize_word(return_data.len() / 2));
        tuple.push_str(return_data);
        tuple.push_str(&"0".repeat(padded_hex_len(return_data.len()) - return_data.len()));
        tuple
    }

    #[test]
    fn switch_known_chain_yields_directive_unknown_errors() {
        let out = handle_wallet_method(
            "wallet_switchEthereumChain",
            &[json!({ "chainId": "0xa4b1" })],
            "0x1",
            None,
        )
        .unwrap();
        assert_eq!(out, WalletOutcome::SwitchChain("0xa4b1".to_string()));

        // unknown target chain is rejected (EIP-3326 4902 territory)
        assert!(handle_wallet_method(
            "wallet_switchEthereumChain",
            &[json!({ "chainId": "0xdead" })],
            "0x1",
            None,
        )
        .is_err());

        // missing chainId param is a hard error, not a silent default
        assert!(handle_wallet_method("wallet_switchEthereumChain", &[], "0x1", None).is_err());
    }

    #[test]
    fn add_ethereum_chain_switches_known_and_adds_new() {
        // A chain already in the registry → just switch (keep OUR rpc, ignore dApp's).
        let known = handle_wallet_method(
            "wallet_addEthereumChain",
            &[json!({ "chainId": "0xa86a", "rpcUrls": ["https://evil.example/rpc"] })],
            "0x1",
            None,
        )
        .unwrap();
        assert_eq!(known, WalletOutcome::SwitchChain("0xa86a".to_string()));

        // A brand-new chain → AddChain built from the EIP-3085 params.
        let added = handle_wallet_method(
            "wallet_addEthereumChain",
            &[json!({
                "chainId": "0x440b",
                "chainName": "Local Test Net",
                "rpcUrls": ["https://rpc.localtest.example"],
                "nativeCurrency": { "symbol": "LTN", "decimals": 18 }
            })],
            "0x1",
            None,
        )
        .unwrap();
        match added {
            WalletOutcome::AddChain(c) => {
                assert_eq!(c.id, "0x440b");
                assert_eq!(c.name, "Local Test Net");
                assert_eq!(c.symbol, "LTN");
                assert_eq!(c.rpc, "https://rpc.localtest.example");
                assert!(!c.builtin);
            }
            other => panic!("expected AddChain, got {other:?}"),
        }

        // A new chain with a non-http(s) rpc is rejected (no malicious scheme).
        assert!(handle_wallet_method(
            "wallet_addEthereumChain",
            &[json!({ "chainId": "0x440c", "chainName": "X", "rpcUrls": ["ftp://nope"] })],
            "0x1",
            None,
        )
        .is_err());
    }
}

// ---------------------------------------------------------------------------
// In-process E2E tests.
//
// These exercise the REAL IPC pipeline — `invoke('wallet_request', …)` →
// `wallet_request(webview, …)` → `handle_rpc` → response — via Tauri's mock
// runtime (`tauri::test`), the only automatable E2E path on macOS. Unlike the
// pure unit tests above, the command's `tauri::Webview` arg and the async path
// are real here.
//
// Only `e2e_pipeline_offline` runs by default (deterministic, no network). The
// live network-forward test is `#[ignore]`d — run it with:
//     cargo test -- --ignored
// Both touch the shared `current_chain()` state, but only one global-touching
// test runs in each pass (default vs --ignored), so there is no race.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod e2e {
    use super::*;
    use serde_json::json;
    use tauri::ipc::{CallbackFn, InvokeBody};
    use tauri::test::{get_ipc_response, mock_builder, MockRuntime, INVOKE_KEY};
    use tauri::webview::InvokeRequest;
    use tauri::{WebviewWindow, WebviewWindowBuilder};

    /// Anvil/Hardhat's well-known dev mnemonic — its m/44'/60'/0'/0/0 account is
    /// SPIKE_ACCOUNT (the publicly-known Anvil #0). NOT a real secret. The
    /// `wallet_guard` unlocks the test vault with it so account/signing tests sign
    /// with a deterministic, recoverable key.
    const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";

    /// Build + leak one mock app with all commands registered. Uses the REAL app
    /// context (generate_context!) so the baked-in capabilities/permissions apply.
    /// A plain `cargo test` is a debug build, so Tauri treats it as dev (devUrl, no
    /// dist needed) — the same reason run() compiles. mock_context()'s empty ACL
    /// would reject every command with "Plugin not found".
    fn build_app() -> &'static tauri::App<MockRuntime> {
        let app = mock_builder()
            .plugin(tauri_plugin_clipboard_manager::init())
            .invoke_handler(tauri::generate_handler![
                wallet_request,
                dapp_dialog,
                resolve_dapp_dialog,
                approve_request,
                reject_request,
                get_pending_requests,
                open_dapp,
                set_dapp_bounds,
                sync_toast_overlay,
                sync_menu_overlay,
                reload_dapp,
                navigate_dapp,
                go_back_dapp,
                hide_dapp,
                show_dapp,
                close_dapp,
                open_external_url,
                node_rpc,
                inspect_safe,
                safe_pending_transactions,
                safe_confirm_transaction,
                wallet_send,
                relay_chains,
                relay_quote,
                relay_status,
                okx_connection_status,
                okx_save_credentials,
                okx_delete_credentials,
                okx_get_assets,
                okx_get_dcd_orders,
            okx_save_dcd_csv,
                set_active_chain,
                get_active_chain,
                get_chains,
                add_chain,
                update_chain,
                remove_chain,
                vault_status,
                create_vault,
                import_vault,
                import_private_key,
                export_wallet_secret,
                unlock_vault,
                change_password,
                unlock_vault_with_touch_id,
                touch_id_status,
                enable_touch_id,
                disable_touch_id,
                lock_vault,
                reset_vault,
                ledger_addresses,
                connect_ledger,
                select_account,
                expose_dapp_account,
                add_account,
                rename_wallet,
                delete_wallet,
                get_connected_sites,
                disconnect_connected_site,
                note_user_activity,
                get_auto_lock_minutes,
                set_auto_lock_minutes,
                set_app_menu_language
            ])
            .build(build_context())
            .expect("failed to build mock app");
        Box::leak(Box::new(app))
    }

    fn webview(
        app: &'static tauri::App<MockRuntime>,
        label: &str,
        url: tauri::WebviewUrl,
    ) -> WebviewWindow<MockRuntime> {
        WebviewWindowBuilder::new(app, label, url)
            .build()
            .expect("failed to build mock webview")
    }

    /// A *dapp* tab webview on a remote URL — the security-relevant path: its grant
    /// comes from dapp.json (webviews:["dapp-*"] + remote urls + allow-wallet-request).
    fn dapp_webview(app: &'static tauri::App<MockRuntime>) -> WebviewWindow<MockRuntime> {
        webview(
            app,
            "dapp-0",
            tauri::WebviewUrl::External("https://metamask.github.io/test-dapp/".parse().unwrap()),
        )
    }

    /// The trusted *approval* webview (local) — granted the approve/reject/list
    /// commands by capabilities/approval.json.
    fn approval_webview(app: &'static tauri::App<MockRuntime>) -> WebviewWindow<MockRuntime> {
        webview(
            app,
            "approval",
            tauri::WebviewUrl::App("index.html?view=approval".into()),
        )
    }

    /// Drive any command through the real IPC pipeline from a given webview.
    /// Returns `Ok(result)` or `Err(error_value)` for a rejected promise.
    fn invoke(wv: &WebviewWindow<MockRuntime>, cmd: &str, args: Value) -> Result<Value, Value> {
        // The IPC url must reflect the calling page: the ACL distinguishes local
        // (approval webview) from remote (dapp webview). Deriving it from the
        // webview makes both capability scopes resolve correctly.
        let url = wv.url().expect("mock webview has a url");
        get_ipc_response(
            wv,
            InvokeRequest {
                cmd: cmd.into(),
                callback: CallbackFn(0),
                error: CallbackFn(1),
                url,
                body: InvokeBody::Json(args),
                headers: Default::default(),
                invoke_key: INVOKE_KEY.to_string(),
            },
        )
        .map(|b| b.deserialize::<Value>().unwrap())
    }

    /// Convenience for the dApp bridge command specifically.
    fn call(wv: &WebviewWindow<MockRuntime>, method: &str, params: Value) -> Result<Value, Value> {
        invoke(
            wv,
            "wallet_request",
            json!({ "method": method, "params": params }),
        )
    }

    #[test]
    fn e2e_relay_commands_are_shell_only() {
        let app = build_app();
        let shell = webview(app, "shell", tauri::WebviewUrl::App("index.html".into()));
        // Invalid inputs prove dispatch reaches the registered shell command
        // without requiring a key or sending an HTTP request.
        assert_eq!(
            invoke(&shell, "relay_quote", json!({"body": []})).unwrap_err(),
            json!("Relay quote body must be an object")
        );
        assert_eq!(
            invoke(&shell, "relay_status", json!({"requestId": ""})).unwrap_err(),
            json!("Relay request id is required")
        );
        let dapp = dapp_webview(app);
        for (command, args) in [
            ("relay_chains", json!({})),
            ("relay_quote", json!({"body": {}})),
            ("relay_status", json!({"requestId": "test"})),
        ] {
            let error = invoke(&dapp, command, args).unwrap_err();
            assert!(error.as_str().unwrap().contains("not allowed"), "{command}: {error}");
        }
        let approval = approval_webview(app);
        let error = invoke(&approval, "relay_quote", json!({"body": {}})).unwrap_err();
        assert!(error.as_str().unwrap().contains("not allowed"), "{error}");
    }

    #[test]
    fn e2e_change_password_is_shell_only() {
        let app = build_app();
        for view in [dapp_webview(app), approval_webview(app)] {
            let error = invoke(&view, "change_password", json!({
                "currentPassword": "old-password", "newPassword": "new-password"
            })).unwrap_err();
            assert!(error.as_str().unwrap().contains("not allowed"), "{error}");
        }
    }

    /// Serialize every test that touches process-global wallet state and reset to a
    /// known baseline: pending registry cleared, chain = Ethereum, and the vault
    /// unlocked with the Anvil dev mnemonic (2 derived accounts). Returning the guard
    /// keeps these tests from racing on the shared statics.
    fn wallet_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        let g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        pending().lock().unwrap().clear();
        *active_dapp_label().lock().unwrap() = None;
        *exposed_account_state().lock().unwrap() = None;
        *current_chain().lock().unwrap() = "0x1".into();
        // dapp-0's origin counts as connected; other origins start disconnected.
        *connected_sites().lock().unwrap() =
            HashSet::from(["https://metamask.github.io".to_string()]);
        connecting_sites().lock().unwrap().clear();
        super::install_unlocked_vault(TEST_MNEMONIC, 2).expect("unlock test vault");
        g
    }

    /// Poll until a request is registered, returning its id.
    fn wait_for_pending_id() -> String {
        for _ in 0..300 {
            if let Some(id) = pending().lock().unwrap().keys().next().cloned() {
                return id;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("no pending approval request appeared within 3s");
    }

    /// Recover the signer address from an EIP-191 personal_sign signature.
    fn recover_personal_sign(message: &[u8], sig65: &[u8]) -> String {
        let mut preimage = format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
        preimage.extend_from_slice(message);
        let digest = Keccak256::digest(&preimage);
        let signature = k256::ecdsa::Signature::from_slice(&sig65[..64]).expect("valid sig");
        let recid = k256::ecdsa::RecoveryId::from_byte(sig65[64] - 27).expect("valid recid");
        let vk = VerifyingKey::recover_from_prehash(&digest, &signature, recid).expect("recover");
        address_from_verifying_key(&vk)
    }

    /// A broadcast the node never acknowledged still yields a hash, and it is the
    /// one computed from the signed bytes. Answering with an error instead would
    /// tell a dApp the request failed, and a dApp that offers Retry on a
    /// transaction that actually landed sends the money a second time.
    #[test]
    fn an_unacknowledged_broadcast_still_yields_the_signed_hash() {
        let _guard = wallet_guard();
        let chain = super::tests::stalled_node_chain();
        let chain_id = chain.id.clone();
        // finalize_tx resolves the chain from the registry, so register the silent
        // one for the length of the test and put the list back afterwards.
        let restore = chains_state().lock().unwrap().clone();
        chains_state().lock().unwrap().push(chain);
        // finalize_tx signs and broadcasts for real. Prove the registry lookup
        // lands on the loopback stub BEFORE letting it near a node — a colliding
        // id once sent a signed transaction to live Ethereum from CI.
        let resolved = find_chain(&chain_id).map(|c| c.rpc);
        if resolved.as_deref().map(|rpc| rpc.contains("127.0.0.1")) != Some(true) {
            *chains_state().lock().unwrap() = restore;
            panic!("test chain must resolve to the loopback stub, got {resolved:?}");
        }

        let prepared = PreparedTx {
            chain_id: chain_id.clone(),
            chain_name: "Stalled".into(),
            symbol: "ETH".into(),
            from: SPIKE_ACCOUNT.into(),
            to: SPIKE_ACCOUNT.into(),
            value: "0x1".into(),
            data: "0x".into(),
            gas: "0x5208".into(),
            nonce: "0x0".into(),
            max_priority_fee_per_gas: "0x1".into(),
            max_fee_per_gas: "0x3b9aca00".into(),
        };
        let sent = tauri::async_runtime::block_on(finalize_tx_within(
            &prepared,
            Duration::from_millis(300),
        ));
        *chains_state().lock().unwrap() = restore;

        let sent = sent.expect("an unreachable node must not fail the call outright");
        assert!(
            sent.broadcast_error.is_some(),
            "a silent node leaves the broadcast unconfirmed"
        );
        // The locally computed hash is the canonical one: keccak of the signed
        // bytes is what the node would have echoed had it answered.
        assert!(
            sent.hash.starts_with("0x") && sent.hash.len() == 66,
            "must report a real tx hash, got {}",
            sent.hash
        );
    }

    /// The whole pre-approval preparation is bounded, so the Send button can never
    /// sit on "confirm in window" with no window. This lives in `e2e` because it
    /// needs an UNLOCKED vault: with a locked one `prepare_tx` returns "wallet is
    /// locked" in microseconds and never reaches the node, which is how the first
    /// version of this test passed without exercising a single timeout.
    #[test]
    fn preparing_a_transaction_gives_up_on_a_silent_node() {
        let _guard = wallet_guard(); // serialises + unlocks the shared vault
        let chain = super::tests::stalled_node_chain();
        let started = std::time::Instant::now();
        let out = tauri::async_runtime::block_on(prepare_tx_within(
            &chain,
            &json!({ "from": SPIKE_ACCOUNT, "to": SPIKE_ACCOUNT, "value": "0x1" }),
            Duration::from_millis(600),
        ));
        let err = out
            .err()
            .expect("preparation against a silent node must fail");
        // Naming the reason is the point: any other error means the call never got
        // as far as the node and the timeout was never tested.
        assert!(
            err.contains("did not answer within"),
            "must fail on the prepare timeout, got: {err}"
        );
        assert!(
            started.elapsed() >= Duration::from_millis(600),
            "returned in {:?} — it cannot have waited on the node",
            started.elapsed()
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "gave up only after {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn e2e_pipeline_offline() {
        let _guard = wallet_guard(); // unlocked vault + chain=0x1, serialized
        let app = build_app();
        let wv = dapp_webview(app);
        activate_dapp_tab(app, "dapp-0"); // only the active tab may switch chains

        // Wallet-routed reads come back through the full invoke→command→handler path.
        // eth_accounts now returns the UNLOCKED vault's active account (Anvil #0).
        assert_eq!(
            call(&wv, "eth_accounts", json!([])).unwrap(),
            json!([SPIKE_ACCOUNT])
        );
        assert_eq!(call(&wv, "eth_chainId", json!([])).unwrap(), json!("0x1"));
        assert_eq!(call(&wv, "net_version", json!([])).unwrap(), json!("1"));

        // A still-unimplemented signing method (eth_signTypedData_v3) is rejected
        // up-front (no approval window, returns immediately). personal_sign,
        // eth_sendTransaction and eth_signTypedData_v4 (which DO prompt) are covered
        // separately.
        let err = call(&wv, "eth_signTypedData_v3", json!([SPIKE_ACCOUNT, "{}"])).unwrap_err();
        assert!(
            err.as_str().unwrap_or_default().contains("not implemented"),
            "expected not-implemented error, got: {err}"
        );

        // Switching chain is reflected by a subsequent eth_chainId — proving the
        // command actually mutated the shared current-chain state.
        assert_eq!(
            call(
                &wv,
                "wallet_switchEthereumChain",
                json!([{ "chainId": "0x2105" }])
            )
            .unwrap(),
            Value::Null
        );
        assert_eq!(
            call(&wv, "eth_chainId", json!([])).unwrap(),
            json!("0x2105")
        );
        assert_eq!(call(&wv, "net_version", json!([])).unwrap(), json!("8453"));

        // Unknown chain is rejected, current chain unchanged.
        assert!(call(
            &wv,
            "wallet_switchEthereumChain",
            json!([{ "chainId": "0xbadbad" }])
        )
        .is_err());
        assert_eq!(
            call(&wv, "eth_chainId", json!([])).unwrap(),
            json!("0x2105")
        );
    }

    /// A LOCKED wallet exposes no account and refuses to sign UP-FRONT — no approval
    /// window opens, so the call returns immediately. Guarded so it can lock the
    /// shared vault without racing other state-touching tests.
    #[test]
    fn e2e_locked_wallet_has_no_account_and_refuses_signing() {
        let _guard = wallet_guard();
        let app = build_app();
        super::lock_vault(app.handle().clone()); // drop all decrypted keys from memory
        let wv = dapp_webview(app);

        // No account is exposed to dApps when locked.
        assert_eq!(call(&wv, "eth_accounts", json!([])).unwrap(), json!([]));
        assert_eq!(call(&wv, "eth_coinbase", json!([])).unwrap(), Value::Null);

        // personal_sign is rejected immediately with a "locked" error — BEFORE any
        // approval, so no worker thread / approval webview is needed here.
        let err = call(&wv, "personal_sign", json!(["0x48656c6c6f", SPIKE_ACCOUNT])).unwrap_err();
        assert!(
            err.as_str().unwrap_or_default().contains("locked"),
            "expected a locked error, got: {err}"
        );
    }

    /// An imported single private key behaves as a one-account wallet that exposes
    /// exactly that address — and refuses `add_account` loudly (no mnemonic to walk,
    /// so deriving a "next" account would be meaningless). Pure in-memory: never
    /// touches the on-disk keystore (which resolves to the real user dir).
    #[test]
    fn e2e_privkey_vault_is_single_account_and_refuses_add() {
        let _guard = wallet_guard();
        // Anvil #0's well-known key → Anvil #0's address (SPIKE_ACCOUNT). NOT a secret.
        super::install_privkey_vault(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        )
        .expect("install privkey vault");

        let app = build_app();
        let wv = dapp_webview(app);
        assert_eq!(
            call(&wv, "eth_accounts", json!([])).unwrap(),
            json!([SPIKE_ACCOUNT])
        );

        // add_account returns its refusal BEFORE any keystore I/O, so this stays
        // disk-free. The error must name the real cause, not a silent no-op.
        // (install_privkey_vault tags the wallet id "w-privkey".)
        let err = super::add_account(app.handle().clone(), "w-privkey".to_string()).unwrap_err();
        assert!(
            err.contains("can't derive"),
            "expected a 'can't derive more accounts' refusal, got: {err}"
        );
    }

    /// Several independent wallets coexist in one store: adding a second wallet makes
    /// its account active (dApps see it), the ACTIVE signing key follows the selected
    /// ADDRESS across wallets, and deleting the active wallet moves the active account
    /// back to a surviving wallet. Pure in-memory (delete's keystore file never
    /// exists, so disk stays untouched). Deleting the core dispatch breaks this.
    #[test]
    fn e2e_multi_wallet_active_follows_address_across_wallets() {
        let _guard = wallet_guard(); // installs HD wallet "w-hd" (2 Anvil accounts), active #0
        let app = build_app();

        // Add a second, independent wallet: Anvil #3's well-known key as a privkey
        // wallet (NOT a secret — a public dev key, used here as an oracle).
        let key = super::vault::parse_private_key(
            "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
        )
        .unwrap();
        let addr3 = super::address_from_verifying_key(key.verifying_key());
        super::store_push_wallet(
            super::UnlockedWallet {
                id: "w-2".to_string(),
                label: "Wallet 2".to_string(),
                secret: super::VaultSecret::PrivateKey,
                accounts: vec![super::UnlockedAccount {
                    index: 0,
                    address: addr3.clone(),
                    signer: super::Signer::Local(key),
                }],
            },
            None,
        );

        // The new wallet's account is active, and dApps see exactly that address.
        assert_eq!(
            super::active_account_address().as_deref(),
            Some(addr3.as_str())
        );
        let wv = dapp_webview(app);
        assert_eq!(
            call(&wv, "eth_accounts", json!([])).unwrap(),
            json!([addr3])
        );
        // The active signing key recovers to Anvil #3 (the second wallet's key).
        let active_addr =
            super::with_active_key(|k| super::address_from_verifying_key(k.verifying_key()))
                .unwrap();
        assert_eq!(active_addr, addr3);

        // Switch back to the FIRST wallet's account (Anvil #0) by address — the active
        // key must now be Anvil #0's, proving selection spans wallets.
        super::select_account(app.handle().clone(), SPIKE_ACCOUNT.to_string()).unwrap();
        let active_addr =
            super::with_active_key(|k| super::address_from_verifying_key(k.verifying_key()))
                .unwrap();
        assert_eq!(active_addr, SPIKE_ACCOUNT);

        // Deleting the second wallet (its keystore file doesn't exist → disk no-op)
        // leaves the first wallet's accounts; active stays a valid, surviving account.
        super::delete_wallet(app.handle().clone(), "w-2".to_string()).unwrap();
        let active = super::active_account_address().expect("an account remains active");
        assert_eq!(active, SPIKE_ACCOUNT);
        assert_eq!(
            call(&wv, "eth_accounts", json!([])).unwrap(),
            json!([SPIKE_ACCOUNT])
        );
    }

    /// Watch-only addresses can be exposed to dApps for read-only portfolio views
    /// (DeBank, explorers, dashboards), but they never become the active signer.
    #[test]
    fn e2e_watch_only_account_is_visible_to_dapps_without_signing_key() {
        let _guard = wallet_guard();
        let app = build_app();
        let shell = shell_webview(app);
        let wv = dapp_webview(app);
        let watch = "0x2222222222222222222222222222222222222222";

        assert_eq!(
            call(&wv, "eth_accounts", json!([])).unwrap(),
            json!([SPIKE_ACCOUNT])
        );
        invoke(&shell, "expose_dapp_account", json!({ "address": watch }))
            .expect("shell can expose a watch-only address");

        assert_eq!(
            call(&wv, "eth_accounts", json!([])).unwrap(),
            json!([watch])
        );
        assert_eq!(call(&wv, "eth_coinbase", json!([])).unwrap(), json!(watch));

        let active_addr =
            super::with_active_key(|k| super::address_from_verifying_key(k.verifying_key()))
                .unwrap();
        assert_eq!(active_addr, SPIKE_ACCOUNT);

        invoke(
            &shell,
            "select_account",
            json!({ "address": SPIKE_ACCOUNT }),
        )
        .expect("shell can switch back to a signer");
        assert_eq!(
            call(&wv, "eth_accounts", json!([])).unwrap(),
            json!([SPIKE_ACCOUNT])
        );
        invoke(&shell, "expose_dapp_account", json!({ "address": watch }))
            .expect("shell can expose the watch-only address again");

        let err = call(&wv, "personal_sign", json!(["0x48656c6c6f", watch])).unwrap_err();
        assert!(
            err.as_str()
                .unwrap_or_default()
                .contains("cannot sign direct EIP-1193"),
            "expected unlocked watch-only signing to be blocked, got: {err}"
        );

        super::lock_vault(app.handle().clone());
        assert_eq!(
            call(&wv, "eth_accounts", json!([])).unwrap(),
            json!([watch])
        );
        let err = call(&wv, "personal_sign", json!(["0x48656c6c6f", watch])).unwrap_err();
        assert!(
            err.as_str().unwrap_or_default().contains("locked"),
            "expected signing to remain unavailable, got: {err}"
        );
    }

    /// A Ledger account exposes its address to dApps WITHOUT any in-process key, and
    /// the software-signing path refuses it (signing must go to the device). Pure
    /// in-memory: no device, no disk. Asserts the account is wired but unsignable
    /// locally — proving the dispatch, not faking a hardware signature.
    #[test]
    fn e2e_ledger_vault_exposes_address_but_has_no_local_key() {
        let _guard = wallet_guard();
        let ledger_addr = "0x1111111111111111111111111111111111111111";
        super::install_ledger_vault("m/44'/60'/0'/0/0", ledger_addr).expect("install ledger vault");

        let wv = dapp_webview(build_app());
        // The device address is exposed to dApps exactly like a software account.
        assert_eq!(
            call(&wv, "eth_accounts", json!([])).unwrap(),
            json!([ledger_addr])
        );

        // There is NO in-process key: the software-signing path must refuse loudly
        // (the real signing path routes to the device, which needs hardware).
        let err = super::with_active_key(|_| ()).unwrap_err();
        assert!(
            err.contains("Ledger"),
            "expected a 'sign on the device' refusal, got: {err}"
        );

        // And the active-signer snapshot reports the Ledger path for the device path.
        match super::active_signer_kind().unwrap() {
            super::ActiveKind::Ledger(path) => assert_eq!(path, "m/44'/60'/0'/0/0"),
            super::ActiveKind::Local => panic!("expected a Ledger active signer"),
        }
    }

    #[test]
    #[ignore = "hits a live public RPC node; run with `cargo test -- --ignored`"]
    fn e2e_forward_live() {
        let wv = dapp_webview(build_app());
        *current_chain().lock().unwrap() = "0x1".into();

        // eth_blockNumber is forwarded to Ethereum mainnet → a plausible block.
        let bn = call(&wv, "eth_blockNumber", json!([])).unwrap();
        let s = bn.as_str().expect("blockNumber should be a hex string");
        let n = u64::from_str_radix(s.trim_start_matches("0x"), 16).expect("hex");
        assert!(n > 19_000_000, "mainnet block implausibly low: {n} ({s})");

        // eth_getBalance forwarded → a hex quantity.
        let bal = call(
            &wv,
            "eth_getBalance",
            json!(["0x0000000000000000000000000000000000000000", "latest"]),
        )
        .unwrap();
        assert!(
            bal.as_str().unwrap().starts_with("0x"),
            "balance not hex: {bal}"
        );

        // Switch to Base, then the SAME method forwards to a DIFFERENT node.
        call(
            &wv,
            "wallet_switchEthereumChain",
            json!([{ "chainId": "0x2105" }]),
        )
        .unwrap();
        let base_bn = call(&wv, "eth_blockNumber", json!([])).unwrap();
        let bs = base_bn.as_str().expect("hex string");
        let bnum = u64::from_str_radix(bs.trim_start_matches("0x"), 16).expect("hex");
        assert!(
            bnum > 10_000_000,
            "base block implausibly low: {bnum} ({bs})"
        );

        *current_chain().lock().unwrap() = "0x1".into();
    }

    // --- Approval flow (offline, deterministic) --------------------------------

    /// personal_sign blocks until the user approves; approval comes ONLY from the
    /// trusted "approval" webview. The returned signature must recover to the
    /// signing account — proving the whole approve→sign path end-to-end.
    #[test]
    fn e2e_personal_sign_approve() {
        let _guard = wallet_guard();
        let app = build_app();
        let dapp = dapp_webview(app);
        activate_dapp_tab(app, "dapp-0");
        let approval = approval_webview(app); // exists → request_approval reuses it

        let message_text = "Hello from AutoDesktop";
        let message_hex = format!("0x{}", hex::encode(message_text));
        let account = SPIKE_ACCOUNT;

        // personal_sign blocks on approval → run it on a worker thread.
        let dapp_for_thread = dapp.clone();
        let signer = std::thread::spawn(move || {
            call(
                &dapp_for_thread,
                "personal_sign",
                json!([message_hex, account]),
            )
        });

        // Approve from the approval webview once the request is registered.
        let id = wait_for_pending_id();
        // The approval UI first lists pending requests…
        let pending_list = invoke(&approval, "get_pending_requests", json!({})).unwrap();
        assert_eq!(pending_list.as_array().unwrap().len(), 1);
        assert_eq!(pending_list[0]["summary"], json!(message_text)); // decoded for display
        assert_eq!(
            pending_list[0]["origin"],
            json!("https://metamask.github.io")
        );
        // …then approves.
        invoke(&approval, "approve_request", json!({ "id": id })).expect("approve ok");

        let sig = signer.join().unwrap().expect("signature returned");
        let sig_hex = sig.as_str().expect("signature is a hex string");
        let raw = hex::decode(sig_hex.trim_start_matches("0x")).expect("hex sig");
        assert_eq!(raw.len(), 65, "EIP-191 signature must be 65 bytes");
        assert_eq!(
            recover_personal_sign(message_text.as_bytes(), &raw).to_lowercase(),
            account.to_lowercase(),
            "signature must recover to the signing account"
        );
    }

    /// SECURITY: the approval window shows the signer captured when the request
    /// arrived. If the user switches account while the prompt is open, approving
    /// must still sign with THAT account — never with whatever is active at the
    /// moment the button is pressed.
    #[test]
    fn e2e_personal_sign_uses_the_account_shown_at_request_time() {
        let _guard = wallet_guard();
        let app = build_app();
        let dapp = dapp_webview(app);
        activate_dapp_tab(app, "dapp-0");
        let approval = approval_webview(app);
        let (_, second) = super::vault::derive_account(TEST_MNEMONIC, 1).unwrap();
        assert_ne!(second, SPIKE_ACCOUNT);

        let message_text = "pin the signer";
        let message_hex = format!("0x{}", hex::encode(message_text));
        let dapp_for_thread = dapp.clone();
        let signer = std::thread::spawn(move || {
            call(
                &dapp_for_thread,
                "personal_sign",
                json!([message_hex, SPIKE_ACCOUNT]),
            )
        });

        let id = wait_for_pending_id();
        let shown = invoke(&approval, "get_pending_requests", json!({})).unwrap();
        assert_eq!(shown[0]["signer_address"], json!(SPIKE_ACCOUNT));
        super::select_account(app.handle().clone(), second.clone()).unwrap();
        invoke(&approval, "approve_request", json!({ "id": id })).expect("approve ok");

        let sig = signer.join().unwrap().expect("signature returned");
        let raw = hex::decode(sig.as_str().unwrap().trim_start_matches("0x")).unwrap();
        assert_eq!(
            recover_personal_sign(message_text.as_bytes(), &raw),
            SPIKE_ACCOUNT,
            "must sign with the account the approval window showed"
        );
    }

    /// Same rule for EIP-712: the signature must come from the account shown.
    #[test]
    fn e2e_sign_typed_data_uses_the_account_shown_at_request_time() {
        let _guard = wallet_guard();
        let app = build_app();
        let dapp = dapp_webview(app);
        activate_dapp_tab(app, "dapp-0");
        let approval = approval_webview(app);
        let (_, second) = super::vault::derive_account(TEST_MNEMONIC, 1).unwrap();

        let typed = json!({
            "types": {
                "EIP712Domain": [{"name": "name", "type": "string"}],
                "Note": [{"name": "text", "type": "string"}]
            },
            "primaryType": "Note",
            "domain": { "name": "Pin" },
            "message": { "text": "signer must not move" }
        });
        let typed_str = serde_json::to_string(&typed).unwrap();
        let dapp_for_thread = dapp.clone();
        let signer = std::thread::spawn(move || {
            call(
                &dapp_for_thread,
                "eth_signTypedData_v4",
                json!([SPIKE_ACCOUNT, typed_str]),
            )
        });

        let id = wait_for_pending_id();
        super::select_account(app.handle().clone(), second).unwrap();
        invoke(&approval, "approve_request", json!({ "id": id })).expect("approve ok");

        let sig = signer.join().unwrap().expect("signature returned");
        let raw = hex::decode(sig.as_str().unwrap().trim_start_matches("0x")).unwrap();
        let digest = eip712::signing_hash(&typed).unwrap();
        let signature = k256::ecdsa::Signature::from_slice(&raw[..64]).unwrap();
        let recid = k256::ecdsa::RecoveryId::from_byte(raw[64] - 27).unwrap();
        let vk = VerifyingKey::recover_from_prehash(&digest, &signature, recid).unwrap();
        assert_eq!(address_from_verifying_key(&vk), SPIKE_ACCOUNT);
    }

    /// A prepared transaction carries its `from` (and that account's nonce). The
    /// signature must come from that account even if another one is active now.
    #[test]
    fn a_prepared_transaction_is_signed_by_its_from_account() {
        let _guard = wallet_guard();
        let app = build_app();
        let chain = super::tests::stalled_node_chain();
        let chain_id = chain.id.clone();
        let restore = chains_state().lock().unwrap().clone();
        chains_state().lock().unwrap().push(chain);
        let resolved = find_chain(&chain_id).map(|c| c.rpc);
        if resolved.as_deref().map(|rpc| rpc.contains("127.0.0.1")) != Some(true) {
            *chains_state().lock().unwrap() = restore;
            panic!("test chain must resolve to the loopback stub, got {resolved:?}");
        }

        let prepared = PreparedTx {
            chain_id: chain_id.clone(),
            chain_name: "Stalled".into(),
            symbol: "ETH".into(),
            from: SPIKE_ACCOUNT.into(),
            to: SPIKE_ACCOUNT.into(),
            value: "0x2".into(),
            data: "0x".into(),
            gas: "0x5208".into(),
            nonce: "0x7".into(),
            max_priority_fee_per_gas: "0x1".into(),
            max_fee_per_gas: "0x3b9aca00".into(),
        };
        let (second, _) = super::vault::derive_account(TEST_MNEMONIC, 1)
            .map(|(_, a)| (a, ()))
            .unwrap();
        super::select_account(app.handle().clone(), second).unwrap();

        let sent = tauri::async_runtime::block_on(finalize_tx_within(
            &prepared,
            Duration::from_millis(300),
        ));
        *chains_state().lock().unwrap() = restore;
        let sent = sent.expect("unreachable node still yields the local hash");

        use eth_tx::{parse_address, parse_data, parse_quantity, Eip1559Tx};
        let (spike_key, _) = super::vault::derive_account(TEST_MNEMONIC, 0).unwrap();
        let expected = Eip1559Tx {
            chain_id: parse_quantity(&prepared.chain_id).unwrap(),
            nonce: parse_quantity(&prepared.nonce).unwrap(),
            max_priority_fee_per_gas: parse_quantity(&prepared.max_priority_fee_per_gas).unwrap(),
            max_fee_per_gas: parse_quantity(&prepared.max_fee_per_gas).unwrap(),
            gas_limit: parse_quantity(&prepared.gas).unwrap(),
            to: parse_address(&prepared.to).unwrap(),
            value: parse_quantity(&prepared.value).unwrap(),
            data: parse_data(&prepared.data).unwrap(),
        }
        .sign(&spike_key)
        .unwrap();
        assert_eq!(
            sent.hash, expected.1,
            "the tx must be signed by prepared.from, not the currently active account"
        );
    }

    /// SECURITY: only standard read methods (plus eth_sendRawTransaction) reach the
    /// node. Node-admin / account methods — anvil_*, personal_*, debug_*,
    /// eth_signTransaction — would act on a local dev node the user registered.
    /// The refusal happens before any network I/O, so this test is offline.
    #[test]
    fn e2e_dapp_cannot_forward_node_admin_methods() {
        let _guard = wallet_guard();
        let app = build_app();
        let wv = dapp_webview(app);
        for method in [
            "anvil_setBalance",
            "hardhat_impersonateAccount",
            "personal_unlockAccount",
            "personal_sendTransaction",
            "eth_signTransaction",
            "debug_traceTransaction",
            "admin_addPeer",
            "miner_start",
        ] {
            let err = call(&wv, method, json!([])).unwrap_err();
            assert!(
                err.as_str().unwrap_or_default().contains("4200"),
                "{method} must be refused as unsupported (4200), got: {err}"
            );
        }
        assert!(route_method("eth_getLogs") == Route::Forward);
        assert!(is_forwardable_method("eth_getLogs"));
        assert!(is_forwardable_method("eth_sendRawTransaction"));
        assert!(!is_forwardable_method("anvil_mine"));
    }

    /// A dApp that names an account in a signing request must name the one that
    /// will sign; otherwise the page believes it holds a signature from X while
    /// it got one from Y. Refused before any approval window opens.
    #[test]
    fn e2e_signing_refuses_a_different_named_account() {
        let _guard = wallet_guard();
        let app = build_app();
        let wv = dapp_webview(app);
        activate_dapp_tab(app, "dapp-0");
        let other = "0x3333333333333333333333333333333333333333";

        let err = call(&wv, "personal_sign", json!(["0x48656c6c6f", other])).unwrap_err();
        assert!(
            err.as_str().unwrap_or_default().contains("is not the selected account"),
            "got: {err}"
        );
        let err = call(&wv, "eth_signTypedData_v4", json!([other, "{}"])).unwrap_err();
        assert!(
            err.as_str().unwrap_or_default().contains("is not the selected account"),
            "got: {err}"
        );
        assert!(pending().lock().unwrap().is_empty(), "no approval may open");
    }

    /// Some older dApps send personal_sign params as [address, message]. The
    /// wallet must sign the message, not the 20 address bytes.
    #[test]
    fn e2e_personal_sign_accepts_legacy_param_order() {
        let _guard = wallet_guard();
        let app = build_app();
        let dapp = dapp_webview(app);
        activate_dapp_tab(app, "dapp-0");
        let approval = approval_webview(app);
        let message_text = "legacy order";
        let message_hex = format!("0x{}", hex::encode(message_text));

        let dapp_for_thread = dapp.clone();
        let signer = std::thread::spawn(move || {
            call(
                &dapp_for_thread,
                "personal_sign",
                json!([SPIKE_ACCOUNT, message_hex]),
            )
        });
        let id = wait_for_pending_id();
        let shown = invoke(&approval, "get_pending_requests", json!({})).unwrap();
        assert_eq!(shown[0]["summary"], json!(message_text));
        invoke(&approval, "approve_request", json!({ "id": id })).expect("approve ok");

        let sig = signer.join().unwrap().expect("signature returned");
        let raw = hex::decode(sig.as_str().unwrap().trim_start_matches("0x")).unwrap();
        assert_eq!(
            recover_personal_sign(message_text.as_bytes(), &raw),
            SPIKE_ACCOUNT
        );
    }

    /// A transaction field of the wrong type must be refused, never read as its
    /// default: `value: 1000` (a number) used to become 0, and a non-string `to`
    /// used to turn a transfer into a contract deployment.
    #[test]
    fn transaction_fields_of_the_wrong_type_are_refused() {
        for (tx, field) in [
            (json!({ "to": SPIKE_ACCOUNT, "value": 1000 }), "value"),
            (json!({ "to": 42, "value": "0x1" }), "to"),
            (json!({ "to": SPIKE_ACCOUNT, "data": ["0x"] }), "data"),
            (json!({ "to": SPIKE_ACCOUNT, "gas": 21000 }), "gas"),
            (json!({ "to": SPIKE_ACCOUNT, "nonce": 3 }), "nonce"),
            (json!({ "to": SPIKE_ACCOUNT, "maxFeePerGas": 1 }), "maxFeePerGas"),
            // Not an address: must not reach the byte-sliced summary (would panic).
            (json!({ "to": "0xéééééééééééééééééééé" }), "to"),
            (json!({ "to": "0x1234" }), "to"),
        ] {
            let err = validate_tx_field_types(&tx).unwrap_err();
            assert!(err.contains(field), "{tx}: error must name {field}, got {err}");
        }
        // Absent fields, and `to: null` (contract creation), stay valid.
        validate_tx_field_types(&json!({ "to": null, "data": "0x60" })).unwrap();
        validate_tx_field_types(&json!({ "to": SPIKE_ACCOUNT, "value": "0x1" })).unwrap();
        // Not a transaction object at all.
        assert!(validate_tx_field_types(&json!("0xdead")).is_err());
    }

    /// End to end: a wrong-typed value is refused before any approval opens.
    #[test]
    fn e2e_send_transaction_with_numeric_value_is_refused() {
        let _guard = wallet_guard();
        let app = build_app();
        let wv = dapp_webview(app);
        activate_dapp_tab(app, "dapp-0");
        let err = call(
            &wv,
            "eth_sendTransaction",
            json!([{ "from": SPIKE_ACCOUNT, "to": SPIKE_ACCOUNT, "value": 1000 }]),
        )
        .unwrap_err();
        assert!(err.as_str().unwrap_or_default().contains("value"), "got: {err}");
        assert!(pending().lock().unwrap().is_empty());
    }

    /// A dApp on an origin the user has never connected. dapp-0 (metamask.github.io)
    /// is treated as already connected by `wallet_guard`.
    fn stranger_dapp(app: &'static tauri::App<MockRuntime>) -> WebviewWindow<MockRuntime> {
        webview(
            app,
            "dapp-1",
            tauri::WebviewUrl::External("https://stranger.example/app".parse().unwrap()),
        )
    }

    /// PRIVACY: a site the user never connected must not learn the address, and
    /// must not be able to sign or switch the wallet's network.
    #[test]
    fn e2e_unconnected_site_sees_no_account_and_cannot_act() {
        let _guard = wallet_guard();
        let app = build_app();
        let wv = stranger_dapp(app);
        activate_dapp_tab(app, "dapp-1");

        assert_eq!(call(&wv, "eth_accounts", json!([])).unwrap(), json!([]));
        assert_eq!(call(&wv, "eth_coinbase", json!([])).unwrap(), Value::Null);
        assert_eq!(
            call(&wv, "wallet_getPermissions", json!([])).unwrap(),
            json!([])
        );

        let err = call(&wv, "personal_sign", json!(["0x48656c6c6f", SPIKE_ACCOUNT])).unwrap_err();
        assert!(
            err.as_str().unwrap_or_default().contains("4100"),
            "unconnected signing must be refused as unauthorized (4100), got: {err}"
        );
        assert!(pending().lock().unwrap().is_empty(), "no approval may open");

        let err = call(
            &wv,
            "wallet_switchEthereumChain",
            json!([{ "chainId": "0x2105" }]),
        )
        .unwrap_err();
        assert!(err.as_str().unwrap_or_default().contains("4100"), "got: {err}");
        assert_eq!(*current_chain().lock().unwrap(), "0x1");
    }

    /// eth_requestAccounts from an unconnected site asks the user first; approving
    /// connects the origin, after which eth_accounts answers.
    #[test]
    fn e2e_request_accounts_asks_then_connects() {
        let _guard = wallet_guard();
        let app = build_app();
        let wv = stranger_dapp(app);
        activate_dapp_tab(app, "dapp-1");
        let approval = approval_webview(app);

        let wv_thread = wv.clone();
        let asker = std::thread::spawn(move || call(&wv_thread, "eth_requestAccounts", json!([])));
        let id = wait_for_pending_id();
        let shown = invoke(&approval, "get_pending_requests", json!({})).unwrap();
        assert_eq!(shown[0]["method"], json!("eth_requestAccounts"));
        assert_eq!(shown[0]["origin"], json!("https://stranger.example"));
        assert_eq!(shown[0]["signer_address"], json!(SPIKE_ACCOUNT));
        invoke(&approval, "approve_request", json!({ "id": id })).expect("approve ok");

        assert_eq!(asker.join().unwrap().unwrap(), json!([SPIKE_ACCOUNT]));
        assert_eq!(
            call(&wv, "eth_accounts", json!([])).unwrap(),
            json!([SPIKE_ACCOUNT])
        );

        // Revoking disconnects the site again.
        assert_eq!(
            call(&wv, "wallet_revokePermissions", json!([{ "eth_accounts": {} }])).unwrap(),
            Value::Null
        );
        assert_eq!(call(&wv, "eth_accounts", json!([])).unwrap(), json!([]));
    }

    /// Connections survive a restart: what `connect_site` saves, a fresh load
    /// reads back, and a disconnect is saved too.
    #[test]
    fn connected_sites_persist_across_a_restart() {
        let _guard = wallet_guard();
        let app = build_app();
        connect_site(app.handle(), "https://kept.example").unwrap();
        connected_sites().lock().unwrap().clear(); // "restart": memory is empty
        load_connected_sites(app.handle());
        assert!(is_site_connected("https://kept.example"));
        assert!(is_site_connected("https://metamask.github.io"));

        disconnect_site(app.handle(), "https://kept.example").unwrap();
        connected_sites().lock().unwrap().clear();
        load_connected_sites(app.handle());
        assert!(!is_site_connected("https://kept.example"));
        assert!(is_site_connected("https://metamask.github.io"));
    }

    /// Rejecting the connection answers 4001 and leaves the site disconnected.
    #[test]
    fn e2e_request_accounts_reject_stays_disconnected() {
        let _guard = wallet_guard();
        let app = build_app();
        let wv = stranger_dapp(app);
        activate_dapp_tab(app, "dapp-1");
        let approval = approval_webview(app);

        let wv_thread = wv.clone();
        let asker = std::thread::spawn(move || call(&wv_thread, "eth_requestAccounts", json!([])));
        let id = wait_for_pending_id();
        invoke(&approval, "reject_request", json!({ "id": id })).expect("reject ok");

        let err = asker.join().unwrap().unwrap_err();
        assert!(err.as_str().unwrap_or_default().contains("4001"), "got: {err}");
        assert_eq!(call(&wv, "eth_accounts", json!([])).unwrap(), json!([]));
    }

    /// A connected dApp in a background tab must not move the whole wallet (and
    /// every other tab) to another network.
    #[test]
    fn e2e_background_tab_cannot_switch_chain() {
        let _guard = wallet_guard();
        let app = build_app();
        let wv = dapp_webview(app);
        let shell = shell_webview(app);
        invoke(
            &shell,
            "open_dapp",
            json!({ "label": "dapp-0", "url": "https://metamask.github.io/test-dapp/", "x": 0.0, "y": 0.0, "w": 100.0, "h": 100.0 }),
        )
        .expect("shell can activate dapp tab");
        invoke(&shell, "hide_dapp", json!({ "label": "dapp-0" })).expect("hide");

        let err = call(
            &wv,
            "wallet_switchEthereumChain",
            json!([{ "chainId": "0x2105" }]),
        )
        .unwrap_err();
        assert!(
            err.as_str().unwrap_or_default().contains("not the active tab"),
            "got: {err}"
        );
        assert_eq!(*current_chain().lock().unwrap(), "0x1");
    }

    /// Rejecting yields the EIP-1193 user-rejected (4001) error to the dApp.
    #[test]
    fn e2e_personal_sign_reject() {
        let _guard = wallet_guard();
        let app = build_app();
        let dapp = dapp_webview(app);
        activate_dapp_tab(app, "dapp-0");
        let approval = approval_webview(app);

        let dapp_for_thread = dapp.clone();
        let signer = std::thread::spawn(move || {
            call(
                &dapp_for_thread,
                "personal_sign",
                json!(["0x48656c6c6f", SPIKE_ACCOUNT]),
            )
        });

        let id = wait_for_pending_id();
        invoke(&approval, "reject_request", json!({ "id": id })).expect("reject ok");

        let err = signer.join().unwrap().unwrap_err();
        assert!(
            err.as_str().unwrap_or_default().contains("4001"),
            "expected user-rejected (4001), got: {err}"
        );
    }

    /// eth_signTypedData_v4 end-to-end through the approval flow (OFFLINE — EIP-712
    /// is pure). The returned signature must recover, over the EIP-712 digest, to the
    /// unlocked signer — proving the typed-data hashing + approve→sign path.
    #[test]
    fn e2e_sign_typed_data_v4_approve() {
        let _guard = wallet_guard();
        let app = build_app();
        let dapp = dapp_webview(app);
        activate_dapp_tab(app, "dapp-0");
        let approval = approval_webview(app);

        let typed = json!({
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "wallet", "type": "address"}
                ],
                "Mail": [
                    {"name": "from", "type": "Person"},
                    {"name": "to", "type": "Person"},
                    {"name": "contents", "type": "string"}
                ]
            },
            "primaryType": "Mail",
            "domain": {
                "name": "Ether Mail", "version": "1", "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
            },
            "message": {
                "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
                "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
                "contents": "Hello, Bob!"
            }
        });
        let typed_str = serde_json::to_string(&typed).unwrap();

        let dapp_for_thread = dapp.clone();
        let signer = std::thread::spawn(move || {
            call(
                &dapp_for_thread,
                "eth_signTypedData_v4",
                json!([SPIKE_ACCOUNT, typed_str]),
            )
        });

        let id = wait_for_pending_id();
        // The approval window shows a typed-data summary AND the full payload —
        // the UI must be able to render every field (spender/amount/deadline…),
        // otherwise typed-data signing is blind signing (permit-phishing risk).
        let pending = invoke(&approval, "get_pending_requests", json!({})).unwrap();
        assert_eq!(pending[0]["summary"], json!("Sign Mail for Ether Mail"));
        assert_eq!(pending[0]["typed_data"], typed);
        invoke(&approval, "approve_request", json!({ "id": id })).expect("approve ok");

        let sig = signer.join().unwrap().expect("signature returned");
        let raw = hex::decode(sig.as_str().unwrap().trim_start_matches("0x")).unwrap();
        assert_eq!(raw.len(), 65, "EIP-712 signature must be 65 bytes");

        // Recover over the EIP-712 digest → must be the unlocked signer (Anvil #0).
        let digest = eip712::signing_hash(&typed).unwrap();
        let signature = k256::ecdsa::Signature::from_slice(&raw[..64]).unwrap();
        let recid = k256::ecdsa::RecoveryId::from_byte(raw[64] - 27).unwrap();
        let vk = VerifyingKey::recover_from_prehash(&digest, &signature, recid).unwrap();
        assert_eq!(
            address_from_verifying_key(&vk).to_lowercase(),
            SPIKE_ACCOUNT.to_lowercase()
        );
    }

    /// SECURITY: a hidden/background dApp webview stays alive, but it must not be
    /// able to surface a signing approval. Switching away calls hide_dapp, which
    /// clears the active dApp label; signing then fails before pending approval is
    /// registered.
    #[test]
    fn e2e_background_dapp_signing_is_blocked_without_approval_popup() {
        let _guard = wallet_guard();
        let app = build_app();
        let dapp = dapp_webview(app);
        let shell = shell_webview(app);

        invoke(
            &shell,
            "open_dapp",
            json!({ "label": "dapp-0", "url": "https://metamask.github.io/test-dapp/", "x": 0.0, "y": 0.0, "w": 100.0, "h": 100.0 }),
        )
        .expect("shell can activate dapp tab");

        invoke(&shell, "hide_dapp", json!({ "label": "dapp-0" }))
            .expect("shell can hide active dapp");

        let err = call(
            &dapp,
            "personal_sign",
            json!(["0x48656c6c6f", SPIKE_ACCOUNT]),
        )
        .unwrap_err();
        assert!(
            err.as_str()
                .unwrap_or_default()
                .contains("not the active tab"),
            "expected inactive-tab signing rejection, got: {err}"
        );
        assert!(
            pending().lock().unwrap().is_empty(),
            "background signing must not register a pending approval"
        );
    }

    /// eth_sendTransaction end-to-end against a LIVE node. All fields are supplied
    /// (with a deliberately low nonce so the node rejects WITHOUT broadcasting), so
    /// only eth_sendRawTransaction hits the node — exactly the path that proves our
    /// RLP + signature are valid on-chain. A "nonce too low" / "insufficient funds"
    /// rejection happens only AFTER the node decoded the tx and recovered the
    /// sender from the signature, so it proves correctness; a decode/RLP/sender
    /// error never gets that far.
    #[test]
    #[ignore = "broadcasts to a live public RPC node; run with `cargo test -- --ignored`"]
    fn e2e_send_transaction_live() {
        let _guard = wallet_guard(); // unlocked Anvil vault, chain 0x1
        let app = build_app();
        let dapp = dapp_webview(app);
        activate_dapp_tab(app, "dapp-0");
        let approval = approval_webview(app);

        let tx = json!([{
            "from": SPIKE_ACCOUNT,
            "to": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
            "value": "0x0",
            "gas": "0x5208",
            "maxPriorityFeePerGas": "0x3b9aca00", // 1 gwei
            "maxFeePerGas": "0x77359400",         // 2 gwei
            "nonce": "0x0"
        }]);

        let dapp_for_thread = dapp.clone();
        let sender = std::thread::spawn(move || call(&dapp_for_thread, "eth_sendTransaction", tx));

        let id = wait_for_pending_id();
        invoke(&approval, "approve_request", json!({ "id": id })).expect("approve ok");

        match sender.join().unwrap() {
            // A funded sender at the right nonce would actually broadcast → tx hash.
            Ok(hash) => assert!(hash.as_str().unwrap_or("").starts_with("0x")),
            Err(e) => {
                let msg = e.as_str().unwrap_or("").to_lowercase();
                // These all occur AFTER the node decoded the tx and recovered the
                // sender (nonce / funds / fee checks) — they prove valid encoding.
                let post_decode = msg.contains("nonce")
                    || msg.contains("insufficient funds")
                    || msg.contains("balance")
                    || msg.contains("fee")
                    || msg.contains("underpriced");
                // A decode/signature failure would surface as one of these instead.
                let encoding_error = msg.contains("rlp")
                    || msg.contains("decode")
                    || msg.contains("invalid sender")
                    || msg.contains("typed transaction")
                    || msg.contains("malformed");
                assert!(
                    post_decode && !encoding_error,
                    "node rejected for an ENCODING reason, not a post-decode check: {msg}"
                );
            }
        }
    }

    /// SECURITY: the dapp webview must NOT be able to approve requests — the ACL
    /// grants approve_request only to the "approval" webview. A page calling it
    /// (e.g. to self-approve) is denied by Tauri before reaching our handler.
    #[test]
    fn e2e_dapp_cannot_approve() {
        let _guard = wallet_guard();
        let app = build_app();
        let dapp = dapp_webview(app);

        let err = invoke(&dapp, "approve_request", json!({ "id": "req-1" })).unwrap_err();
        let msg = err.as_str().unwrap_or_default();
        assert!(
            msg.contains("not allowed") || msg.contains("not found"),
            "expected ACL denial for dapp→approve_request, got: {err}"
        );
    }

    #[test]
    fn e2e_dapp_can_request_dialog_but_only_through_narrow_command() {
        let app = build_app();
        let dapp = dapp_webview(app);

        let err = invoke(
            &dapp,
            "dapp_dialog",
            json!({ "kind": "bogus", "message": "hi", "defaultValue": null }),
        )
        .unwrap_err();
        assert!(
            err.as_str()
                .unwrap_or_default()
                .contains("unsupported kind"),
            "expected dapp_dialog to reach the narrow handler, got: {err}"
        );
    }

    #[test]
    fn auto_lock_is_due_only_after_the_idle_window() {
        let min = 60_000;
        // Never when disabled, when nothing is unlocked with a password, or early.
        assert!(!auto_lock_due(100 * min, 0, 0, true));
        assert!(!auto_lock_due(100 * min, 0, 15, false));
        assert!(!auto_lock_due(20 * min, 6 * min, 15, true));
        // Exactly at, and past, the window.
        assert!(auto_lock_due(21 * min, 6 * min, 15, true));
        assert!(auto_lock_due(60 * min, 6 * min, 15, true));
        // A clock that went backwards never locks by accident.
        assert!(!auto_lock_due(1 * min, 6 * min, 15, true));
    }

    /// The idle timer drops the keys, but never under an open approval (the user
    /// is looking at it), and dApp traffic counts as activity.
    #[test]
    fn e2e_auto_lock_drops_keys_after_idle() {
        let _guard = wallet_guard();
        let app = build_app();
        let wv = dapp_webview(app);
        // The test vault has no password; give it one so it is lockable.
        store_state().lock().unwrap().as_mut().unwrap().password =
            Some(Zeroizing::new("hunter22".to_string()));
        let min = 60_000;

        note_activity_at(10 * min);
        auto_lock_tick_at(app.handle(), 15, 20 * min);
        assert!(active_account_address().is_some(), "not idle long enough yet");

        // A dApp call is activity: it resets the timer.
        call(&wv, "eth_chainId", json!([])).unwrap();
        assert!(last_activity_ms() > 20 * min);

        note_activity_at(10 * min);
        auto_lock_tick_at(app.handle(), 15, 30 * min);
        assert!(active_account_address().is_none(), "idle 20 min > 15 min: locked");
        assert_eq!(call(&wv, "eth_accounts", json!([])).unwrap(), json!([]));
    }

    #[test]
    fn e2e_auto_lock_waits_while_an_approval_is_open() {
        let _guard = wallet_guard();
        let app = build_app();
        store_state().lock().unwrap().as_mut().unwrap().password =
            Some(Zeroizing::new("hunter22".to_string()));
        let (tx, _rx) = tokio::sync::oneshot::channel();
        pending().lock().unwrap().insert(
            "req-open".into(),
            PendingEntry {
                req: PendingRequest {
                    id: "req-open".into(),
                    method: "personal_sign".into(),
                    origin: "https://metamask.github.io".into(),
                    signer_address: None,
                    signer_kind: None,
                    summary: String::new(),
                    tx: None,
                    typed_data: None,
                },
                responder: tx,
            },
        );
        note_activity_at(0);
        auto_lock_tick_at(app.handle(), 15, 600 * 60_000);
        assert!(active_account_address().is_some());
        pending().lock().unwrap().clear();
    }

    /// Locking tells connected tabs their account is gone; unconnected tabs are
    /// never told anything (not even that there was an account).
    #[test]
    fn e2e_lock_announces_no_account_to_connected_tabs_only() {
        let _guard = wallet_guard();
        let app = build_app();
        let _connected = dapp_webview(app);
        let _stranger = stranger_dapp(app);

        let before = accounts_changed_targets(app.handle(), dapp_account_address().as_deref());
        assert_eq!(before, vec![("dapp-0".to_string(), vec![SPIKE_ACCOUNT.to_string()])]);

        lock_vault(app.handle().clone());
        let after = accounts_changed_targets(app.handle(), dapp_account_address().as_deref());
        assert_eq!(after, vec![("dapp-0".to_string(), Vec::<String>::new())]);
    }

    /// A background tab must not put a dialog over the tab the user is looking at
    /// (it would appear to come from the visible site), nor open browser tabs.
    #[test]
    fn e2e_background_dapp_cannot_pop_dialogs_or_open_urls() {
        let _guard = wallet_guard();
        let app = build_app();
        let dapp = dapp_webview(app);
        let shell = shell_webview(app);
        invoke(
            &shell,
            "open_dapp",
            json!({ "label": "dapp-0", "url": "https://metamask.github.io/test-dapp/", "x": 0.0, "y": 0.0, "w": 100.0, "h": 100.0 }),
        )
        .expect("activate");
        invoke(&shell, "hide_dapp", json!({ "label": "dapp-0" })).expect("hide");

        let err = invoke(
            &dapp,
            "dapp_dialog",
            json!({ "kind": "prompt", "message": "Enter your recovery phrase", "defaultValue": null }),
        )
        .unwrap_err();
        assert!(err.as_str().unwrap_or_default().contains("not the active tab"), "got: {err}");
        assert!(dapp_dialog_pending().lock().unwrap().is_empty());

        let err = invoke(
            &dapp,
            "open_external_url",
            json!({ "url": "https://phish.example/" }),
        )
        .unwrap_err();
        assert!(err.as_str().unwrap_or_default().contains("not the active tab"), "got: {err}");
    }

    /// One dialog per tab at a time: a page looping on alert() must not stack
    /// prompts (the shell shows only one; the rest would hang for 300s).
    #[test]
    fn e2e_dapp_dialogs_do_not_stack() {
        let _guard = wallet_guard();
        dapp_dialog_pending().lock().unwrap().clear();
        dapp_dialog_owners().lock().unwrap().clear();
        let app = build_app();
        let dapp = dapp_webview(app);
        activate_dapp_tab(app, "dapp-0");

        let first = dapp.clone();
        let opener = std::thread::spawn(move || {
            invoke(
                &first,
                "dapp_dialog",
                json!({ "kind": "alert", "message": "one", "defaultValue": null }),
            )
        });
        let mut id = None;
        for _ in 0..300 {
            id = dapp_dialog_pending().lock().unwrap().keys().next().cloned();
            if id.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let id = id.expect("first dialog registered");

        let err = invoke(
            &dapp,
            "dapp_dialog",
            json!({ "kind": "alert", "message": "two", "defaultValue": null }),
        )
        .unwrap_err();
        assert!(err.as_str().unwrap_or_default().contains("already open"), "got: {err}");

        resolve_dapp_dialog(id, "ok".into(), None).unwrap();
        let res = opener.join().unwrap().expect("first dialog resolves");
        assert_eq!(res["action"], json!("ok"));
        assert!(dapp_dialog_owners().lock().unwrap().is_empty(), "slot freed");
    }

    /// The trusted *shell* webview (local). As a local webview it may call bare
    /// app commands; the dapp-browser controls (open/close/bounds) are reachable
    /// only this way.
    fn shell_webview(app: &'static tauri::App<MockRuntime>) -> WebviewWindow<MockRuntime> {
        webview(app, "shell", tauri::WebviewUrl::App("index.html".into()))
    }

    fn activate_dapp_tab(app: &'static tauri::App<MockRuntime>, label: &str) {
        let shell = shell_webview(app);
        invoke(
            &shell,
            "open_dapp",
            json!({ "label": label, "url": "https://metamask.github.io/test-dapp/", "x": 0.0, "y": 0.0, "w": 100.0, "h": 100.0 }),
        )
        .expect("shell can activate dapp tab");
    }

    /// SECURITY: an untrusted dApp page must NOT be able to drive the embedded
    /// browser — navigating or repositioning a webview is a shell-only power. The
    /// commands have no ACL permission entry, so the remote dapp webview is denied
    /// before reaching the handler. (If these were ever added to dapp.json this
    /// fails.)
    #[test]
    fn e2e_dapp_cannot_control_webviews() {
        let app = build_app();
        let dapp = dapp_webview(app);

        for (cmd, args) in [
            (
                "open_dapp",
                json!({ "label": "dapp-9", "url": "https://evil.example", "x": 0.0, "y": 0.0, "w": 10.0, "h": 10.0 }),
            ),
            (
                "set_dapp_bounds",
                json!({ "label": "dapp-9", "x": 0.0, "y": 0.0, "w": 10.0, "h": 10.0 }),
            ),
            (
                "sync_toast_overlay",
                json!({ "visible": true, "x": 0.0, "y": 0.0, "w": 10.0, "h": 10.0 }),
            ),
            (
                "sync_menu_overlay",
                json!({ "visible": true, "x": 0.0, "y": 0.0, "w": 10.0, "h": 10.0 }),
            ),
            (
                "resolve_dapp_dialog",
                json!({ "id": "dlg-1", "action": "ok", "value": null }),
            ),
            ("reload_dapp", json!({ "label": "dapp-9" })),
            ("navigate_dapp", json!({ "label": "dapp-9", "url": "https://evil.example/" })),
            ("go_back_dapp", json!({ "label": "dapp-9" })),
            ("hide_dapp", json!({ "label": "dapp-9" })),
            ("close_dapp", json!({ "label": "dapp-9" })),
            ("set_active_chain", json!({ "chainId": "0x1" })),
            (
                "expose_dapp_account",
                json!({ "address": "0x2222222222222222222222222222222222222222" }),
            ),
        ] {
            let err = invoke(&dapp, cmd, args).unwrap_err();
            let msg = err.as_str().unwrap_or_default();
            assert!(
                msg.contains("not allowed") || msg.contains("not found"),
                "expected ACL denial for dapp→{cmd}, got: {err}"
            );
        }
    }

    #[test]
    fn e2e_clipboard_access_is_scoped_to_trusted_copy_buttons() {
        let app = build_app();
        let dapp = dapp_webview(app);
        let shell = shell_webview(app);
        let menu = webview(
            app,
            "menu-overlay",
            tauri::WebviewUrl::App("index.html?view=menu-overlay".into()),
        );

        for caller in [&dapp, &shell, &menu] {
            let err = invoke(caller, "plugin:clipboard-manager|read_text", json!({}))
                .expect_err("webviews must not read the clipboard");
            assert!(err.as_str().unwrap().contains("not allowed"), "{err}");
        }
        let err = invoke(
            &dapp,
            "plugin:clipboard-manager|write_text",
            json!({ "text": "untrusted replacement" }),
        )
        .expect_err("remote pages must not overwrite the clipboard");
        assert!(err.as_str().unwrap().contains("not allowed"), "{err}");
    }

    /// Opt-in OS smoke test: preserves the previous clipboard text in memory.
    #[test]
    #[ignore = "writes the real OS clipboard; run explicitly on a desktop"]
    fn e2e_native_clipboard_copy() {
        use tauri_plugin_clipboard_manager::ClipboardExt;

        let app = build_app();
        let previous = app.clipboard().read_text().expect("read clipboard text");
        // Restore on success or panic without saving clipboard data to disk.
        struct RestoreClipboard<'a>(&'a tauri::App<MockRuntime>, String);
        impl Drop for RestoreClipboard<'_> {
            fn drop(&mut self) {
                self.0
                    .clipboard()
                    .write_text(&self.1)
                    .expect("restore clipboard text");
            }
        }
        let _restore = RestoreClipboard(app, previous);
        let shell = shell_webview(app);
        let menu = webview(
            app,
            "menu-overlay",
            tauri::WebviewUrl::App("index.html?view=menu-overlay".into()),
        );
        for caller in [&shell, &menu] {
            for text in [
                "clipboard regression marker",
                "0x7521ed00000000000000000000000000000d5188",
            ] {
                invoke(
                    caller,
                    "plugin:clipboard-manager|write_text",
                    json!({ "text": text }),
                )
                .expect("trusted copy completes");
                // Do not print the user's prior clipboard contents on failure.
                assert!(app.clipboard().read_text().expect("read copied text") == text);
            }
        }
    }

    /// open_dapp refuses non-http(s) schemes (e.g. file:/javascript:) — guards
    /// against the shell being tricked into pointing the webview at a local file
    /// or a script URL. Pure command logic: deleting the scheme check fails this.
    #[test]
    fn e2e_open_dapp_rejects_non_http_scheme() {
        let app = build_app();
        let shell = shell_webview(app);

        for bad in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,x",
        ] {
            let err = invoke(
                &shell,
                "open_dapp",
                json!({ "label": "dapp-0", "url": bad, "x": 0.0, "y": 0.0, "w": 100.0, "h": 100.0 }),
            )
            .unwrap_err();
            assert!(
                err.as_str()
                    .unwrap_or_default()
                    .contains("refusing non-http"),
                "expected scheme rejection for {bad}, got: {err}"
            );
        }
    }

    /// open_dapp / reload_dapp / go_back_dapp / hide_dapp / close_dapp reject labels that aren't `dapp-<id>`,
    /// so these shell commands can never target the trusted shell/approval webviews.
    #[test]
    fn e2e_dapp_controls_reject_foreign_labels() {
        let app = build_app();
        let shell = shell_webview(app);
        for label in ["shell", "approval", "dapp", "../shell", "dapp-bad/slash"] {
            let err = invoke(
                &shell,
                "open_dapp",
                json!({ "label": label, "url": "https://app.uniswap.org", "x": 0.0, "y": 0.0, "w": 10.0, "h": 10.0 }),
            )
            .unwrap_err();
            assert!(
                err.as_str()
                    .unwrap_or_default()
                    .contains("invalid dapp label"),
                "expected label rejection for {label:?}, got: {err}"
            );
        }
    }

    /// set_active_chain accepts a known chain and rejects an unknown one (real
    /// validation: deleting the find_chain check fails the unknown case). Only ever
    /// sets the default 0x1 so it doesn't race the other chain-reading e2e tests.
    #[test]
    fn e2e_set_active_chain_validates() {
        let app = build_app();
        let shell = shell_webview(app);

        invoke(&shell, "set_active_chain", json!({ "chainId": "0x1" }))
            .expect("known chain should be accepted");

        let err = invoke(&shell, "set_active_chain", json!({ "chainId": "0xdead" })).unwrap_err();
        assert!(
            err.as_str().unwrap_or_default().contains("unknown chain"),
            "expected unknown-chain rejection, got: {err}"
        );
    }

    /// The trusted shell must be able to reach every Safe command. Invalid
    /// addresses deliberately stop each handler before network or signing work,
    /// so this locks down the IPC registration + ACL seam deterministically.
    #[test]
    fn e2e_shell_can_reach_safe_commands() {
        let app = build_app();
        let shell = shell_webview(app);

        for (command, args) in [
            (
                "inspect_safe",
                json!({ "chainId": "0x2105", "address": "not-an-address" }),
            ),
            (
                "safe_pending_transactions",
                json!({
                    "serviceUrl": "https://api.safe.global/tx-service/base/api",
                    "safeAddress": "not-an-address"
                }),
            ),
            (
                "safe_confirm_transaction",
                json!({
                    "chainId": "0x2105",
                    "serviceUrl": "https://api.safe.global/tx-service/base/api",
                    "safeAddress": "not-an-address",
                    "ownerAddress": "not-an-address",
                    "transaction": {}
                }),
            ),
        ] {
            let err = invoke(&shell, command, args).unwrap_err();
            let message = err.as_str().unwrap_or_default();
            assert!(
                message.to_ascii_lowercase().contains("address"),
                "{command} did not reach its argument validation: {err}"
            );
        }
    }

    /// SECURITY: Safe management and owner-signing commands stay shell-only.
    /// Registering their permissions must never make them callable by a remote
    /// dApp webview.
    #[test]
    fn e2e_dapp_cannot_reach_safe_commands() {
        let app = build_app();
        let dapp = dapp_webview(app);

        for (command, args) in [
            (
                "inspect_safe",
                json!({ "chainId": "0x2105", "address": "not-an-address" }),
            ),
            (
                "safe_pending_transactions",
                json!({
                    "serviceUrl": "https://api.safe.global/tx-service/base/api",
                    "safeAddress": "not-an-address"
                }),
            ),
            (
                "safe_confirm_transaction",
                json!({
                    "chainId": "0x2105",
                    "serviceUrl": "https://api.safe.global/tx-service/base/api",
                    "safeAddress": "not-an-address",
                    "ownerAddress": "not-an-address",
                    "transaction": {}
                }),
            ),
        ] {
            let err = invoke(&dapp, command, args).unwrap_err();
            let message = err.as_str().unwrap_or_default();
            assert!(
                message.contains("not allowed") || message.contains("not found"),
                "remote dapp unexpectedly reached {command}: {err}"
            );
        }
    }

    /// SECURITY: exchange credentials and account data stay behind the trusted
    /// shell capability. A remote dApp cannot even check whether OKX is connected.
    #[test]
    fn e2e_dapp_cannot_reach_okx_account_commands() {
        let app = build_app();
        let dapp = dapp_webview(app);

        for (command, args) in [
            ("okx_connection_status", json!({})),
            (
                "okx_save_credentials",
                json!({
                    "creds": {
                        "apiKey": "not-a-real-key",
                        "secretKey": "not-a-real-secret",
                        "passphrase": "not-a-real-passphrase",
                        "region": "global"
                    }
                }),
            ),
            ("okx_delete_credentials", json!({})),
            ("okx_get_assets", json!({})),
            (
                "okx_get_dcd_index_prices",
                json!({ "instrumentIds": ["BTC-USDC"] }),
            ),
            ("okx_get_dcd_orders", json!({})),
        ] {
            let err = invoke(&dapp, command, args).unwrap_err();
            let message = err.as_str().unwrap_or_default();
            assert!(
                message.contains("not allowed") || message.contains("not found"),
                "remote dapp unexpectedly reached {command}: {err}"
            );
        }
    }

    /// The trusted shell CAN drive a tab webview: open (show), reposition, hide,
    /// and close all succeed against the real dapp-<id> webview.
    #[test]
    fn e2e_shell_controls_embedded_browser() {
        let app = build_app();
        let _dapp = dapp_webview(app); // label "dapp-0" — must exist for the controls
        let shell = shell_webview(app);

        invoke(
            &shell,
            "open_dapp",
            json!({ "label": "dapp-0", "url": "https://app.uniswap.org", "x": 232.0, "y": 52.0, "w": 1048.0, "h": 668.0 }),
        )
        .expect("shell open_dapp should succeed");

        invoke(
            &shell,
            "set_dapp_bounds",
            json!({ "label": "dapp-0", "x": 232.0, "y": 52.0, "w": 1200.0, "h": 800.0 }),
        )
        .expect("shell set_dapp_bounds should succeed");

        invoke(&shell, "reload_dapp", json!({ "label": "dapp-0" }))
            .expect("shell reload_dapp should succeed");

        invoke(&shell, "go_back_dapp", json!({ "label": "dapp-0" }))
            .expect("shell go_back_dapp should succeed");

        invoke(&shell, "hide_dapp", json!({ "label": "dapp-0" }))
            .expect("shell hide_dapp should succeed");

        invoke(&shell, "close_dapp", json!({ "label": "dapp-0" }))
            .expect("shell close_dapp should succeed");
    }

    #[test]
    fn e2e_shell_navigates_existing_dapp() {
        let app = build_app();
        let dapp = dapp_webview(app);
        let shell = shell_webview(app);
        let target = "https://app.aave.com/markets/?market=base#supply";
        invoke(
            &shell,
            "navigate_dapp",
            json!({ "label": "dapp-0", "url": target }),
        )
        .expect("shell can navigate the existing tab");
        assert_eq!(dapp.url().unwrap().as_str(), target);
    }

    #[test]
    fn e2e_navigate_dapp_rejects_invalid_targets() {
        let app = build_app();
        let dapp = dapp_webview(app);
        let original_url = dapp.url().unwrap();
        let shell = shell_webview(app);
        for (label, url, expected) in [
            ("shell", "https://app.aave.com/", "invalid dapp label"),
            ("approval", "https://app.aave.com/", "invalid dapp label"),
            ("dapp-0", "file:///etc/passwd", "refusing non-http"),
            ("dapp-0", "javascript:alert(1)", "refusing non-http"),
            ("dapp-0", "data:text/html,x", "refusing non-http"),
            ("dapp-0", "not a URL", "invalid url"),
            ("dapp-missing", "https://app.aave.com/", "webview not found"),
        ] {
            let error = invoke(
                &shell,
                "navigate_dapp",
                json!({ "label": label, "url": url }),
            )
            .unwrap_err();
            assert!(error.as_str().unwrap().contains(expected), "{error}");
            assert_eq!(dapp.url().unwrap(), original_url);
        }
    }
}
