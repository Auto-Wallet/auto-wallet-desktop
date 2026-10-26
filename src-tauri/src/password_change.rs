use crate::touch_id;
use crate::vault::{self, Keystore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;

const JOURNAL_FILE: &str = "password-change.pending";
const BACKUP_FILE: &str = "password-change.backup";
const LOCK_FILE: &str = "vault-io.lock";

pub fn recovery_pending(directory: &Path) -> Result<bool, String> {
    for name in [JOURNAL_FILE, BACKUP_FILE] {
        if directory
            .join(name)
            .try_exists()
            .map_err(|e| format!("checking password recovery files: {e}"))?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The OS releases this exclusive lock even if a process crashes. Keeping the
/// file in the app-data parent also protects reset/recreation of wallets/.
pub fn lock_directory(parent: &Path) -> Result<std::fs::File, String> {
    std::fs::create_dir_all(parent).map_err(|e| format!("opening vault directory: {e}"))?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(parent.join(LOCK_FILE))
        .map_err(|e| format!("opening vault lock: {e}"))?;
    file.lock()
        .map_err(|e| format!("locking wallet files: {e}"))?;
    Ok(file)
}

/// Metadata edits and migration must not truncate the only encrypted key copy.
pub fn write_keystore(path: &Path, wallet: &Keystore) -> Result<(), String> {
    let parent = path.parent().ok_or("wallet path has no parent")?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("invalid wallet filename")?;
    std::fs::create_dir_all(parent).map_err(|e| format!("creating wallet directory: {e}"))?;
    let bytes = serde_json::to_vec_pretty(wallet).map_err(|e| e.to_string())?;
    atomic_write(parent, name, &bytes)?;
    sync_directory(parent)
}

/// Retire a legacy filename with the same durable rename used for encrypted
/// wallets. A leftover backup is never eligible for automatic re-import.
pub fn finish_legacy_cleanup(legacy: &Path) -> Result<(), String> {
    let backup = legacy.with_extension("migrated");
    if !backup
        .try_exists()
        .map_err(|e| format!("checking legacy backup: {e}"))?
    {
        return Ok(());
    }
    if legacy
        .try_exists()
        .map_err(|e| format!("checking legacy vault: {e}"))?
    {
        return Err(
            "both legacy vault and migration backup exist; files preserved for recovery".into(),
        );
    }
    std::fs::remove_file(&backup).map_err(|e| format!("removing migrated legacy vault: {e}"))?;
    sync_parent(&backup)
}

pub fn retire_legacy(legacy: &Path) -> Result<(), String> {
    let backup = legacy.with_extension("migrated");
    if backup
        .try_exists()
        .map_err(|e| format!("checking legacy backup: {e}"))?
    {
        return Err("legacy migration backup already exists; files preserved".into());
    }
    replace_file(legacy, &backup).map_err(|e| format!("retiring legacy vault: {e}"))?;
    sync_parent(&backup)?;
    finish_legacy_cleanup(legacy)
}

#[derive(Clone, Serialize, Deserialize)]
struct Journal {
    version: u32,
    id: String,
    originals: Vec<Keystore>,
    wallets: Vec<Keystore>,
    checksum: String,
}

#[derive(Debug)]
pub struct RecoveryReport {
    pub used_backup: bool,
}

fn checksum(journal: &Journal) -> Result<String, String> {
    let bytes = serde_json::to_vec(&(
        journal.version,
        &journal.id,
        &journal.originals,
        &journal.wallets,
    ))
    .map_err(|e| e.to_string())?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn new_journal(originals: Vec<Keystore>, wallets: Vec<Keystore>) -> Result<Journal, String> {
    let mut journal = Journal {
        version: 2,
        id: vault::new_wallet_id(),
        originals,
        wallets,
        checksum: String::new(),
    };
    journal.checksum = checksum(&journal)?;
    validate_journal(&journal)?;
    Ok(journal)
}

fn decode_journal(bytes: &[u8]) -> Result<Journal, String> {
    let journal: Journal = serde_json::from_slice(bytes)
        .map_err(|e| format!("invalid password change journal; recovery files retained: {e}"))?;
    validate_journal(&journal)?;
    Ok(journal)
}

fn validate_journal(journal: &Journal) -> Result<(), String> {
    if journal.version != 2 || journal.id.is_empty() {
        return Err("unsupported password change journal; recovery files retained".into());
    }
    validate_replacements(&journal.wallets)?;
    validate_replacements(&journal.originals)?;
    if checksum(journal)? != journal.checksum {
        return Err("password change journal checksum mismatch; recovery files retained".into());
    }
    if journal.originals.len() != journal.wallets.len()
        || journal
            .originals
            .iter()
            .zip(&journal.wallets)
            .any(|(old, new)| old.id != new.id || old.kind != new.kind)
    {
        return Err("password change journal wallet mismatch; recovery files retained".into());
    }
    Ok(())
}

fn same_wallet(left: &Keystore, right: &Keystore) -> Result<bool, String> {
    Ok(serde_json::to_vec(left).map_err(|e| e.to_string())?
        == serde_json::to_vec(right).map_err(|e| e.to_string())?)
}

fn read_wallet_file(directory: &Path, id: &str) -> Result<Option<Keystore>, String> {
    let bytes = match std::fs::read(directory.join(format!("{id}.json"))) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("reading wallet during password change: {error}")),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| format!("invalid wallet during password change; recovery files retained: {e}"))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordResult {
    pub touch_id_enabled: bool,
    pub warning: Option<String>,
}

/// The caller holds the vault I/O lock. The journal rename is the commit point.
/// Both recovery copies hold old/new ENCRYPTED snapshots, never plaintext keys.
pub fn change(
    directory: &Path,
    touch_id_marker: &Path,
    wallets: &[Keystore],
    current: &str,
    new: &str,
    save_touch_id: impl FnOnce(&str) -> Result<(), String>,
) -> Result<ChangePasswordResult, String> {
    recover(directory, touch_id_marker)?;
    let touch_id_enabled = touch_id::read_enabled_marker(touch_id_marker)?;
    // Reject filename/id mismatches or a stale source snapshot before commit.
    // Otherwise rotation could create a second file and leave an old-password
    // copy in the live vault, making the next all-wallet unlock fail.
    for wallet in wallets {
        if wallet.id.is_empty()
            || !wallet
                .id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err("invalid wallet id".into());
        }
        let source = read_wallet_file(directory, &wallet.id)?
            .ok_or("wallet filename does not match its id")?;
        if !same_wallet(&source, wallet)? {
            return Err("wallet changed before password rotation; no files were changed".into());
        }
    }
    let replacements = prepare(wallets, current, new)?;
    let originals = wallets
        .iter()
        .filter(|w| w.kind != "ledger")
        .cloned()
        .collect();
    let journal = new_journal(originals, replacements)?;
    let bytes = serde_json::to_vec(&journal).map_err(|e| e.to_string())?;
    // Two independently flushed copies hold both old and new ciphertext. Read
    // back the backup before publishing the commit record or replacing a wallet.
    atomic_write(directory, BACKUP_FILE, &bytes)?;
    sync_directory(directory)?;
    let saved = std::fs::read(directory.join(BACKUP_FILE)).map_err(|e| e.to_string())?;
    if decode_journal(&saved)?.checksum != journal.checksum {
        return Err("password change backup did not match; wallet files were not changed".into());
    }
    atomic_write(directory, JOURNAL_FILE, &bytes)?;

    // Errors AFTER commit must say the password changed, rather than invite a
    // retry with the old password. Recovery copies remain until wallet bytes
    // have been checked against the prepared, verified snapshots.
    if let Err(error) = recover(directory, touch_id_marker) {
        return Ok(ChangePasswordResult {
            touch_id_enabled: false,
            warning: Some(format!(
                "Password changed; finishing the wallet update failed: {error}"
            )),
        });
    }
    if touch_id_enabled {
        let updated = save_touch_id(new)
            .and_then(|()| touch_id::write_enabled_marker(touch_id_marker))
            .and_then(|()| sync_parent(touch_id_marker));
        if let Err(error) = updated {
            let cleanup = touch_id::remove_enabled_marker(touch_id_marker)
                .and_then(|()| sync_parent(touch_id_marker));
            let detail = match cleanup {
                Ok(()) => error,
                Err(cleanup_error) => {
                    format!("{error}; removing Touch ID setting failed: {cleanup_error}")
                }
            };
            return Ok(ChangePasswordResult {
                touch_id_enabled: false,
                warning: Some(format!(
                    "Password changed; Touch ID needs to be enabled again: {detail}"
                )),
            });
        }
    }
    Ok(ChangePasswordResult {
        touch_id_enabled,
        warning: None,
    })
}

/// Complete a committed change before any vault read or write. No password is
/// needed: the journal already holds every new encrypted keystore.
pub fn recover(directory: &Path, touch_id_marker: &Path) -> Result<RecoveryReport, String> {
    let path = directory.join(JOURNAL_FILE);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("reading password change journal: {error}")),
    };
    let backup_path = directory.join(BACKUP_FILE);
    let mut used_backup = false;
    let journal = match bytes {
        Some(bytes) => match decode_journal(&bytes) {
            Ok(journal) => journal,
            Err(error) => {
                // Repair only from the verified copy of this SAME transaction.
                // An unparseable header or a stale backup must never pick a
                // different password generation or overwrite unrelated wallets.
                let header: serde_json::Value =
                    serde_json::from_slice(&bytes).map_err(|_| error.clone())?;
                let id = header
                    .get("id")
                    .and_then(|id| id.as_str())
                    .ok_or(error.clone())?;
                let backup = std::fs::read(&backup_path)
                    .map_err(|e| format!("{error}; reading recovery copy: {e}"))?;
                let backup = decode_journal(&backup)?;
                if backup.id != id {
                    return Err(format!("{error}; recovery copy belongs to another change"));
                }
                used_backup = true;
                backup
            }
        },
        None => {
            let backup = match std::fs::read(&backup_path) {
                Ok(bytes) => decode_journal(&bytes)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(RecoveryReport { used_backup: false })
                }
                Err(error) => return Err(format!("reading password recovery copy: {error}")),
            };
            let (all_old, all_new) = check_current_wallets(directory, &backup)?;
            if all_old || all_new {
                // A backup alone is either pre-commit, or post-commit cleanup.
                // Both are safe to clean without rewriting any wallet.
                if all_new {
                    touch_id::remove_enabled_marker(touch_id_marker)?;
                    sync_parent(touch_id_marker)?;
                }
                std::fs::remove_file(&backup_path)
                    .map_err(|e| format!("removing password recovery copy: {e}"))?;
                sync_directory(directory)?;
                return Ok(RecoveryReport { used_backup: false });
            }
            used_backup = true;
            backup
        }
    };
    // Stop if a different process or a manual restore changed a wallet to an
    // unrelated value. Preserve that file and BOTH recovery snapshots.
    check_current_wallets(directory, &journal)?;
    // Never replace a healthy copy needlessly: while repairing one copy, keep
    // the other intact until the repaired bytes have been read and checked.
    let repaired_backup = ensure_recovery_copy(directory, BACKUP_FILE, &journal)?;
    let repaired_journal = ensure_recovery_copy(directory, JOURNAL_FILE, &journal)?;
    used_backup |= repaired_backup || repaired_journal;
    sync_directory(directory)?;
    // A crash may leave Keychain holding the old password. Disable its entry
    // point before recovery; a normal change re-enables it after replacing it.
    touch_id::remove_enabled_marker(touch_id_marker)?;
    sync_parent(touch_id_marker)?;
    sync_directory(directory)?;
    for wallet in &journal.wallets {
        let bytes = serde_json::to_vec_pretty(wallet).map_err(|e| e.to_string())?;
        atomic_write(directory, &format!("{}.json", wallet.id), &bytes)?;
    }
    sync_directory(directory)?;
    for expected in &journal.wallets {
        let actual = read_wallet_file(directory, &expected.id)?
            .ok_or("wallet missing after password change")?;
        if !same_wallet(&actual, expected)? {
            return Err("wallet verification failed; encrypted recovery copies retained".into());
        }
    }
    std::fs::remove_file(&path).map_err(|e| format!("removing password change journal: {e}"))?;
    sync_directory(directory)?;
    std::fs::remove_file(&backup_path)
        .map_err(|e| format!("removing password recovery copy: {e}"))?;
    sync_directory(directory)?;
    Ok(RecoveryReport { used_backup })
}

fn check_current_wallets(directory: &Path, journal: &Journal) -> Result<(bool, bool), String> {
    let mut all_old = true;
    let mut all_new = true;
    for (old, new) in journal.originals.iter().zip(&journal.wallets) {
        let (matches_old, matches_new) = match read_wallet_file(directory, &new.id)? {
            Some(current) => (same_wallet(&current, old)?, same_wallet(&current, new)?),
            None => {
                all_old = false;
                all_new = false;
                continue;
            }
        };
        if !matches_old && !matches_new {
            return Err(
                "wallet differs from both password snapshots; recovery files retained".into(),
            );
        }
        all_old &= matches_old;
        all_new &= matches_new;
    }
    Ok((all_old, all_new))
}

fn ensure_recovery_copy(directory: &Path, name: &str, expected: &Journal) -> Result<bool, String> {
    match std::fs::read(directory.join(name)) {
        Ok(bytes) => {
            if let Ok(existing) = decode_journal(&bytes) {
                if existing.id != expected.id || existing.checksum != expected.checksum {
                    return Err("conflicting password recovery copies; files retained".into());
                }
                return Ok(false);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("reading password recovery copy: {error}")),
    }
    let bytes = serde_json::to_vec(expected).map_err(|e| e.to_string())?;
    atomic_write(directory, name, &bytes)?;
    let written = std::fs::read(directory.join(name)).map_err(|e| e.to_string())?;
    if decode_journal(&written)?.checksum != expected.checksum {
        return Err("password recovery copy verification failed; files retained".into());
    }
    sync_directory(directory)?;
    Ok(true)
}

fn validate_replacements(wallets: &[Keystore]) -> Result<(), String> {
    if wallets.is_empty() {
        return Err("password change journal contains no wallets".into());
    }
    let mut ids = std::collections::HashSet::new();
    for wallet in wallets {
        if wallet.id.is_empty()
            || !wallet
                .id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
            || !ids.insert(&wallet.id)
            || !matches!(wallet.kind.as_str(), "hd" | "privkey")
        {
            return Err("invalid wallet in password change journal".into());
        }
    }
    Ok(())
}

fn atomic_write(directory: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    let temporary = directory.join(format!("password-change-{}.tmp", vault::new_wallet_id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|e| format!("staging password change: {e}"))?;
    file.write_all(bytes)
        .map_err(|e| format!("writing password change: {e}"))?;
    file.sync_all()
        .map_err(|e| format!("saving password change: {e}"))?;
    drop(file);
    replace_file(&temporary, &directory.join(name))
        .map_err(|e| format!("committing password change: {e}"))
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::rename(source, destination)
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "Kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(source: *const u16, destination: *const u16, flags: u32) -> i32;
    }
    fn wide(path: &Path) -> std::io::Result<Vec<u16>> {
        let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
        if value.contains(&0) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path contains NUL",
            ));
        }
        value.push(0);
        Ok(value)
    }
    let source = wide(source)?;
    let destination = wide(destination)?;
    // MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH. Both paths are
    // always on the same volume; never emulate atomic replacement by copying.
    let result = unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), 0x1 | 0x8) };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn sync_parent(path: &Path) -> Result<(), String> {
    sync_directory(path.parent().ok_or("password change path has no parent")?)
}

fn sync_directory(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    std::fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|e| format!("saving wallet directory: {e}"))?;
    #[cfg(not(unix))]
    // Windows replacements request WRITE_THROUGH. If cleanup is interrupted,
    // the independently checked remaining recovery copy is processed again.
    let _ = path;
    Ok(())
}

/// Prepare every replacement before touching disk. Secrets never leave Rust.
fn prepare(wallets: &[Keystore], current: &str, new: &str) -> Result<Vec<Keystore>, String> {
    if new.chars().count() < 8 {
        return Err("new password must be at least 8 characters".into());
    }
    if current == new {
        return Err("new password must differ from the current password".into());
    }
    let mut replacements = Vec::new();
    for wallet in wallets {
        match wallet.kind.as_str() {
            "ledger" => continue,
            "hd" | "privkey" => {}
            _ => return Err(format!("unsupported wallet kind {}", wallet.kind)),
        }
        let secret = vault::open(current, wallet)?;
        let mut replacement = vault::seal(new, &secret, &wallet.kind, wallet.accounts.clone())?;
        if vault::open(new, &replacement)?.as_str() != secret.as_str() {
            return Err("new wallet encryption verification failed; no files were changed".into());
        }
        replacement.id = wallet.id.clone();
        replacement.label = wallet.label.clone();
        replacement.created = wallet.created;
        replacements.push(replacement);
    }
    if replacements.is_empty() {
        return Err("no software wallet uses an app password".into());
    }
    Ok(replacements)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{self, AccountMeta};

    const OLD: &str = "old-password";
    const NEW: &str = "new-password";
    const PHRASE: &str = "test test test test test test test test test test test junk";
    const KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    fn software(id: &str, kind: &str, secret: &str) -> vault::Keystore {
        let mut ks = vault::seal(
            OLD,
            secret,
            kind,
            vec![AccountMeta {
                index: 3,
                address: "0x90f79bf6eb2c4f870365e785982e1f101e93b906".into(),
            }],
        )
        .unwrap();
        ks.id = id.into();
        ks.label = format!("Named {id}");
        ks.created = 12345;
        ks
    }

    #[test]
    fn changing_password_reencrypts_every_software_wallet_and_keeps_metadata() {
        let hd = software("seed", "hd", PHRASE);
        let key = software("key", "privkey", KEY);
        let ledger = vault::ledger_keystore("m/44'/60'/0'/0/0", vec![]);
        let changed = prepare(&[hd.clone(), ledger, key.clone()], OLD, NEW).unwrap();
        assert_eq!(changed.len(), 2);
        for (updated, original, secret) in [(&changed[0], &hd, PHRASE), (&changed[1], &key, KEY)] {
            assert_eq!(vault::open(NEW, updated).unwrap().as_str(), secret);
            assert!(vault::open(OLD, updated).is_err());
            assert_eq!(updated.id, original.id);
            assert_eq!(updated.label, original.label);
            assert_eq!(updated.created, original.created);
            assert_eq!(
                serde_json::to_value(&updated.accounts).unwrap(),
                serde_json::to_value(&original.accounts).unwrap()
            );
            assert_eq!(updated.kind, original.kind);
            assert_ne!(updated.salt, original.salt);
            assert_ne!(updated.nonce, original.nonce);
        }
    }

    #[test]
    fn password_change_updates_disk_and_the_enabled_touch_id_credential() {
        let dir =
            std::env::temp_dir().join(format!("autodesktop-password-{}", vault::new_wallet_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("touch-id-enabled");
        crate::touch_id::write_enabled_marker(&marker).unwrap();
        let wallets = vec![
            software("seed", "hd", PHRASE),
            software("key", "privkey", KEY),
        ];
        for wallet in &wallets {
            std::fs::write(
                dir.join(format!("{}.json", wallet.id)),
                serde_json::to_vec(wallet).unwrap(),
            )
            .unwrap();
        }
        let mut saved = String::new();
        let outcome = change(&dir, &marker, &wallets, OLD, NEW, |password| {
            saved = password.to_string();
            Ok(())
        })
        .unwrap();
        assert_eq!(saved, NEW);
        assert!(outcome.touch_id_enabled);
        assert!(outcome.warning.is_none());
        assert!(crate::touch_id::read_enabled_marker(&marker).unwrap());
        for (id, secret) in [("seed", PHRASE), ("key", KEY)] {
            let ks: vault::Keystore =
                serde_json::from_slice(&std::fs::read(dir.join(format!("{id}.json"))).unwrap())
                    .unwrap();
            assert_eq!(vault::open(NEW, &ks).unwrap().as_str(), secret);
            assert!(vault::open(OLD, &ks).is_err());
        }
        assert!(!dir.join(JOURNAL_FILE).exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn directory() -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("autodesktop-password-{}", vault::new_wallet_id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_wallet(dir: &Path, wallet: &Keystore) {
        std::fs::write(
            dir.join(format!("{}.json", wallet.id)),
            serde_json::to_vec(wallet).unwrap(),
        )
        .unwrap();
    }

    fn read_wallet(dir: &Path, id: &str) -> Keystore {
        serde_json::from_slice(&std::fs::read(dir.join(format!("{id}.json"))).unwrap()).unwrap()
    }

    #[test]
    fn wrong_current_password_leaves_every_file_and_touch_id_unchanged() {
        let dir = directory();
        let marker = dir.join("touch-id-enabled");
        touch_id::write_enabled_marker(&marker).unwrap();
        let wallets = vec![
            software("seed", "hd", PHRASE),
            software("key", "privkey", KEY),
        ];
        for wallet in &wallets {
            write_wallet(&dir, wallet);
        }
        let original = std::fs::read(dir.join("seed.json")).unwrap();
        let error = change(&dir, &marker, &wallets, "wrong-password", NEW, |_| {
            panic!("must not update Keychain")
        })
        .err()
        .unwrap();
        assert_eq!(error, "incorrect password");
        assert_eq!(std::fs::read(dir.join("seed.json")).unwrap(), original);
        assert_eq!(
            vault::open(OLD, &read_wallet(&dir, "key"))
                .unwrap()
                .as_str(),
            KEY
        );
        assert!(!dir.join(JOURNAL_FILE).exists());
        assert!(touch_id::read_enabled_marker(&marker).unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_later_undecryptable_wallet_prevents_the_entire_change() {
        let dir = directory();
        let marker = dir.join("touch-id-enabled");
        let good = software("good", "hd", PHRASE);
        let mut bad = software("bad", "privkey", KEY);
        bad.ciphertext = good.ciphertext.clone(); // Valid JSON, invalid authentication tag for this salt/nonce.
        write_wallet(&dir, &good);
        write_wallet(&dir, &bad);
        let original = std::fs::read(dir.join("good.json")).unwrap();
        assert!(change(&dir, &marker, &[good, bad], OLD, NEW, |_| panic!(
            "not enabled"
        ))
        .is_err());
        assert_eq!(std::fs::read(dir.join("good.json")).unwrap(), original);
        assert!(!dir.join(JOURNAL_FILE).exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn interrupted_file_writes_recover_all_wallets_with_the_new_password() {
        let dir = directory();
        let marker = dir.join("touch-id-enabled");
        touch_id::write_enabled_marker(&marker).unwrap();
        let wallets = vec![
            software("seed", "hd", PHRASE),
            software("key", "privkey", KEY),
        ];
        for wallet in &wallets {
            write_wallet(&dir, wallet);
        }
        let journal = new_journal(wallets.clone(), prepare(&wallets, OLD, NEW).unwrap()).unwrap();
        let bytes = serde_json::to_vec(&journal).unwrap();
        atomic_write(&dir, BACKUP_FILE, &bytes).unwrap();
        atomic_write(&dir, JOURNAL_FILE, &bytes).unwrap();
        // Model a crash after replacing the first wallet, followed by a real
        // filesystem error that prevents recovery from replacing the second.
        write_wallet(&dir, &journal.wallets[0]);
        std::fs::remove_file(dir.join("key.json")).unwrap();
        std::fs::create_dir(dir.join("key.json")).unwrap();
        assert!(recover(&dir, &marker).is_err());
        assert!(dir.join(JOURNAL_FILE).exists());
        assert!(dir.join(BACKUP_FILE).exists());
        // The first wallet has already changed; the second write failed.
        assert_eq!(
            vault::open(NEW, &read_wallet(&dir, "seed"))
                .unwrap()
                .as_str(),
            PHRASE
        );
        std::fs::remove_dir(dir.join("key.json")).unwrap();
        recover(&dir, &marker).unwrap();
        for (id, secret) in [("seed", PHRASE), ("key", KEY)] {
            let wallet = read_wallet(&dir, id);
            assert_eq!(vault::open(NEW, &wallet).unwrap().as_str(), secret);
            assert!(vault::open(OLD, &wallet).is_err());
        }
        assert!(!dir.join(JOURNAL_FILE).exists());
        // Recovery is safe to run on every subsequent read.
        recover(&dir, &marker).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn keychain_failure_does_not_roll_back_the_new_password_or_leave_touch_id_enabled() {
        let dir = directory();
        let marker = dir.join("touch-id-enabled");
        touch_id::write_enabled_marker(&marker).unwrap();
        let wallet = software("seed", "hd", PHRASE);
        write_wallet(&dir, &wallet);
        let outcome = change(&dir, &marker, &[wallet], OLD, NEW, |_| {
            Err("Keychain unavailable".into())
        })
        .unwrap();
        assert!(!outcome.touch_id_enabled);
        assert!(outcome.warning.unwrap().contains("Keychain unavailable"));
        assert!(!touch_id::read_enabled_marker(&marker).unwrap());
        let updated = read_wallet(&dir, "seed");
        assert_eq!(vault::open(NEW, &updated).unwrap().as_str(), PHRASE);
        assert!(vault::open(OLD, &updated).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_short_same_and_ledger_only_password_changes() {
        assert_eq!(
            prepare(&[], OLD, "short").unwrap_err(),
            "new password must be at least 8 characters"
        );
        assert_eq!(
            prepare(&[], OLD, OLD).unwrap_err(),
            "new password must differ from the current password"
        );
        let ledger = vault::ledger_keystore("m/44'/60'/0'/0/0", vec![]);
        assert_eq!(
            prepare(&[ledger], OLD, NEW).unwrap_err(),
            "no software wallet uses an app password"
        );
    }

    #[test]
    fn journal_cannot_write_a_wallet_outside_its_directory() {
        let root = directory();
        let dir = root.join("wallets");
        std::fs::create_dir(&dir).unwrap();
        let outside = root.join("outside.json");
        std::fs::write(&outside, b"must not change").unwrap();
        let marker = root.join("touch-id-enabled");
        touch_id::write_enabled_marker(&marker).unwrap();
        let mut wallet = vault::ledger_keystore("m/44'/60'/0'/0/0", vec![]);
        wallet.kind = "hd".into();
        wallet.id = "../outside".into();
        let mut journal = Journal {
            version: 2,
            id: "unsafe-id".into(),
            originals: vec![wallet.clone()],
            wallets: vec![wallet],
            checksum: String::new(),
        };
        journal.checksum = checksum(&journal).unwrap();
        std::fs::write(
            dir.join(JOURNAL_FILE),
            serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        assert!(recover(&dir, &marker)
            .unwrap_err()
            .starts_with("invalid wallet in password change journal"));
        assert_eq!(std::fs::read(&outside).unwrap(), b"must not change");
        assert!(touch_id::read_enabled_marker(&marker).unwrap());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn damaged_journal_must_not_overwrite_the_only_working_wallet() {
        let dir = directory();
        let marker = dir.join("touch-id-enabled");
        let original = software("seed", "hd", PHRASE);
        write_wallet(&dir, &original);
        let bytes_before = std::fs::read(dir.join("seed.json")).unwrap();
        let mut replacements = prepare(&[original], OLD, NEW).unwrap();
        // Valid JSON, but unusable encrypted data: previously recover() accepted
        // this and deleted the only working ciphertext plus its journal.
        replacements[0].ciphertext = Some("broken-ciphertext".into());
        let journal = serde_json::json!({ "version": 1, "wallets": replacements });
        std::fs::write(
            dir.join(JOURNAL_FILE),
            serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        assert!(
            recover(&dir, &marker).is_err(),
            "damaged ciphertext was accepted"
        );
        assert_eq!(std::fs::read(dir.join("seed.json")).unwrap(), bytes_before);
        assert_eq!(
            vault::open(OLD, &read_wallet(&dir, "seed"))
                .unwrap()
                .as_str(),
            PHRASE
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn stage_test_journal(dir: &Path, wallets: &[Keystore]) -> Journal {
        let journal = new_journal(wallets.to_vec(), prepare(wallets, OLD, NEW).unwrap()).unwrap();
        let bytes = serde_json::to_vec(&journal).unwrap();
        atomic_write(dir, BACKUP_FILE, &bytes).unwrap();
        atomic_write(dir, JOURNAL_FILE, &bytes).unwrap();
        sync_directory(dir).unwrap();
        journal
    }

    #[test]
    fn valid_json_corruption_is_repaired_from_the_matching_verified_copy() {
        let dir = directory();
        let marker = dir.join("touch-id-enabled");
        let originals = vec![
            software("seed", "hd", PHRASE),
            software("key", "privkey", KEY),
        ];
        for wallet in &originals {
            write_wallet(&dir, wallet);
        }
        let journal = stage_test_journal(&dir, &originals);
        write_wallet(&dir, &journal.wallets[0]); // Partial commit before a crash.
        let mut damaged = journal.clone();
        damaged.wallets[1].ciphertext = Some("damaged-but-valid-JSON".into());
        std::fs::write(
            dir.join(JOURNAL_FILE),
            serde_json::to_vec(&damaged).unwrap(),
        )
        .unwrap();
        assert!(recover(&dir, &marker).unwrap().used_backup);
        assert_eq!(
            vault::open(NEW, &read_wallet(&dir, "seed"))
                .unwrap()
                .as_str(),
            PHRASE
        );
        assert_eq!(
            vault::open(NEW, &read_wallet(&dir, "key"))
                .unwrap()
                .as_str(),
            KEY
        );
        assert!(!dir.join(JOURNAL_FILE).exists());
        assert!(!dir.join(BACKUP_FILE).exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn damage_to_both_recovery_copies_stops_before_overwriting_wallets() {
        let dir = directory();
        let marker = dir.join("touch-id-enabled");
        let wallet = software("seed", "hd", PHRASE);
        write_wallet(&dir, &wallet);
        let before = std::fs::read(dir.join("seed.json")).unwrap();
        let mut journal = stage_test_journal(&dir, &[wallet]);
        journal.wallets[0].ciphertext = Some("broken".into());
        let broken = serde_json::to_vec(&journal).unwrap();
        std::fs::write(dir.join(JOURNAL_FILE), &broken).unwrap();
        std::fs::write(dir.join(BACKUP_FILE), &broken).unwrap();
        assert!(recover(&dir, &marker)
            .unwrap_err()
            .contains("checksum mismatch"));
        assert_eq!(std::fs::read(dir.join("seed.json")).unwrap(), before);
        assert_eq!(
            vault::open(OLD, &read_wallet(&dir, "seed"))
                .unwrap()
                .as_str(),
            PHRASE
        );
        assert!(dir.join(JOURNAL_FILE).exists() && dir.join(BACKUP_FILE).exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_commit_record_recovers_a_partially_written_generation() {
        let dir = directory();
        let marker = dir.join("touch-id-enabled");
        let originals = vec![
            software("seed", "hd", PHRASE),
            software("key", "privkey", KEY),
        ];
        for wallet in &originals {
            write_wallet(&dir, wallet);
        }
        let journal = stage_test_journal(&dir, &originals);
        write_wallet(&dir, &journal.wallets[0]);
        std::fs::remove_file(dir.join(JOURNAL_FILE)).unwrap();
        assert!(recover(&dir, &marker).unwrap().used_backup);
        assert_eq!(
            vault::open(NEW, &read_wallet(&dir, "seed"))
                .unwrap()
                .as_str(),
            PHRASE
        );
        assert_eq!(
            vault::open(NEW, &read_wallet(&dir, "key"))
                .unwrap()
                .as_str(),
            KEY
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn wrong_filename_or_stale_snapshot_cannot_create_mixed_password_files() {
        let dir = directory();
        let marker = dir.join("touch-id-enabled");
        let wallet = software("seed", "hd", PHRASE);
        write_wallet(&dir, &wallet);
        std::fs::rename(dir.join("seed.json"), dir.join("renamed-file.json")).unwrap();
        let before = std::fs::read(dir.join("renamed-file.json")).unwrap();
        assert!(change(&dir, &marker, &[wallet], OLD, NEW, |_| panic!(
            "not enabled"
        ))
        .is_err());
        assert_eq!(
            std::fs::read(dir.join("renamed-file.json")).unwrap(),
            before
        );
        assert!(!dir.join("seed.json").exists());
        assert!(!dir.join(JOURNAL_FILE).exists() && !dir.join(BACKUP_FILE).exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn filesystem_lock_excludes_an_independent_file_handle() {
        let dir = directory();
        let first = lock_directory(&dir).unwrap();
        let second = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.join(LOCK_FILE))
            .unwrap();
        assert!(matches!(
            second.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        drop(first);
        second.try_lock().unwrap();
        drop(second);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
