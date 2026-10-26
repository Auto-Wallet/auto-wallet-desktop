use crate::touch_id;
use crate::vault::{self, Keystore};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;

const JOURNAL_FILE: &str = "password-change.pending";

#[derive(Serialize, Deserialize)]
struct Journal {
    version: u32,
    wallets: Vec<Keystore>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordResult {
    pub touch_id_enabled: bool,
    pub warning: Option<String>,
}

/// The caller holds the vault I/O lock. The journal rename is the commit point:
/// it contains only NEW ciphertext and lets startup finish every interrupted write.
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
    let replacements = prepare(wallets, current, new)?;
    validate_replacements(&replacements)?;
    let journal = Journal {
        version: 1,
        wallets: replacements,
    };
    let bytes = serde_json::to_vec(&journal).map_err(|e| e.to_string())?;
    atomic_write(directory, JOURNAL_FILE, &bytes)?;

    // Errors AFTER commit must say the password changed, rather than invite a
    // retry with the old password. The durable journal remains for recovery.
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
pub fn recover(directory: &Path, touch_id_marker: &Path) -> Result<(), String> {
    let path = directory.join(JOURNAL_FILE);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("reading password change journal: {error}")),
    };
    let journal: Journal = serde_json::from_slice(&bytes)
        .map_err(|e| format!("invalid password change journal: {e}"))?;
    if journal.version != 1 {
        return Err("unsupported password change journal version".into());
    }
    validate_replacements(&journal.wallets)?;
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
    std::fs::remove_file(&path).map_err(|e| format!("removing password change journal: {e}"))?;
    sync_directory(directory)
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
    std::fs::rename(&temporary, directory.join(name))
        .map_err(|e| format!("committing password change: {e}"))
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
        // A directory at the target path makes a real rename fail after commit.
        std::fs::remove_file(dir.join("key.json")).unwrap();
        std::fs::create_dir(dir.join("key.json")).unwrap();
        let outcome = change(&dir, &marker, &wallets, OLD, NEW, |_| {
            panic!("cannot enable Touch ID during recovery")
        })
        .unwrap();
        assert!(outcome.warning.unwrap().contains("Password changed"));
        assert!(!outcome.touch_id_enabled);
        assert!(dir.join(JOURNAL_FILE).exists());
        assert!(!touch_id::read_enabled_marker(&marker).unwrap());
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
        let dir = directory();
        let marker = dir.join("touch-id-enabled");
        touch_id::write_enabled_marker(&marker).unwrap();
        let mut wallet = vault::ledger_keystore("m/44'/60'/0'/0/0", vec![]);
        wallet.kind = "hd".into();
        wallet.id = "../outside".into();
        let journal = Journal {
            version: 1,
            wallets: vec![wallet],
        };
        std::fs::write(
            dir.join(JOURNAL_FILE),
            serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        assert_eq!(
            recover(&dir, &marker).unwrap_err(),
            "invalid wallet in password change journal"
        );
        assert!(touch_id::read_enabled_marker(&marker).unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
