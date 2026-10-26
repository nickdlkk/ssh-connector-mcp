//! Encrypted credential vault.
//!
//! Security model (design doc §6.1/§6.2):
//! - Master password -> Argon2id -> 32-byte key-encryption-key (KEK).
//! - A random 32-byte data-encryption-key (DEK) is generated on init and stored
//!   encrypted under the KEK. The DEK never touches disk in plaintext.
//! - Each credential field is sealed with XChaCha20Poly1305 under the DEK with a
//!   fresh random 24-byte nonce.
//! - Plaintext secrets exist only in memory and are wrapped in `Zeroizing`.
//! - AI-facing reads always go through redaction; only an explicit
//!   master-password-gated reveal returns plaintext.

use crate::error::{ConnectorError, ErrorCode, Result};
use crate::types::{AuthMethod, BecomeRootConfig, HostConfig, HostSpec, JumpHop};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rusqlite::{Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;
use zeroize::Zeroizing;

const DEK_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).map_err(|e| ConnectorError::internal(format!("rng: {e}")))?;
    Ok(buf)
}

fn argon2() -> Argon2<'static> {
    // OWASP-recommended-ish defaults from the crate (19 MiB, t=2, p=1).
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::DEFAULT)
}

/// Derive the 32-byte KEK from the master password and salt.
fn derive_kek(master_password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut kek = Zeroizing::new([0u8; 32]);
    argon2()
        .hash_password_into(master_password.as_bytes(), salt, kek.as_mut_slice())
        .map_err(|e| ConnectorError::internal(format!("argon2: {e}")))?;
    Ok(kek)
}

fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce_bytes = random_bytes(NONCE_LEN)?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let mut ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| ConnectorError::internal("seal failed"))?;
    // Store nonce || ciphertext.
    let mut out = nonce_bytes;
    out.append(&mut ct);
    Ok(out)
}

fn open(key: &[u8; 32], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < NONCE_LEN {
        return Err(ConnectorError::internal("ciphertext too short"));
    }
    let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(nonce_bytes);
    let pt = cipher.decrypt(nonce, ct).map_err(|_| {
        ConnectorError::new(
            ErrorCode::VaultBadPassword,
            "decryption failed (wrong key or corrupted vault)",
        )
    })?;
    Ok(Zeroizing::new(pt))
}

/// Holds the decrypted DEK while unlocked. Dropped (and zeroized) on lock.
struct Unlocked {
    dek: Zeroizing<[u8; 32]>,
}

pub struct Vault {
    conn: Mutex<Connection>,
    unlocked: Mutex<Option<Unlocked>>,
}

impl Vault {
    /// Open (or create) the vault database at `path`. Does not unlock.
    pub fn open(path: &Path) -> Result<Vault> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS vault_meta (
                 id INTEGER PRIMARY KEY CHECK (id = 1),
                 salt BLOB NOT NULL,
                 dek_wrapped BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS hosts (
                 id TEXT PRIMARY KEY,
                 alias TEXT NOT NULL,
                 host TEXT NOT NULL,
                 port INTEGER NOT NULL,
                 user TEXT NOT NULL,
                 -- encrypted JSON of the full HostConfig (secrets included)
                 sealed BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS host_keys (
                 host TEXT NOT NULL,
                 port INTEGER NOT NULL,
                 fingerprint TEXT NOT NULL,
                 PRIMARY KEY (host, port)
             );",
        )?;
        Ok(Vault {
            conn: Mutex::new(conn),
            unlocked: Mutex::new(None),
        })
    }

    fn lock_conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn is_initialized(&self) -> Result<bool> {
        let conn = self.lock_conn();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM vault_meta", [], |r| r.get(0))?;
        Ok(n > 0)
    }

    pub fn is_unlocked(&self) -> bool {
        self.unlocked.lock().map(|g| g.is_some()).unwrap_or(false)
    }

    /// First-run: create the vault with a master password. Generates salt + DEK.
    pub fn init(&self, master_password: &str) -> Result<()> {
        if self.is_initialized()? {
            return Err(ConnectorError::new(
                ErrorCode::VaultAlreadyInit,
                "vault already initialized",
            ));
        }
        let salt = random_bytes(SALT_LEN)?;
        let kek = derive_kek(master_password, &salt)?;
        let dek = random_bytes(DEK_LEN)?;
        let dek_wrapped = seal(&kek, &dek)?;
        {
            let conn = self.lock_conn();
            conn.execute(
                "INSERT INTO vault_meta (id, salt, dek_wrapped) VALUES (1, ?1, ?2)",
                rusqlite::params![salt, dek_wrapped],
            )?;
        }
        // Unlock immediately after init.
        let mut dek_arr = Zeroizing::new([0u8; 32]);
        dek_arr.copy_from_slice(&dek);
        *self.unlocked.lock().unwrap_or_else(|p| p.into_inner()) = Some(Unlocked { dek: dek_arr });
        Ok(())
    }

    /// Unlock with the master password: derive KEK, decrypt DEK, hold in memory.
    pub fn unlock(&self, master_password: &str) -> Result<()> {
        let (salt, dek_wrapped): (Vec<u8>, Vec<u8>) = {
            let conn = self.lock_conn();
            conn.query_row(
                "SELECT salt, dek_wrapped FROM vault_meta WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| {
                ConnectorError::new(ErrorCode::VaultBadPassword, "vault not initialized")
            })?
        };
        let kek = derive_kek(master_password, &salt)?;
        let dek = open(&kek, &dek_wrapped)?; // VaultBadPassword on wrong pw
        if dek.len() != DEK_LEN {
            return Err(ConnectorError::internal("corrupt DEK length"));
        }
        let mut dek_arr = Zeroizing::new([0u8; 32]);
        dek_arr.copy_from_slice(&dek);
        *self.unlocked.lock().unwrap_or_else(|p| p.into_inner()) = Some(Unlocked { dek: dek_arr });
        Ok(())
    }

    pub fn unlock_with_totp(&self, totp: &crate::totp::Totp, code:&str) -> Result<()> {
        totp.verify(code)?;
        let dek=totp.unwrap_dek()?;
        self.unlock_with_dek(&dek)
    }

    pub fn unlock_with_master_password(&self, master_password: &str) -> Result<()> {
        self.unlock(master_password)
    }

    pub fn unlock_with_dek(&self, dek: &[u8]) -> Result<()> {
        if dek.len()!=DEK_LEN{return Err(ConnectorError::internal("corrupt DEK length"));}
        let mut dek_arr=Zeroizing::new([0u8;32]);dek_arr.copy_from_slice(dek);
        *self.unlocked.lock().unwrap_or_else(|p|p.into_inner())=Some(Unlocked{dek:dek_arr});Ok(())
    }

    /// Forget the in-memory DEK.
    pub fn lock(&self) {
        *self.unlocked.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }

    /// Run a closure with the live DEK, or fail if locked.
    fn with_dek<T>(&self, f: impl FnOnce(&[u8; 32]) -> Result<T>) -> Result<T> {
        let guard = self.unlocked.lock().unwrap_or_else(|p| p.into_inner());
        match guard.as_ref() {
            Some(u) => f(&u.dek),
            None => Err(ConnectorError::locked()),
        }
    }

    pub fn current_dek(&self) -> Result<Zeroizing<[u8;32]>> {
        let guard=self.unlocked.lock().unwrap_or_else(|p|p.into_inner());
        guard.as_ref().map(|u|Zeroizing::new(*u.dek)).ok_or_else(ConnectorError::locked)
    }

    pub fn verify_master_password(&self, master_password: &str) -> Result<Zeroizing<[u8;32]>> {
        let (salt, dek_wrapped): (Vec<u8>, Vec<u8>) = {
            let conn = self.lock_conn();
            conn.query_row(
                "SELECT salt, dek_wrapped FROM vault_meta WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?
        };
        let kek = derive_kek(master_password, &salt)?;
        let dek=open(&kek, &dek_wrapped)?;
        if dek.len()!=DEK_LEN{return Err(ConnectorError::internal("corrupt DEK length"));}
        let mut out=Zeroizing::new([0u8;32]);out.copy_from_slice(&dek);Ok(out)
    }

    fn gen_id() -> Result<String> {
        let b = random_bytes(8)?;
        Ok(b.iter().map(|x| format!("{x:02x}")).collect())
    }

    /// Insert a new host, returning its assigned id.
    pub fn add_host(&self, spec: HostSpec) -> Result<String> {
        let id = Self::gen_id()?;
        let cfg = HostConfig {
            id: id.clone(),
            alias: spec.alias,
            host: spec.host,
            port: spec.port,
            user: spec.user,
            auth: spec.auth,
            jump_hosts: spec.jump_hosts,
            env: spec.env,
            become_root: spec.become_root,
        };
        self.persist_host(&cfg)?;
        Ok(id)
    }

    /// Overwrite an existing host wholesale (AI may write new secrets here).
    pub fn update_host(&self, id: &str, spec: HostSpec) -> Result<()> {
        // Ensure it exists.
        let existing = self.get_host_config(id)?;
        let cfg = HostConfig {
            id: id.to_string(),
            alias: spec.alias,
            host: spec.host,
            port: spec.port,
            user: spec.user,
            auth: merge_auth(existing.auth, spec.auth),
            jump_hosts: merge_jump_hosts(existing.jump_hosts, spec.jump_hosts),
            env: spec.env,
            become_root: merge_become_root(existing.become_root, spec.become_root),
        };
        self.persist_host(&cfg)
    }

    fn persist_host(&self, cfg: &HostConfig) -> Result<()> {
        let json = serde_json::to_vec(cfg)
            .map_err(|e| ConnectorError::internal(format!("serialize host: {e}")))?;
        let sealed = self.with_dek(|dek| seal(dek, &json))?;
        let conn = self.lock_conn();
        conn.execute(
            "INSERT INTO hosts (id, alias, host, port, user, sealed) VALUES (?1,?2,?3,?4,?5,?6)
             ON CONFLICT(id) DO UPDATE SET alias=?2, host=?3, port=?4, user=?5, sealed=?6",
            rusqlite::params![cfg.id, cfg.alias, cfg.host, cfg.port, cfg.user, sealed],
        )?;
        Ok(())
    }

    pub fn remove_host(&self, id: &str) -> Result<()> {
        let conn = self.lock_conn();
        let n = conn.execute("DELETE FROM hosts WHERE id = ?1", rusqlite::params![id])?;
        if n == 0 {
            return Err(ConnectorError::host_not_found(id));
        }
        Ok(())
    }

    /// Full host config WITH plaintext secrets. Internal/connection use and the
    /// master-password-gated reveal only — never hand this to AI directly.
    pub fn get_host_config(&self, id: &str) -> Result<HostConfig> {
        let sealed: Vec<u8> = {
            let conn = self.lock_conn();
            conn.query_row(
                "SELECT sealed FROM hosts WHERE id = ?1",
                rusqlite::params![id],
                |r| r.get(0),
            )
            .optional()?
            .ok_or_else(|| ConnectorError::host_not_found(id))?
        };
        let json = self.with_dek(|dek| open(dek, &sealed))?;
        let cfg: HostConfig = serde_json::from_slice(&json)
            .map_err(|e| ConnectorError::internal(format!("deserialize host: {e}")))?;
        Ok(cfg)
    }

    /// All host configs (plaintext); callers redact before exposing to AI.
    pub fn list_host_configs(&self) -> Result<Vec<HostConfig>> {
        let ids: Vec<String> = {
            let conn = self.lock_conn();
            let mut stmt = conn.prepare("SELECT id FROM hosts ORDER BY alias")?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            out.push(self.get_host_config(&id)?);
        }
        Ok(out)
    }

    /// Reveal plaintext credentials, gated on the master password (human only).
    pub fn reveal_credentials(
        &self,
        id: &str,
        master_password: &str,
    ) -> Result<(AuthMethod, Vec<JumpHop>)> {
        self.verify_master_password(master_password)?;
        let cfg = self.get_host_config(id)?;
        Ok((cfg.auth, cfg.jump_hosts))
    }

    // --- Host key TOFU ---

    /// Returns the recorded fingerprint for a host:port, if any.
    pub fn get_host_key(&self, host: &str, port: u16) -> Result<Option<String>> {
        let conn = self.lock_conn();
        let fp: Option<String> = conn
            .query_row(
                "SELECT fingerprint FROM host_keys WHERE host = ?1 AND port = ?2",
                rusqlite::params![host, port],
                |r| r.get(0),
            )
            .optional()?;
        Ok(fp)
    }

    /// Record a fingerprint on first use (TOFU).
    pub fn record_host_key(&self, host: &str, port: u16, fingerprint: &str) -> Result<()> {
        let conn = self.lock_conn();
        conn.execute(
            "INSERT INTO host_keys (host, port, fingerprint) VALUES (?1,?2,?3)
             ON CONFLICT(host, port) DO NOTHING",
            rusqlite::params![host, port, fingerprint],
        )?;
        Ok(())
    }
}

fn merge_auth(existing: AuthMethod, incoming: AuthMethod) -> AuthMethod {
    match (&existing, &incoming) {
        (AuthMethod::Password { .. }, AuthMethod::Password { password })
            if password == "***" || password.is_empty() =>
        {
            existing
        }
        (
            AuthMethod::PrivateKey { .. },
            AuthMethod::PrivateKey {
                key_pem,
                passphrase,
            },
        ) if key_pem == "***" || key_pem.is_empty() => match (existing, passphrase.as_deref()) {
            (
                AuthMethod::PrivateKey {
                    key_pem,
                    passphrase: old_passphrase,
                },
                Some("***") | None | Some(""),
            ) => AuthMethod::PrivateKey {
                key_pem,
                passphrase: old_passphrase,
            },
            (AuthMethod::PrivateKey { key_pem, .. }, Some(new_passphrase)) => {
                AuthMethod::PrivateKey {
                    key_pem,
                    passphrase: Some(new_passphrase.to_string()),
                }
            }
            (other, _) => other,
        },
        (AuthMethod::KeyboardInteractive { .. }, AuthMethod::KeyboardInteractive { answers })
            if answers.is_empty() || answers.iter().all(|a| a == "***") =>
        {
            existing
        }
        _ => incoming,
    }
}

fn merge_jump_hosts(existing: Vec<JumpHop>, incoming: Vec<JumpHop>) -> Vec<JumpHop> {
    incoming
        .into_iter()
        .enumerate()
        .map(|(idx, mut hop)| {
            if let Some(old) = existing.get(idx) {
                hop.auth = merge_auth(old.auth.clone(), hop.auth);
            }
            hop
        })
        .collect()
}

fn merge_become_root(
    existing: Option<BecomeRootConfig>,
    incoming: Option<BecomeRootConfig>,
) -> Option<BecomeRootConfig> {
    match (existing, incoming) {
        (Some(old), Some(mut new)) if new.password == "***" || new.password.is_empty() => {
            new.password = old.password;
            Some(new)
        }
        (_, new) => new,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuthMethod, BecomeRootConfig};

    fn temp_vault() -> Vault {
        let dir =
            std::env::temp_dir().join(format!("vault-test-{}", super::Vault::gen_id().unwrap()));
        std::fs::create_dir_all(&dir).unwrap();
        Vault::open(&dir.join("vault.db")).unwrap()
    }

    #[test]
    fn init_unlock_roundtrip() {
        let v = temp_vault();
        assert!(!v.is_initialized().unwrap());
        v.init("hunter2").unwrap();
        assert!(v.is_initialized().unwrap());
        assert!(v.is_unlocked());
        v.lock();
        assert!(!v.is_unlocked());
        v.unlock("hunter2").unwrap();
        assert!(v.is_unlocked());
    }

    #[test]
    fn wrong_password_rejected() {
        let v = temp_vault();
        v.init("correct").unwrap();
        v.lock();
        let err = v.unlock("wrong").unwrap_err();
        assert_eq!(err.code, ErrorCode::VaultBadPassword);
        assert!(!v.is_unlocked());
    }

    #[test]
    fn host_crud_and_secret_seal() {
        let v = temp_vault();
        v.init("pw").unwrap();
        let spec = HostSpec {
            alias: "box1".into(),
            host: "1.2.3.4".into(),
            port: 22,
            user: "root".into(),
            auth: AuthMethod::Password {
                password: "s3cr3t".into(),
            },
            jump_hosts: vec![],
            env: Default::default(),
            become_root: None,
        };
        let id = v.add_host(spec).unwrap();
        let cfg = v.get_host_config(&id).unwrap();
        match &cfg.auth {
            AuthMethod::Password { password } => assert_eq!(password, "s3cr3t"),
            _ => panic!("wrong auth"),
        }
        // redaction hides the secret
        let red = cfg.redacted();
        match red.auth {
            AuthMethod::Password { password } => assert_eq!(password, "***"),
            _ => panic!(),
        }
        // reveal requires correct master password
        assert!(v.reveal_credentials(&id, "nope").is_err());
        let (auth, _) = v.reveal_credentials(&id, "pw").unwrap();
        matches!(auth, AuthMethod::Password { .. });

        v.remove_host(&id).unwrap();
        assert_eq!(
            v.get_host_config(&id).unwrap_err().code,
            ErrorCode::HostNotFound
        );
    }

    #[test]
    fn update_host_keeps_redacted_secrets_and_become_root_password() {
        let v = temp_vault();
        v.init("pw").unwrap();
        let id = v
            .add_host(HostSpec {
                alias: "box1".into(),
                host: "1.2.3.4".into(),
                port: 22,
                user: "ubuntu".into(),
                auth: AuthMethod::Password {
                    password: "ssh-secret".into(),
                },
                jump_hosts: vec![],
                env: Default::default(),
                become_root: Some(BecomeRootConfig {
                    enabled: true,
                    command: "su -".into(),
                    password: "root-secret".into(),
                    prompt_timeout_ms: 5000,
                }),
            })
            .unwrap();

        v.update_host(
            &id,
            HostSpec {
                alias: "renamed".into(),
                host: "1.2.3.4".into(),
                port: 22,
                user: "ubuntu".into(),
                auth: AuthMethod::Password {
                    password: "***".into(),
                },
                jump_hosts: vec![],
                env: Default::default(),
                become_root: Some(BecomeRootConfig {
                    enabled: true,
                    command: "su -".into(),
                    password: "***".into(),
                    prompt_timeout_ms: 9000,
                }),
            },
        )
        .unwrap();

        let cfg = v.get_host_config(&id).unwrap();
        match cfg.auth {
            AuthMethod::Password { password } => assert_eq!(password, "ssh-secret"),
            _ => panic!("wrong auth"),
        }
        let become_root = cfg.become_root.unwrap();
        assert_eq!(become_root.password, "root-secret");
        assert_eq!(become_root.prompt_timeout_ms, 9000);
    }

    #[test]
    fn locked_vault_refuses_host_ops() {
        let v = temp_vault();
        v.init("pw").unwrap();
        v.lock();
        let spec = HostSpec {
            alias: "x".into(),
            host: "h".into(),
            port: 22,
            user: "u".into(),
            auth: AuthMethod::Password {
                password: "p".into(),
            },
            jump_hosts: vec![],
            env: Default::default(),
            become_root: None,
        };
        assert_eq!(v.add_host(spec).unwrap_err().code, ErrorCode::VaultLocked);
    }

    #[test]
    fn host_key_tofu() {
        let v = temp_vault();
        v.init("pw").unwrap();
        assert!(v.get_host_key("h", 22).unwrap().is_none());
        v.record_host_key("h", 22, "SHA256:abc").unwrap();
        assert_eq!(v.get_host_key("h", 22).unwrap().unwrap(), "SHA256:abc");
        // second record is ignored (TOFU keeps first)
        v.record_host_key("h", 22, "SHA256:different").unwrap();
        assert_eq!(v.get_host_key("h", 22).unwrap().unwrap(), "SHA256:abc");
    }
}
