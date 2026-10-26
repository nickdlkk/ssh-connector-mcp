//! RFC 6238 TOTP and independent secret wrapping-key management.
use crate::error::{ConnectorError, Result};
use chacha20poly1305::{XChaCha20Poly1305, XNonce, aead::{Aead, KeyInit}};
use hmac::{Hmac, Mac};
use rusqlite::OptionalExtension;
use sha1::Sha1;
use std::{fs::{self, OpenOptions}, io::Write, os::unix::fs::{OpenOptionsExt, PermissionsExt}, path::{Path, PathBuf}, sync::Mutex, time::{SystemTime, UNIX_EPOCH}};
use zeroize::Zeroizing;

type HmacSha1 = Hmac<Sha1>;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const STEP: u64 = 30;
const DIGITS: u32 = 6;

pub struct Totp {
    conn: Mutex<rusqlite::Connection>,
    key: Zeroizing<[u8; KEY_LEN]>,
    pending: Mutex<Option<PendingEnrollment>>,
    fail_count: Mutex<u32>,
    locked_until: Mutex<u64>,
}

struct PendingEnrollment {
    seed_b32: Zeroizing<String>,
    expires_at: u64,
    dek: Zeroizing<[u8; 32]>,
    replacing: bool,
}

impl Totp {
    pub fn open(db_path: &Path, key_path: PathBuf) -> Result<Self> {
        let conn = rusqlite::Connection::open(db_path)?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS vault_totp (id INTEGER PRIMARY KEY CHECK(id=1), seed_wrapped BLOB NOT NULL, dek_wrapped BLOB, last_step INTEGER NOT NULL DEFAULT -1);
             CREATE TABLE IF NOT EXISTS vault_totp_meta (id INTEGER PRIMARY KEY CHECK(id=1), enabled INTEGER NOT NULL DEFAULT 0, last_step INTEGER NOT NULL DEFAULT -1);
             INSERT OR IGNORE INTO vault_totp_meta(id,enabled,last_step) VALUES(1,0,-1);")?;
        let enabled: i64 = conn.query_row("SELECT enabled FROM vault_totp_meta WHERE id=1", [], |r| r.get(0)).optional()?.unwrap_or(0);
        if enabled != 0 {
            let metadata=fs::symlink_metadata(&key_path).map_err(|_|ConnectorError::new(crate::error::ErrorCode::TotpUnavailable,"TOTP key unavailable"))?;
            if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.permissions().mode() & 0o077 != 0 {
                return Err(ConnectorError::new(crate::error::ErrorCode::TotpUnavailable,"TOTP key unavailable"));
            }
        }
        let key = load_or_create_key(&key_path)?;
        Ok(Self { conn: Mutex::new(conn), key: Zeroizing::new(key), fail_count: Mutex::new(0), locked_until: Mutex::new(0), pending: Mutex::new(None) })
    }
    pub fn enabled(&self) -> Result<bool> {
        let enabled:i64=self.conn.lock().unwrap_or_else(|e|e.into_inner()).query_row("SELECT enabled FROM vault_totp_meta WHERE id=1",[],|r|r.get(0)).optional()?.unwrap_or(0);
        Ok(enabled != 0)
    }
    pub fn start_enrollment(&self, dek:&[u8;32]) -> Result<(String, String)> {
        self.start_pending(dek, false)
    }
    pub fn start_replacement(&self, dek:&[u8;32]) -> Result<(String, String)> {
        if !self.enabled()? { return Err(ConnectorError::bad_request("TOTP is not configured")); }
        self.start_pending(dek, true)
    }
    fn start_pending(&self, dek:&[u8;32], replacing:bool) -> Result<(String, String)> {
        let mut seed = Zeroizing::new(vec![0u8; 20]);
        getrandom::fill(&mut seed).map_err(|e| ConnectorError::internal(format!("rng: {e}")))?;
        let secret = base32_encode(&seed);
        let uri = format!("otpauth://totp/SSH-Connector:Vault?secret={secret}&issuer=SSH-Connector&algorithm=SHA1&digits=6&period=30");
        *self.pending.lock().unwrap_or_else(|e|e.into_inner())=Some(PendingEnrollment {
            seed_b32: Zeroizing::new(secret.clone()),
            expires_at: unix_time()? + 300,
            dek: Zeroizing::new(*dek),
            replacing,
        });
        Ok((secret, uri))
    }
    pub fn confirm_pending(&self, code:&str, dek:&[u8;32])->Result<()> {
        self.confirm_pending_inner(code, dek, None)
    }
    pub fn confirm_pending_mode(&self, code:&str, dek:&[u8;32], expected_replacing:bool)->Result<()> {
        self.confirm_pending_inner(code, dek, Some(expected_replacing))
    }
    fn confirm_pending_inner(&self, code:&str, dek:&[u8;32], expected_replacing:Option<bool>)->Result<()> {
        let mut guard = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let pending = guard.as_ref().ok_or_else(|| ConnectorError::bad_request("invalid enrollment"))?;
        if unix_time()? > pending.expires_at {
            *guard = None;
            return Err(ConnectorError::bad_request("invalid enrollment"));
        }
        let now = unix_time()?;
        if now < *self.locked_until.lock().unwrap_or_else(|e| e.into_inner()) {
            return Err(ConnectorError::bad_request("invalid code"));
        }
        if !constant_time_equal(pending.dek.as_ref(), dek) {
            return Err(ConnectorError::new(crate::error::ErrorCode::VaultBadPassword, "secondary authentication failed"));
        }
        if expected_replacing.is_some_and(|expected| expected != pending.replacing) {
            return Err(ConnectorError::bad_request("enrollment action mismatch"));
        }
        let result = self.confirm_enrollment_mode(&pending.seed_b32, code, dek, pending.replacing);
        if result.is_ok() { *guard = None; }
        else { self.failed(now); }
        result
    }
    pub fn confirm_enrollment(&self, seed_b32: &str, code: &str, dek: &[u8;32]) -> Result<()> {
        self.confirm_enrollment_mode(seed_b32, code, dek, false)
    }
    fn confirm_enrollment_mode(&self, seed_b32:&str, code:&str, dek:&[u8;32], replacing:bool)->Result<()> {
        self.confirm_enrollment_at(seed_b32, code, dek, unix_time()? / STEP, replacing)
    }
    fn confirm_enrollment_at(&self, seed_b32:&str, code:&str, dek:&[u8;32], current:u64, replacing:bool)->Result<()> {
        self.confirm_enrollment_at_inner(seed_b32,code,dek,current,replacing)
    }
    fn confirm_enrollment_at_inner(&self, seed_b32:&str, code:&str, dek:&[u8;32], current:u64, replacing:bool)->Result<()> {
        let seed = Zeroizing::new(base32_decode(seed_b32).ok_or_else(|| ConnectorError::bad_request("invalid enrollment"))?);
        let step=self.match_step(&seed,code,current).ok_or_else(||ConnectorError::bad_request("invalid code"))?;
        if step != current { return Err(ConnectorError::bad_request("invalid code")); }
        if self.enabled()? != replacing { return Err(ConnectorError::bad_request("TOTP configuration changed; restart enrollment")); }
        let seed_nonce=nonce()?;
        let blob={let mut value=seed_nonce.to_vec();value.extend(XChaCha20Poly1305::new((&*self.key).into()).encrypt(XNonce::from_slice(&seed_nonce),seed.as_slice()).map_err(|_|ConnectorError::internal("TOTP encryption failed"))?);value};
        let conn=self.conn.lock().unwrap_or_else(|e|e.into_inner());
        let tx=conn.unchecked_transaction()?;
        let dek_nonce=nonce()?;
        let wrapped={let mut value=dek_nonce.to_vec();value.extend(XChaCha20Poly1305::new((&*self.key).into()).encrypt(XNonce::from_slice(&dek_nonce),dek.as_slice()).map_err(|_|ConnectorError::internal("TOTP DEK wrapping failed"))?);value};
        tx.execute("INSERT INTO vault_totp(id,seed_wrapped,dek_wrapped,last_step) VALUES(1,?1,?2,?3) ON CONFLICT(id) DO UPDATE SET seed_wrapped=excluded.seed_wrapped,dek_wrapped=excluded.dek_wrapped,last_step=excluded.last_step",rusqlite::params![blob,wrapped,step as i64])?;
        tx.execute("INSERT INTO vault_totp_meta(id,enabled,last_step) VALUES(1,1,?1) ON CONFLICT(id) DO UPDATE SET enabled=1,last_step=excluded.last_step",[step as i64])?;
        tx.commit()?;
        Ok(())
    }
    pub fn verify(&self, code: &str) -> Result<()> { self.verify_at(code, unix_time()?) }
    fn verify_at(&self, code: &str, now: u64) -> Result<()> {
        if now < *self.locked_until.lock().unwrap_or_else(|e| e.into_inner()) { return Err(ConnectorError::bad_request("invalid code")); }
        let row: Option<(Vec<u8>, i64)> = self.conn.lock().unwrap_or_else(|e| e.into_inner()).query_row("SELECT seed_wrapped,last_step FROM vault_totp WHERE id=1", [], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
        let Some((blob, last_step)) = row else { self.failed(now); return Err(ConnectorError::bad_request("invalid code")); };
        if blob.len() < NONCE_LEN { self.failed(now); return Err(ConnectorError::bad_request("invalid code")); }
        let cipher = XChaCha20Poly1305::new((&*self.key).into());
        let seed = Zeroizing::new(cipher.decrypt(XNonce::from_slice(&blob[..NONCE_LEN]), &blob[NONCE_LEN..]).map_err(|_| ConnectorError::internal("TOTP unavailable"))?);
        let accepted = self.match_step(&seed, code, now / STEP).filter(|s| *s as i64 > last_step);
        let Some(step) = accepted else { self.failed(now); return Err(ConnectorError::bad_request("invalid code")); };
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.unchecked_transaction()?;
        let changed = tx.execute("UPDATE vault_totp SET last_step=?1 WHERE id=1 AND last_step=?2", rusqlite::params![step as i64, last_step])?;
        let meta_changed = tx.execute("UPDATE vault_totp_meta SET last_step=?1 WHERE id=1 AND enabled=1 AND last_step<?2", rusqlite::params![step as i64, step as i64])?;
        if changed != 1 || meta_changed != 1 { self.failed(now); return Err(ConnectorError::bad_request("invalid code")); }
        tx.commit()?;
        *self.fail_count.lock().unwrap_or_else(|e| e.into_inner()) = 0;
        Ok(())
    }
    pub fn unwrap_dek(&self)->Result<Zeroizing<Vec<u8>>>{
        let blob:Vec<u8>=self.conn.lock().unwrap_or_else(|e|e.into_inner()).query_row("SELECT dek_wrapped FROM vault_totp WHERE id=1",[],|r|r.get(0)).optional()?.ok_or_else(||ConnectorError::bad_request("TOTP not configured"))?;
        if blob.len()<NONCE_LEN{return Err(ConnectorError::internal("TOTP unavailable"));}
        XChaCha20Poly1305::new((&*self.key).into()).decrypt(XNonce::from_slice(&blob[..NONCE_LEN]),&blob[NONCE_LEN..]).map(Zeroizing::new).map_err(|_|ConnectorError::internal("TOTP unavailable"))
    }
    pub fn cancel_pending(&self) {
        *self.pending.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
    pub fn disable(&self) -> Result<()> {
        let conn=self.conn.lock().unwrap_or_else(|e|e.into_inner());
        let tx=conn.unchecked_transaction()?;
        tx.execute("DELETE FROM vault_totp WHERE id=1", [])?;
        tx.execute("UPDATE vault_totp_meta SET enabled=0,last_step=-1 WHERE id=1",[])?;
        tx.commit()?;
        *self.pending.lock().unwrap_or_else(|e|e.into_inner())=None;
        Ok(())
    }
    fn match_step(&self, seed: &[u8], code: &str, current: u64) -> Option<u64> {
        if code.len()!=DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) { return None; }
        let mut found=None;
        for step in [current.saturating_sub(1),current,current.saturating_add(1)] {
            let expected=format!("{:06}",hotp(seed,step));
            let equal=constant_time_equal(expected.as_bytes(),code.as_bytes());
            if equal { found=Some(step); }
        }
        found
    }
    fn failed(&self, now: u64) {
        let mut count=self.fail_count.lock().unwrap_or_else(|e| e.into_inner()); *count=count.saturating_add(1);
        if *count >= 5 { *self.locked_until.lock().unwrap_or_else(|e| e.into_inner())=now+30; *count=0; }
    }
}

fn load_or_create_key(path: &Path) -> Result<[u8; KEY_LEN]> {
    if path.exists() {
        let metadata=fs::symlink_metadata(path).map_err(|_|ConnectorError::new(crate::error::ErrorCode::TotpUnavailable,"TOTP key unavailable"))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(ConnectorError::new(crate::error::ErrorCode::TotpUnavailable,"TOTP key unavailable"));
        }
        let bytes=fs::read(path).map_err(|_|ConnectorError::new(crate::error::ErrorCode::TotpUnavailable,"TOTP key unavailable"))?;
        if bytes.len()!=KEY_LEN { return Err(ConnectorError::new(crate::error::ErrorCode::TotpUnavailable,"TOTP key unavailable")); }
        let mut key=[0u8;KEY_LEN]; key.copy_from_slice(&bytes); return Ok(key);
    }
    if let Some(parent)=path.parent() { fs::create_dir_all(parent).map_err(|e| ConnectorError::internal(format!("TOTP key directory: {e}")))?; fs::set_permissions(parent,fs::Permissions::from_mode(0o700)).map_err(|e| ConnectorError::internal(format!("TOTP key directory permissions: {e}")))?; }
    let mut key=[0u8;KEY_LEN]; getrandom::fill(&mut key).map_err(|e| ConnectorError::internal(format!("rng: {e}")))?;
    let mut file=OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).map_err(|e| ConnectorError::internal(format!("TOTP key create: {e}")))?;
    file.write_all(&key).and_then(|_|file.sync_all()).map_err(|e| ConnectorError::internal(format!("TOTP key write: {e}")))?;
    Ok(key)
}
fn nonce()->Result<[u8;NONCE_LEN]>{let mut n=[0u8;NONCE_LEN];getrandom::fill(&mut n).map_err(|e|ConnectorError::internal(format!("rng: {e}")))?;Ok(n)}
fn unix_time()->Result<u64>{SystemTime::now().duration_since(UNIX_EPOCH).map(|d|d.as_secs()).map_err(|_|ConnectorError::internal("system clock invalid"))}
fn hotp(seed:&[u8],counter:u64)->u32{let mut mac=<HmacSha1 as Mac>::new_from_slice(seed).expect("HMAC accepts any key");mac.update(&counter.to_be_bytes());let digest=mac.finalize().into_bytes();let offset=(digest[19]&0x0f)as usize;let binary=((u32::from(digest[offset]&0x7f))<<24)|(u32::from(digest[offset+1])<<16)|(u32::from(digest[offset+2])<<8)|u32::from(digest[offset+3]);binary%10u32.pow(DIGITS)}
fn constant_time_equal(a:&[u8],b:&[u8])->bool{if a.len()!=b.len(){return false} let mut d=0u8;for(i,j)in a.iter().zip(b){d|=i^j;}d==0}
fn base32_encode(bytes:&[u8])->String{const A:&[u8]=b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";let mut out=String::new();let(mut acc,mut bits)=(0u32,0u32);for b in bytes{acc=(acc<<8)|u32::from(*b);bits+=8;while bits>=5{bits-=5;out.push(A[((acc>>bits)&31)as usize]as char);}}if bits>0{out.push(A[((acc<<(5-bits))&31)as usize]as char);}out}
fn base32_decode(s:&str)->Option<Vec<u8>>{let(mut acc,mut bits)=(0u32,0u32);let mut out=Vec::new();for b in s.bytes(){let v=match b.to_ascii_uppercase(){b'A'..=b'Z'=>b.to_ascii_uppercase()-b'A',b'2'..=b'7'=>b.to_ascii_uppercase()-b'2'+26,_=>return None};acc=(acc<<5)|u32::from(v);bits+=5;if bits>=8{bits-=8;out.push((acc>>bits)as u8);}}Some(out)}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_totp() -> (Totp, PathBuf) {
        let dir = std::env::temp_dir().join(format!("ssh-connector-totp-{}", time::OffsetDateTime::now_utc().unix_timestamp_nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        let t = Totp::open(&dir.join("vault.db"), dir.join("totp.key")).unwrap();
        (t, dir)
    }

    #[test]
    fn enroll_encrypts_seed_and_consumes_each_code_once() {
        let (totp, dir) = temp_totp();
        let dek = [7u8; 32];
        let (secret, _) = totp.start_enrollment(&dek).unwrap();
        let seed = base32_decode(&secret).unwrap();
        let mut current = unix_time().unwrap() / STEP;
        while hotp(&seed, current) == hotp(&seed, current + 1)
            || hotp(&seed, current + 1) == hotp(&seed, current + 2)
        { current += 1; }
        let code = format!("{:06}", hotp(&seed, current));
        totp.confirm_pending(&code, &dek).unwrap();
        assert!(totp.enabled().unwrap());
        assert!(totp.pending.lock().unwrap().is_none());
        let db = std::fs::read(dir.join("vault.db")).unwrap();
        assert!(!db.windows(seed.len()).any(|w| w == seed.as_slice()));
        let verify_code = format!("{:06}", hotp(&seed, current + 1));
        totp.verify_at(&verify_code, (current + 1) * STEP).unwrap();
        assert!(totp.verify_at(&verify_code, (current + 1) * STEP).is_err());

        let replacement_dek = dek;
        let _ = totp.start_replacement(&replacement_dek).unwrap();
        let replacement = totp.pending.lock().unwrap().as_ref().unwrap().seed_b32.to_string();
        let replacement_seed = base32_decode(&replacement).unwrap();
        let mut replacement_step = current + 4;
        while hotp(&replacement_seed, replacement_step) == hotp(&replacement_seed, replacement_step + 1)
            || hotp(&replacement_seed, replacement_step + 1) == hotp(&replacement_seed, replacement_step + 2)
        { replacement_step += 1; }
        let replacement_code = format!("{:06}", hotp(&replacement_seed, replacement_step));
        // Wrong secondary credential must not consume pending state or replace the existing seed.
        assert!(totp.confirm_pending(&replacement_code, &[8u8; 32]).is_err());
        assert!(totp.enabled().unwrap());
        let mut confirm_step = unix_time().unwrap() / STEP;
        while hotp(&replacement_seed, confirm_step) == hotp(&replacement_seed, confirm_step + 1) || hotp(&replacement_seed, confirm_step + 1) == hotp(&replacement_seed, confirm_step + 2) { confirm_step += 1; }
        let code_after_pending = format!("{:06}", hotp(&replacement_seed, confirm_step));
        // After confirmation commits, old seed fails at a later step and the replacement seed succeeds.
        let replacement_commit_step = confirm_step;
        totp.confirm_pending(&code_after_pending, &replacement_dek).unwrap();
        assert!(totp.pending.lock().unwrap().is_none());
        let old_after_commit = format!("{:06}", hotp(&seed, replacement_commit_step + 1));
        assert!(totp.verify_at(&old_after_commit, (replacement_commit_step + 1) * STEP).is_err());
        let new_after_commit = format!("{:06}", hotp(&replacement_seed, replacement_commit_step + 1));
        assert!(totp.verify_at(&new_after_commit, (replacement_commit_step + 1) * STEP).is_ok());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn enrollment_confirmation_expires_and_bad_code_does_not_bind() {
        let (totp, dir) = temp_totp();
        let dek = [9u8; 32];
        totp.start_enrollment(&dek).unwrap();
        assert!(totp.confirm_pending("000000", &dek).is_err());
        assert!(!totp.enabled().unwrap());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn wrong_secondary_factor_does_not_consume_pending_enrollment() {
        let (totp, dir) = temp_totp();
        let original = [3u8; 32];
        let attacker = [4u8; 32];
        totp.start_enrollment(&original).unwrap();
        assert!(totp.confirm_pending_mode("123456", &attacker, false).is_err());
        assert!(!totp.enabled().unwrap());
        assert!(totp.pending.lock().unwrap().is_some());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn enabled_totp_with_missing_key_fails_closed_without_regeneration() {
        let (totp, dir) = temp_totp();
        let seed = [4u8; 20];
        let secret = base32_encode(&seed);
        let dek = [2u8; 32];
        let step = unix_time().unwrap() / STEP;
        let mut acceptable_step = step;
        while hotp(&seed, acceptable_step) == hotp(&seed, acceptable_step + 1) { acceptable_step += 1; }
        let code = format!("{:06}", hotp(&seed, acceptable_step));
        totp.confirm_enrollment_at(&secret, &code, &dek, acceptable_step, false).unwrap();
        drop(totp);
        let key_path = dir.join("totp.key");
        std::fs::remove_file(&key_path).unwrap();
        let reopened = Totp::open(&dir.join("vault.db"), key_path.clone());
        assert!(reopened.is_err());
        assert!(!key_path.exists(), "must not silently create a new wrapping key");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn otp_failures_trigger_shared_cooldown() {
        let (totp, dir) = temp_totp();
        let now = unix_time().unwrap();
        for _ in 0..5 { assert!(totp.verify_at("000000", now).is_err()); }
        assert!(totp.locked_until.lock().unwrap().gt(&now));
        assert!(totp.verify_at("000000", now + 1).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rfc6238_sha1_six_digit_vectors() {
        let seed = b"12345678901234567890";
        for (counter, expected) in [
            (1, 287_082),
            (37_037_036, 81_804),
            (37_037_037, 50_471),
            (41_152_263, 5_924),
            (66_666_666, 279_037),
            (666_666_666, 353_130),
        ] {
            assert_eq!(hotp(seed, counter), expected % 1_000_000);
        }
    }

    #[test]
    fn base32_roundtrip() {
        let raw = b"01234567890123456789";
        assert_eq!(base32_decode(&base32_encode(raw)).unwrap(), raw);
    }

    #[test]
    fn rejects_bad_code_length_and_chars() {
        let t = Totp {
            conn: Mutex::new(rusqlite::Connection::open_in_memory().unwrap()),
            key: Zeroizing::new([0; 32]),
            pending: Mutex::new(None),
            fail_count: Mutex::new(0),
            locked_until: Mutex::new(0),
        };
        assert!(t.match_step(b"seed", "12x456", 1).is_none());
        assert!(t.match_step(b"seed", "12345", 1).is_none());
    }
}
