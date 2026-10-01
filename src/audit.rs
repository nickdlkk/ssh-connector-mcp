//! SQLite-backed local audit log with idempotent legacy JSONL migration.
use crate::audit_policy::sanitize_bounded;
use base64::Engine;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{path::{Path, PathBuf}, sync::Mutex, time::Duration};

const RETENTION_SECONDS: i64 = 7 * 24 * 60 * 60;
const MAX_RECORD_BYTES: usize = 65_536;
const MAX_PAGE_SIZE: usize = 500;

#[derive(Debug, Serialize)]
pub struct AuditEntry<'a> {
    pub ts: String,
    pub action: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<Value>,
}

impl<'a> AuditEntry<'a> {
    pub fn with_host(mut self, value: &'a str) -> Self { self.host_id = Some(value); self }
    pub fn with_session(mut self, value: &'a str) -> Self { self.session_id = Some(value); self }
    pub fn with_caller(mut self, value: &'a str) -> Self { self.caller = Some(value); self }
    pub fn with_exit(mut self, value: Option<i32>) -> Self { self.exit_code = value; self }
    pub fn with_detail(mut self, value: Value) -> Self { self.detail = Some(value); self }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuditFilter {
    pub from: Option<String>,
    pub to: Option<String>,
    pub method: Option<String>,
    pub methods: Vec<String>,
    pub source: Option<String>,
    pub host_id: Option<String>,
    pub session_id: Option<String>,
    pub status: Option<String>,
    pub error_code: Option<String>,
    pub sort_by: Option<String>,
    pub order: Option<String>,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

pub struct AuditLog {
    dir: PathBuf,
    db: Mutex<Connection>,
}

impl AuditLog {
    pub fn new(dir: PathBuf) -> Self { Self::try_new(dir).expect("initialize SQLite audit store") }

    pub fn try_new(dir: PathBuf) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let path = dir.join("audit.sqlite3");
        let mut db = Connection::open(&path)?;
        db.busy_timeout(Duration::from_secs(5))?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "NORMAL")?;
        db.pragma_update(None, "foreign_keys", "ON")?;
        schema(&mut db)?;
        migrate(&mut db, &dir)?;
        prune_expired(&mut db)?;
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(Self { dir, db: Mutex::new(db) })
    }

    pub fn entry(action: &str) -> AuditEntry<'_> {
        AuditEntry { ts: now(), action, host_id: None, session_id: None, caller: None, exit_code: None, detail: None }
    }

    pub fn record(&self, entry: AuditEntry<'_>) {
        self.record_fields(entry, "internal", serde_json::json!({}), None, None, None, None, None);
    }

    /// Record a single sanitized event. It fails closed to its caller only through
    /// `try_record_fields`; legacy fire-and-forget sites still emit an error log.
    pub fn record_fields(
        &self,
        entry: AuditEntry<'_>,
        source: &str,
        input: Value,
        output: Option<Value>,
        duration_ms: Option<i64>,
        input_bytes: Option<i64>,
        output_bytes: Option<i64>,
        error_code: Option<&str>,
    ) {
        if let Err(error) = self.try_record_fields(entry, source, input, output, duration_ms, input_bytes, output_bytes, error_code) {
            tracing::error!(target: "audit", "audit write failed: {error}");
        }
    }

    pub fn try_record_fields(
        &self,
        entry: AuditEntry<'_>,
        source: &str,
        input: Value,
        output: Option<Value>,
        duration_ms: Option<i64>,
        input_bytes: Option<i64>,
        output_bytes: Option<i64>,
        error_code: Option<&str>,
    ) -> rusqlite::Result<()> {
        let mut truncated = false;
        let original_input_bytes = input_bytes.unwrap_or_else(|| serde_json::to_vec(&input).map_or(0, |bytes| bytes.len() as i64));
        let original_output_bytes = output_bytes.unwrap_or_else(|| output.as_ref().map_or(0, |value| serde_json::to_vec(value).map_or(0, |bytes| bytes.len() as i64)));
        let serialized_size = serde_json::to_vec(&serde_json::json!({"input":&input,"output":&output,"detail":&entry.detail})).map_or(0, |bytes| bytes.len());
        if serialized_size > MAX_RECORD_BYTES { truncated = true; }
        let input = sanitize_bounded(input, MAX_RECORD_BYTES, &mut truncated);
        let output = output.map(|value| sanitize_bounded(value, MAX_RECORD_BYTES, &mut truncated));
        let detail = entry.detail.map(|value| sanitize_bounded(value, MAX_RECORD_BYTES, &mut truncated));
        if original_input_bytes > 0 && serde_json::to_vec(&input).map_or(0, |bytes|bytes.len() as i64) < original_input_bytes { truncated = true; }
        if original_output_bytes > 0 && output.as_ref().and_then(|value|serde_json::to_vec(value).ok()).map_or(0, |bytes|bytes.len() as i64) < original_output_bytes { truncated = true; }
        let input_json = serde_json::to_string(&input).unwrap_or_else(|_| "{}".to_string());
        let output_json = output.and_then(|value| serde_json::to_string(&value).ok());
        let detail_json = detail.and_then(|value| serde_json::to_string(&value).ok());
        let encoded_detail_bytes = detail_json.as_ref().map_or(0, String::len) as i64;
        let output_bytes = original_output_bytes.saturating_add(encoded_detail_bytes);
        let status = if error_code.is_some() || entry.action.ends_with("_failed") || entry.exit_code.is_some_and(|code| code != 0) { "error" } else { "success" };
        let ts = normalize_utc(&entry.ts).unwrap_or_else(now);
        self.db.lock().map_err(|_| rusqlite::Error::InvalidQuery)?.execute(
            "INSERT INTO audit_events(ts_utc,method,source,host_id,session_id,status,duration_ms,input_json,output_json,input_bytes,output_bytes,truncated,error_code,legacy_action,caller,exit_code,detail_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?2,?14,?15,?16)",
            params![ts, entry.action, source, entry.host_id, entry.session_id, status, duration_ms, input_json, output_json, input_bytes, output_bytes, truncated, error_code, entry.caller, entry.exit_code, detail_json],
        )?;
        Ok(())
    }

    pub fn query(&self, filter: &AuditFilter) -> rusqlite::Result<(Vec<Value>, Option<String>)> {
        let db = self.db.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
        let now_value = time::OffsetDateTime::now_utc();
        let floor_value = now_value - time::Duration::seconds(RETENTION_SECONDS);
        let floor = format_utc(floor_value);
        let from = match filter.from.as_deref() {
            Some(value) => normalize_utc(value).ok_or_else(|| rusqlite::Error::InvalidParameterName("invalid from timestamp".into()))?,
            None => floor.clone(),
        };
        if from < floor { return Err(rusqlite::Error::InvalidParameterName("from is outside retention window".into())); }
        let to = match filter.to.as_deref() {
            Some(value) => Some(normalize_utc(value).ok_or_else(|| rusqlite::Error::InvalidParameterName("invalid to timestamp".into()))?),
            None => None,
        };
        if let Some(end) = &to {
            let end_dt = parse_utc(end).ok_or(rusqlite::Error::InvalidQuery)?;
            let from_dt = parse_utc(&from).ok_or(rusqlite::Error::InvalidQuery)?;
            if end_dt < from_dt || end_dt > now_value {
                return Err(rusqlite::Error::InvalidParameterName("to is outside valid query window".into()));
            }
            if end_dt - from_dt > time::Duration::seconds(RETENTION_SECONDS) {
                return Err(rusqlite::Error::InvalidParameterName("query span exceeds seven days".into()));
            }
        }
        let sort = match filter.sort_by.as_deref().unwrap_or("ts_utc") {
            "ts_utc" => "ts_utc", "id" => "id", "method" => "method", "source" => "source",
            "host_id" => "host_id", "session_id" => "session_id", "status" => "status", "error_code" => "error_code",
            _ => return Err(rusqlite::Error::InvalidParameterName("unsupported sort_by".into())),
        };
        let order = match filter.order.as_deref().unwrap_or("desc").to_ascii_lowercase().as_str() {
            "asc" => "ASC", "desc" => "DESC",
            _ => return Err(rusqlite::Error::InvalidParameterName("order must be asc or desc".into())),
        };
        let limit = filter.limit.unwrap_or(200).clamp(1, MAX_PAGE_SIZE);
        if filter.cursor.is_some() && sort != "ts_utc" {
            return Err(rusqlite::Error::InvalidParameterName("cursor pagination requires sort_by=ts_utc".into()));
        }
        let cursor = match filter.cursor.as_deref() {
            Some(raw) => {
                let (raw_ts, id) = decode_cursor(raw).ok_or_else(|| rusqlite::Error::InvalidParameterName("invalid cursor".into()))?;
                let ts = normalize_utc(&raw_ts).ok_or_else(|| rusqlite::Error::InvalidParameterName("invalid cursor timestamp".into()))?;
                let cursor_dt = parse_utc(&ts).ok_or(rusqlite::Error::InvalidQuery)?;
                if cursor_dt < floor_value || cursor_dt > now_value {
                    return Err(rusqlite::Error::InvalidParameterName("cursor outside retention window".into()));
                }
                Some((ts, id))
            }
            None => None,
        };
        let mut sql = String::from("SELECT id,ts_utc,method,source,host_id,session_id,status,duration_ms,input_json,output_json,input_bytes,output_bytes,truncated,error_code,legacy_action,caller,exit_code,detail_json FROM audit_events WHERE ts_utc>=?");
        let mut args: Vec<rusqlite::types::Value> = vec![from.into()];
        if let Some(end) = to { sql.push_str(" AND ts_utc<=?"); args.push(end.into()); }
        if let Some(value) = &filter.method { sql.push_str(" AND method=?"); args.push(value.clone().into()); }
        if !filter.methods.is_empty() {
            let methods: Vec<String> = filter.methods.iter().filter(|method| !method.is_empty()).cloned().collect();
            if methods.len() > 32 { return Err(rusqlite::Error::InvalidParameterName("at most 32 methods may be selected".into())); }
            if !methods.is_empty() {
                sql.push_str(" AND method IN (");
                for index in 0..methods.len() { if index > 0 { sql.push(','); } sql.push('?'); }
                sql.push(')');
                args.extend(methods.into_iter().map(Into::into));
            }
        }
        for (column, value) in [("source", &filter.source), ("host_id", &filter.host_id), ("session_id", &filter.session_id), ("status", &filter.status), ("error_code", &filter.error_code)] {
            if let Some(value) = value { sql.push_str(" AND "); sql.push_str(column); sql.push_str("=?"); args.push(value.clone().into()); }
        }
        if let Some((ts, id)) = cursor {
            sql.push_str(if order == "ASC" { " AND (ts_utc,id)>(?,?)" } else { " AND (ts_utc,id)<(?,?)" });
            args.push(ts.into()); args.push(id.into());
        }
        sql.push_str(" ORDER BY "); sql.push_str(sort); sql.push(' '); sql.push_str(order);
        if sort != "id" { sql.push_str(",id "); sql.push_str(order); }
        sql.push_str(" LIMIT ?"); args.push(((limit + 1) as i64).into());
        let mut statement = db.prepare(&sql)?;
        let mut rows = statement.query(rusqlite::params_from_iter(args))?;
        let mut output = Vec::new();
        while let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?; let ts: String = row.get(1)?; let method: String = row.get(2)?;
            let source: String = row.get(3)?; let host: Option<String> = row.get(4)?; let session: Option<String> = row.get(5)?;
            let status: String = row.get(6)?; let duration: Option<i64> = row.get(7)?; let input: String = row.get(8)?;
            let result: Option<String> = row.get(9)?; let input_bytes: Option<i64> = row.get(10)?; let output_bytes: Option<i64> = row.get(11)?;
            let truncated: bool = row.get(12)?; let error_code: Option<String> = row.get(13)?; let legacy_action: Option<String> = row.get(14)?;
            let caller: Option<String> = row.get(15)?; let exit_code: Option<i32> = row.get(16)?; let detail: Option<String> = row.get(17)?;
            let input_value = serde_json::from_str::<Value>(&input).unwrap_or(Value::Null);
            let output_value = result.and_then(|value| serde_json::from_str::<Value>(&value).ok()).unwrap_or(Value::Null);
            let event = serde_json::json!({
                "id":id,"ts":ts,"ts_utc":ts,"action":legacy_action.unwrap_or(method.clone()),"method":method,"source":source,
                "host_id":host,"session_id":session,"status":status,"duration_ms":duration,
                "input":input_value,"output":output_value,
                "input_bytes":input_bytes,"output_bytes":output_bytes,"truncated":truncated,"error_code":error_code,
                "caller":caller,"exit_code":exit_code,"detail":detail.and_then(|value|serde_json::from_str::<Value>(&value).ok()),
            });
            let mut event_truncated = false;
            output.push(sanitize_bounded(event, MAX_RECORD_BYTES, &mut event_truncated));
        }
        let has_more = output.len() > limit;
        let next_cursor = if has_more {
            let last = &output[limit - 1];
            Some(encode_cursor(last["ts_utc"].as_str().ok_or(rusqlite::Error::InvalidQuery)?, last["id"].as_i64().ok_or(rusqlite::Error::InvalidQuery)?))
        } else { None };
        if has_more { output.truncate(limit); }
        Ok((output, next_cursor))
    }

    pub fn tail(&self, limit: usize) -> Vec<Value> {
        self.query(&AuditFilter { limit: Some(limit.clamp(1, MAX_PAGE_SIZE)), ..Default::default() })
            .map(|result| result.0)
            .unwrap_or_else(|error| { tracing::error!(target: "audit", "audit query failed: {error}"); Vec::new() })
    }

    pub fn prune(&self) -> rusqlite::Result<usize> {
        let mut db = self.db.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
        prune_expired(&mut db)
    }

    pub fn database_path(&self) -> PathBuf { self.dir.join("audit.sqlite3") }
}

fn schema(db: &mut Connection) -> rusqlite::Result<()> {
    db.execute_batch("BEGIN IMMEDIATE;
        CREATE TABLE IF NOT EXISTS audit_schema(version INTEGER NOT NULL);
        INSERT INTO audit_schema(version) SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM audit_schema);
        CREATE TABLE IF NOT EXISTS audit_events(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts_utc TEXT NOT NULL, method TEXT NOT NULL, source TEXT NOT NULL,
            host_id TEXT, session_id TEXT, status TEXT NOT NULL CHECK(status IN ('success','error')),
            duration_ms INTEGER, input_json TEXT NOT NULL DEFAULT '{}', output_json TEXT, input_bytes INTEGER,
            output_bytes INTEGER, truncated INTEGER NOT NULL DEFAULT 0, error_code TEXT, legacy_action TEXT,
            caller TEXT, exit_code INTEGER, detail_json TEXT, migration_key TEXT UNIQUE
        );
        CREATE INDEX IF NOT EXISTS audit_ts_idx ON audit_events(ts_utc,id);
        CREATE INDEX IF NOT EXISTS audit_method_ts_idx ON audit_events(method,ts_utc,id);
        CREATE INDEX IF NOT EXISTS audit_source_ts_idx ON audit_events(source,ts_utc,id);
        CREATE INDEX IF NOT EXISTS audit_host_ts_idx ON audit_events(host_id,ts_utc,id);
        CREATE INDEX IF NOT EXISTS audit_session_ts_idx ON audit_events(session_id,ts_utc,id);
        CREATE INDEX IF NOT EXISTS audit_status_ts_idx ON audit_events(status,ts_utc,id);
        CREATE INDEX IF NOT EXISTS audit_error_ts_idx ON audit_events(error_code,ts_utc,id);
        COMMIT;")?;
    Ok(())
}

fn migrate(db: &mut Connection, dir: &Path) -> rusqlite::Result<()> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?
        .filter_map(Result::ok).map(|entry| entry.path()).filter(|path| is_jsonl(path)).collect();
    files.sort();
    let floor = format_utc(time::OffsetDateTime::now_utc() - time::Duration::seconds(RETENTION_SECONDS));
    let tx = db.transaction()?;
    let (mut imported, mut expired, mut malformed) = (0usize, 0usize, 0usize);
    for path in files {
        let name = path.file_name().and_then(|value| value.to_str()).unwrap_or("unknown");
        let contents = match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(error) => { tracing::error!(target: "audit", file=name, "legacy read failed: {error}"); continue; }
        };
        for (line_index, line) in contents.lines().enumerate() {
            let value: Value = match serde_json::from_str(line) { Ok(value) => value, Err(_) => { malformed += 1; continue; } };
            let timestamp = match value.get("ts").and_then(Value::as_str).and_then(normalize_utc) { Some(ts) => ts, None => { malformed += 1; continue; } };
            if timestamp < floor { expired += 1; continue; }
            let method = value.get("action").and_then(Value::as_str).unwrap_or("legacy_unknown");
            let host = value.get("host_id").and_then(Value::as_str);
            let session = value.get("session_id").and_then(Value::as_str);
            let caller = value.get("caller").and_then(Value::as_str);
            let exit_code = value.get("exit_code").and_then(Value::as_i64).map(|code| code as i32);
            let detail = value.get("detail").cloned().map(safe_legacy_detail).map(|detail| bounded(detail, MAX_RECORD_BYTES).to_string());
            let status = if exit_code.is_some_and(|code| code != 0) || method.ends_with("_failed") { "error" } else { "success" };
            imported += tx.execute(
                "INSERT OR IGNORE INTO audit_events(ts_utc,method,source,host_id,session_id,status,input_json,legacy_action,caller,exit_code,detail_json,migration_key) VALUES(?1,?2,'migration',?3,?4,?5,'{}',?2,?6,?7,?8,?9)",
                params![timestamp,method,host,session,status,caller,exit_code,detail,format!("{name}:{}",line_index+1)],
            )?;
        }
    }
    tx.commit()?;
    tracing::info!(target: "audit", imported, expired, malformed, "legacy JSONL migration scan complete");
    Ok(())
}

fn prune_expired(db: &mut Connection) -> rusqlite::Result<usize> {
    let floor = format_utc(time::OffsetDateTime::now_utc() - time::Duration::seconds(RETENTION_SECONDS));
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let count = tx.execute("DELETE FROM audit_events WHERE ts_utc < ?1", [floor])?;
    tx.commit()?;
    if count > 0 { tracing::info!(target: "audit", removed=count, "expired audit rows deleted"); }
    Ok(count)
}

fn is_jsonl(path: &Path) -> bool {
    path.file_name().and_then(|value| value.to_str()).is_some_and(|name| name.starts_with("audit-") && name.ends_with(".jsonl"))
}
fn format_utc(value: time::OffsetDateTime) -> String {
    value.format(&time::format_description::parse("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z").expect("valid UTC timestamp format")).unwrap_or_default()
}
fn now() -> String { format_utc(time::OffsetDateTime::now_utc()) }
fn now_utc() -> String { now() }
fn parse_utc(value: &str) -> Option<time::OffsetDateTime> { time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).ok() }
fn normalize_utc(value: &str) -> Option<String> { Some(format_utc(parse_utc(value)?.to_offset(time::UtcOffset::UTC))) }
fn encode_cursor(timestamp: &str, id: i64) -> String { format!("{id}:{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(timestamp)) }
fn decode_cursor(cursor: &str) -> Option<(String, i64)> {
    let (id, timestamp) = cursor.split_once(':')?;
    Some((String::from_utf8(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(timestamp).ok()?).ok()?, id.parse().ok()?))
}
fn bounded(value: Value, maximum: usize) -> Value {
    let bytes = serde_json::to_vec(&value).unwrap_or_default();
    if bytes.len() <= maximum { value } else { serde_json::json!({"_truncated":true,"original_bytes":bytes.len()}) }
}

fn safe_legacy_detail(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(map.into_iter().filter_map(|(key, value)| {
            let key_lc = key.to_ascii_lowercase();
            let forbidden = ["password","secret","cookie","header","credential","private_key","key_pem","passphrase","answer","preview","command","script","raw","stdout","stderr","output","content","path","env","message","context"];
            let allowed = ["type","argc","arg_bytes","bytes","lines","duration_ms","stdout_bytes","stderr_bytes","output_bytes","input_bytes","timed_out","truncated","had_invalid_utf8","rows","cols","method","error_code","source","overwrite","verified","chunk_size_bytes","redacted","entries","host_id","session_id","asset_id","account_id","status","ok","exit_code","sha256","auth_kind","jump_count","become_root_enabled","become_root_configured","env_keys","payload","error","code"];
            if forbidden.iter().any(|needle| key_lc.contains(needle)) || !allowed.contains(&key_lc.as_str()) { return None; }
            let value = match value {
                Value::String(text) if matches!(key_lc.as_str(), "type"|"method"|"error_code"|"source"|"status"|"auth_kind"|"host_id"|"session_id"|"asset_id"|"account_id"|"code") => Value::String(text.chars().take(128).collect()),
                Value::String(text) => serde_json::json!({"redacted":true,"bytes":text.len()}),
                Value::Array(items) => serde_json::json!({"redacted":true,"items":items.len()}),
                Value::Object(fields) => serde_json::json!({"redacted":true,"fields":fields.len()}),
                value => value,
            };
            Some((key, value))
        }).collect()),
        Value::Array(items) => Value::Array(items.into_iter().map(safe_legacy_detail).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (AuditLog, PathBuf) {
        let dir = std::env::temp_dir().join(format!("sqlite-audit-test-{}", time::OffsetDateTime::now_utc().unix_timestamp_nanos()));
        (AuditLog::new(dir.clone()), dir)
    }

    #[test]
    fn writes_sanitized_event_and_rejects_injected_sort() {
        let (store, _) = temp_store();
        store.record_fields(AuditLog::entry("demo"), "mcp", serde_json::json!({"host_id":"host-a","password":"no-store","command":"secret","arg_bytes":9}), Some(serde_json::json!({"status":"ok","stdout":"private output"})), Some(7), None, None, None);
        let (rows, _) = store.query(&AuditFilter { method: Some("demo".into()), ..Default::default() }).unwrap();
        assert_eq!(rows.len(), 1);
        let serialized = rows[0].to_string();
        assert!(!serialized.contains("no-store"));
        assert!(!serialized.contains("private output"));
        assert_eq!(rows[0]["output"]["status"], "ok");
        assert!(store.query(&AuditFilter { sort_by: Some("id; DROP TABLE audit_events".into()), ..Default::default() }).is_err());
    }

    #[test]
    fn cursor_pagination_is_stable_for_equal_timestamps() {
        let (store, _) = temp_store();
        let ts = now();
        for _id in 1..=4 {
            store.db.lock().unwrap().execute("INSERT INTO audit_events(ts_utc,method,source,status,input_json) VALUES(?1,'page','mcp','success','{}')", [&ts]).unwrap();
        }
        let (first, cursor) = store.query(&AuditFilter { method:Some("page".into()), limit: Some(2), ..Default::default() }).unwrap();
        assert_eq!(first.len(), 2);
        let cursor = cursor.unwrap_or_else(|| panic!("missing cursor; rows={first:?}"));
        let (second, _) = store.query(&AuditFilter { method:Some("page".into()), limit: Some(2), cursor:Some(cursor), ..Default::default() }).unwrap();
        assert_eq!(second.len(), 2);
        assert_ne!(first[1]["id"], second[0]["id"]);
    }

    #[test]
    fn filters_multiple_methods_as_a_union_and_caps_selection() {
        let (store, _) = temp_store();
        for method in ["alpha", "beta", "gamma"] {
            store.record_fields(AuditLog::entry(method), "mcp", serde_json::json!({}), Some(serde_json::json!({"status":"ok"})), None, None, None, None);
        }
        let (rows, _) = store.query(&AuditFilter { methods:vec!["alpha".into(),"gamma".into()], ..Default::default() }).unwrap();
        assert_eq!(rows.len(),2);
        assert!(rows.iter().all(|row| row["method"]=="alpha" || row["method"]=="gamma"));
        let too_many=(0..33).map(|index|format!("method-{index}")).collect();
        assert!(store.query(&AuditFilter { methods:too_many, ..Default::default() }).is_err());
    }

    #[test]
    fn rejects_cursor_outside_retention_and_expired_query_window() {
        let (store, _) = temp_store();
        let old = format_utc(time::OffsetDateTime::now_utc() - time::Duration::seconds(RETENTION_SECONDS + 3));
        assert!(store.query(&AuditFilter { from: Some(old.clone()), ..Default::default() }).is_err());
        assert!(store.query(&AuditFilter { cursor: Some(encode_cursor(&old, 1)), ..Default::default() }).is_err());
    }

    #[test]
    fn imports_legacy_idempotently_redacts_and_preserves_original() {
        let (store, dir) = temp_store();
        let path = dir.join("audit-2026-09-30.jsonl");
        std::fs::write(&path, format!("{{\"ts\":\"{}\",\"action\":\"legacy\",\"detail\":{{\"path\":\"/secret/path\",\"bytes\":12}}}}\nBAD\n", now())).unwrap();
        drop(store);
        let store = AuditLog::new(dir.clone());
        assert!(path.exists());
        let (rows, _) = store.query(&AuditFilter { method: Some("legacy".into()), ..Default::default() }).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["source"], "migration");
        assert!(rows[0].to_string().contains("/secret/path") == false);
        drop(store);
        let store = AuditLog::new(dir);
        let (rows, _) = store.query(&AuditFilter { method: Some("legacy".into()), ..Default::default() }).unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn oversized_record_is_bounded_and_marked() {
        let (store, _) = temp_store();
        let oversized = "x".repeat(MAX_RECORD_BYTES * 2);
        store.record_fields(AuditLog::entry("large"), "mcp", serde_json::json!({"raw":oversized}), Some(serde_json::json!({"status":"ok"})), None, None, None, None);
        let (rows, _) = store.query(&AuditFilter { method: Some("large".into()), ..Default::default() }).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["truncated"], true);
        assert!(!rows[0].to_string().contains(&"x".repeat(100)));
    }

    #[test]
    fn prune_deletes_strictly_older_than_seven_days_and_keeps_boundary_or_newer() {
        let (store, _) = temp_store();
        let now = time::OffsetDateTime::now_utc();
        let old = format_utc(now - time::Duration::seconds(RETENTION_SECONDS + 2));
        let boundaryish = format_utc(now - time::Duration::seconds(RETENTION_SECONDS - 2));
        {
            let db = store.db.lock().unwrap();
            db.execute("INSERT INTO audit_events(ts_utc,method,source,status,input_json) VALUES(?1,'old','test','success','{}')", [&old]).unwrap();
            db.execute("INSERT INTO audit_events(ts_utc,method,source,status,input_json) VALUES(?1,'recent','test','success','{}')", [&boundaryish]).unwrap();
        }
        assert_eq!(store.prune().unwrap(), 1);
        let (rows, _) = store.query(&AuditFilter { method:Some("recent".into()), ..Default::default() }).unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn try_record_fields_surfaces_audit_database_failure() {
        let (store, _) = temp_store();
        let db = store.db.lock().unwrap();
        db.execute_batch("DROP TABLE audit_events").unwrap();
        drop(db);
        let result = store.try_record_fields(AuditLog::entry("must_fail"), "mcp", serde_json::json!({}), None, None, None, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn every_sort_whitelist_field_is_accepted_in_both_directions() {
        let (store, _) = temp_store();
        store.record_fields(AuditLog::entry("alpha"), "mcp", serde_json::json!({}), Some(serde_json::json!({"status":"ok"})), None, None, None, None);
        for field in ["ts_utc", "id", "method", "source", "host_id", "session_id", "status", "error_code"] {
            for order in ["asc", "desc"] {
                let (rows, _) = store.query(&AuditFilter { sort_by:Some(field.into()), order:Some(order.into()), ..Default::default() }).unwrap();
                assert_eq!(rows.len(),1,"field={field} order={order}");
            }
        }
    }

}
