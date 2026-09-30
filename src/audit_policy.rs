use serde_json::Value;

const SAFE_KEYS: &[&str] = &[
    "type", "argc", "arg_bytes", "bytes", "lines", "duration_ms", "stdout_bytes",
    "stderr_bytes", "output_bytes", "input_bytes", "timed_out", "truncated",
    "had_invalid_utf8", "rows", "cols", "method", "error_code", "source",
    "overwrite", "verified", "chunk_size_bytes", "redacted", "entries", "host_id",
    "session_id", "asset_id", "account_id", "status", "ok", "exit_code", "sha256",
    "auth_kind", "jump_count", "become_root_enabled", "become_root_configured",
    "env_keys", "payload", "error", "token", "code", "fields", "items", "count",
    "connected", "disconnected", "created", "updated", "removed", "name", "input", "output",
    "detail", "content_bytes", "stdout_bytes", "stderr_bytes", "next_cursor", "http_status",
    "entered", "body_rejected", "action", "ts", "ts_utc", "id", "legacy_action",
    "caller", "detail_json", "duration_ms", "truncated", "error_code", "exit_code",
    "input_bytes", "output_bytes", "next_cursor", "response_too_large", "count", "has_more",
];
const NEVER_STORE: &[&str] = &[
    "password", "secret", "cookie", "header", "credential", "private_key", "key_pem",
    "passphrase", "answer", "preview", "command", "script", "raw", "stdout", "stderr",
    "content", "path", "env", "message", "context", "authorization", "token_value",
];
const MAX_RECORD_BYTES: usize = 65_536;

pub fn sanitize(v: Value) -> Value {
    match v {
        Value::Object(map) => Value::Object(map.into_iter().filter_map(|(key, value)| {
            let lower = key.to_ascii_lowercase();
            if NEVER_STORE.iter().any(|s| lower.contains(s)) {
                return None;
            }
            if !SAFE_KEYS.contains(&lower.as_str()) { return None; }
            let value = if matches!(value, Value::Object(_) | Value::Array(_)) {
                sanitize(value)
            } else if matches!(value, Value::String(_)) && !matches!(lower.as_str(),
                "type"|"method"|"error_code"|"source"|"status"|"auth_kind"|"host_id"|"session_id"|"asset_id"|"account_id"|"code"|"name"|"ts"|"ts_utc"|"action"|"legacy_action"|"caller") {
                metadata(&value)
            } else { value };
            Some((key, value))
        }).collect()),
        Value::Array(array) => Value::Array(array.into_iter().map(sanitize).collect()),
        primitive => primitive,
    }
}

fn metadata(v: &Value) -> Value {
    match v {
        Value::String(s) => serde_json::json!({"redacted":true,"bytes":s.len()}),
        Value::Array(a) => serde_json::json!({"redacted":true,"items":a.len()}),
        Value::Object(o) => serde_json::json!({"redacted":true,"fields":o.len()}),
        Value::Null => serde_json::json!({"redacted":true,"type":"null"}),
        Value::Number(_) => serde_json::json!({"redacted":true,"type":"number"}),
        Value::Bool(_) => serde_json::json!({"redacted":true,"type":"boolean"}),
    }
}

pub fn sanitize_bounded(v: Value, max_bytes: usize, truncated: &mut bool) -> Value {
    let safe = sanitize(v);
    let bytes = serde_json::to_vec(&safe).unwrap_or_default();
    if bytes.len() <= max_bytes.min(MAX_RECORD_BYTES) { safe }
    else {
        *truncated = true;
        serde_json::json!({"_truncated":true,"original_bytes":bytes.len()})
    }
}
