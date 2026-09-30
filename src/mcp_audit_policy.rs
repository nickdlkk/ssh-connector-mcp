use serde_json::{Map, Value};

const SENSITIVE: &[&str] = &[
    "password", "secret", "token", "cookie", "header", "credential", "private_key",
    "passphrase", "answer", "content", "command", "script", "raw", "stdout", "stderr",
    "path", "env", "message", "context", "key_material", "auth", "password_host",
];
const SAFE_SCALARS: &[&str] = &[
    "host_id", "session_id", "asset_id", "account_id", "rows", "cols", "wait_ms",
    "max_output_bytes", "overwrite", "create_parent_dirs", "chunk_size_bytes", "verify_sha256",
    "key", "method", "status", "ok", "cursor", "limit", "sort_by", "order", "from", "to",
    "error_code", "id", "type", "name", "source", "action", "ts", "ts_utc", "next_cursor",
    "entries", "entered", "body_rejected", "http_status", "vault_initialized", "vault_unlocked",
    "hosts", "sessions", "assets", "accounts", "structuredcontent", "iserror", "alias", "host",
    "user", "port", "auth_kind", "jump_count", "connected", "disconnected", "verified", "sha256",
    "bytes", "duration_ms", "truncated", "had_invalid_utf8", "local_path_bytes", "remote_path_bytes",
];

pub fn sanitize_input(input: Value) -> Value {
    match input {
        Value::Object(map) => Value::Object(map.into_iter().filter_map(|(key, value)| {
            let lower=key.to_ascii_lowercase();
            if SENSITIVE.iter().any(|v| lower.contains(v)) { return None; }
            if SAFE_SCALARS.contains(&lower.as_str()) {
                let val=match value { Value::String(s)=>Value::String(s.chars().take(128).collect()), other=>other };
                Some((key,val))
            } else {
                let summary=match value {Value::String(s)=>serde_json::json!({"type":"string","bytes":s.len()}),Value::Array(a)=>serde_json::json!({"type":"array","items":a.len()}),Value::Object(o)=>serde_json::json!({"type":"object","fields":o.len()}),Value::Number(_)=>serde_json::json!({"type":"number"}),Value::Bool(_)=>serde_json::json!({"type":"boolean"}),Value::Null=>serde_json::json!({"type":"null"})};
                Some((key,summary))
            }
        }).collect()),
        Value::Array(a)=>Value::Array(a.into_iter().map(sanitize_input).collect()),
        other=>other,
    }
}

pub fn sanitize_output(value: &Value, method: &str) -> Value {
    if method == "credential_reveal" || method == "reveal_host" || method.ends_with("/reveal") {
        return serde_json::json!({"returned":true,"redacted":true});
    }
    sanitize_output_value(value)
}

fn sanitize_output_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out=Map::new();
            for (key,val) in map {
                let lower=key.to_ascii_lowercase();
                if SENSITIVE.iter().any(|v|lower.contains(v)) && !matches!(lower.as_str(),"content"|"output"|"stdout"|"stderr"|"data") { continue; }
                if SAFE_SCALARS.contains(&lower.as_str()) {
                    let safe_value = match val {
                        Value::String(text) if matches!(lower.as_str(), "host_id"|"session_id"|"asset_id"|"account_id"|"method"|"status"|"type"|"name"|"source"|"error_code"|"code") => Value::String(text.chars().take(128).collect()),
                        value if value.is_number() || value.is_boolean() || value.is_null() => value.clone(),
                        Value::String(text) => serde_json::json!({"redacted":true,"bytes":text.len()}),
                        other => serde_json::json!({"redacted":true,"items":other.as_array().map_or(0,|items|items.len())}),
                    };
                    out.insert(key.clone(),safe_value);
                }
                else if val.is_object() { out.insert(key.clone(),sanitize_output_value(val)); }
                else if val.is_array() { out.insert(key.clone(),Value::Array(val.as_array().unwrap().iter().map(sanitize_output_value).collect())); }
                else if val.is_string() {
                    let text_len=val.as_str().unwrap().len();
                    if matches!(lower.as_str(),"content"|"text"|"screen"|"output"|"stdout"|"stderr"|"data"|"content_base64") {
                        out.insert(format!("{key}_bytes"),serde_json::json!(text_len));
                    }
                }
                else if val.is_number() || val.is_boolean() || val.is_null() { out.insert(key.clone(),val.clone()); }
            }
            Value::Object(out)
        }
        Value::Array(a)=>Value::Array(a.iter().map(sanitize_output_value).collect()),
        Value::String(s)=>serde_json::json!({"type":"string","bytes":s.len()}),
        other=>other.clone(),
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strips_secrets_and_keeps_safe_metadata() {
        let input=sanitize_input(serde_json::json!({"host_id":"host","password":"hidden","raw":"danger","wait_ms":500,"other":"free text"}));
        let text=input.to_string();
        assert!(!text.contains("hidden")); assert!(!text.contains("danger")); assert!(!text.contains("free text"));
        assert_eq!(input["host_id"],"host"); assert_eq!(input["wait_ms"],500);
    }
    #[test]
    fn reveal_and_arbitrary_output_text_are_redacted() {
        let reveal=sanitize_output(&serde_json::json!({"auth":{"password":"secret"},"jump_hosts":[]}),"reveal_host");
        assert!(!reveal.to_string().contains("secret"));
        let list=sanitize_output(&serde_json::json!({"content":"long-secret-output","status":"success","count":3}),"sftp_get");
        assert!(!list.to_string().contains("long-secret-output"));
        assert_eq!(list["content_bytes"],18);
        assert_eq!(list["status"],"success");
    }
}
