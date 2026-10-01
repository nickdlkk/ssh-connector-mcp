//! Web management API (human-facing). Bound to loopback only by the daemon.
//!
//! This is the ONLY surface that can reveal stored credentials, and only after
//! re-supplying the master password. Vault init/unlock also live here. The
//! static SPA in `static/` is served as a fallback.

use crate::error::{ConnectorError, ErrorCode};
use crate::state::AppState;
use crate::types::HostSpec;
use crate::audit::AuditFilter;
use axum::{
    Json, Router,
    extract::{
        Path, Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tower_http::services::ServeDir;

type Shared = Arc<AppState>;

/// Build the axum router: API under `/api`, static SPA fallback.
pub fn router(state: Shared, static_dir: std::path::PathBuf) -> Router {
    let api = Router::new()
        .route("/status", get(status))
        .route("/vault/init", post(vault_init))
        .route("/vault/unlock", post(vault_unlock))
        .route("/hosts", get(get_hosts).post(add_host))
        .route("/jumpserver/assets", get(get_jumpserver_assets))
        .route("/jumpserver/assets/{asset_id}/accounts", get(get_jumpserver_accounts))
        .route("/hosts/{id}", put(update_host).delete(remove_host))
        .route("/hosts/{id}/connect", post(connect_host))
        .route("/hosts/{id}/disconnect", post(disconnect_host))
        .route("/hosts/{id}/reveal", post(reveal_host))
        .route("/sessions", get(get_sessions))
        .route("/sessions/{id}/close", post(close_session))
        .route("/sessions/{id}/attach", get(attach_session))
        .route("/audit", get(get_audit))
        .with_state(state.clone())
        .route_layer(axum::middleware::from_fn_with_state(state, audit_web_boundary));

    Router::new()
        .nest("/api", api)
        .fallback_service(ServeDir::new(static_dir).append_index_html_on_directories(true))
}

/// Map a ConnectorError to an HTTP status + JSON body the SPA understands.
struct ApiError(ConnectorError);

impl From<ConnectorError> for ApiError {
    fn from(e: ConnectorError) -> Self {
        ApiError(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0.code {
            ErrorCode::BadRequest => StatusCode::BAD_REQUEST,
            ErrorCode::HostNotFound | ErrorCode::SessionNotFound => StatusCode::NOT_FOUND,
            ErrorCode::VaultLocked
            | ErrorCode::VaultBadPassword
            | ErrorCode::AuthFailed
            | ErrorCode::PrivateKeyInvalid
            | ErrorCode::PrivateKeyPassphraseRequired
            | ErrorCode::PrivateKeyPassphraseInvalid
            | ErrorCode::KeyboardInteractiveFailed => StatusCode::UNAUTHORIZED,
            ErrorCode::VaultAlreadyInit | ErrorCode::HostKeyMismatch => StatusCode::CONFLICT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = Json(
            json!({ "code": self.0.code, "message": self.0.message, "context": self.0.context }),
        );
        (status, body).into_response()
    }
}

type ApiResult = std::result::Result<Json<serde_json::Value>, ApiError>;

// Cross-cutting API audit. This observes completed handler responses, sanitizes
// both request JSON and returned JSON, and leaves the audited handler response intact.
async fn audit_web_boundary(
    State(st): State<Shared>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    use axum::body::to_bytes;

    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let route = stable_route(&path);
    let started = std::time::Instant::now();
    let (parts, body) = request.into_parts();
    let request_bytes = match to_bytes(body, 1_048_576).await {
        Ok(bytes) => bytes,
        Err(_) => {
            let method_name = format!("{} {}", method.as_str(), route);
            let input = serde_json::json!({"entered":false,"body_rejected":true});
            let record = st.audit.try_record_fields(crate::audit::AuditLog::entry(&method_name), "web_api", input, Some(serde_json::json!({"http_status":413})), Some(started.elapsed().as_millis() as i64), None, None, Some("body_too_large_or_unreadable"));
            if let Err(error) = record { tracing::error!(target:"audit", method=%method_name, "request rejection audit failed: {error}"); }
            return (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response();
        }
    };
    let request_body_len = body_for_audit_len(&request_bytes);
    let request_json = serde_json::from_slice::<serde_json::Value>(&request_bytes).unwrap_or(serde_json::Value::Null);
    let req = axum::http::Request::from_parts(parts, axum::body::Body::from(request_bytes));
    let response = next.run(req).await;
    let status = response.status();
    let (parts, body) = response.into_parts();
    let body_for_client = match to_bytes(body, 1_048_576).await {
        Ok(bytes) => bytes,
        Err(_) => {
            let method_name = format!("{} {}", method.as_str(), route);
            let audit_input = crate::mcp_audit_policy::sanitize_input(request_json);
            let record = st.audit.try_record_fields(crate::audit::AuditLog::entry(&method_name), "web_api", audit_input, Some(serde_json::json!({"response_too_large":true})), Some(started.elapsed().as_millis() as i64), None, None, Some("response_too_large"));
            if let Err(error) = record { tracing::error!(target:"audit", method=%method_name, "response overflow audit failed: {error}"); }
            return (StatusCode::INTERNAL_SERVER_ERROR, "handler response exceeded audit size cap").into_response();
        }
    };
    let response_json = serde_json::from_slice::<serde_json::Value>(&body_for_client).ok();
    let method_name = format!("{} {}", method.as_str(), route);
    let audit_input = crate::mcp_audit_policy::sanitize_input(request_json);
    let audit_output = if route == "audit" {
        response_json.as_ref().map(|value| serde_json::json!({"entry_count": value.get("entries").and_then(|entries|entries.as_array()).map_or(0, |entries|entries.len()), "has_next_cursor":value.get("next_cursor").is_some_and(|cursor|!cursor.is_null())}))
    } else {
        response_json.as_ref().map(|value| crate::mcp_audit_policy::sanitize_output(value, route))
    };
    let err_code = if status.is_client_error() || status.is_server_error() {
        response_json.as_ref().and_then(|v|v.get("code").or_else(||v.get("error_code"))).and_then(|v|v.as_str()).map(str::to_string).or_else(||Some(status.as_u16().to_string()))
    } else { None };
        let audit_result = st.audit.try_record_fields(
            crate::audit::AuditLog::entry(&method_name), "web_api", audit_input, audit_output,
            Some(started.elapsed().as_millis() as i64), Some(request_body_len),
            None, err_code.as_deref(),
        );
        if let Err(error) = audit_result {
            tracing::error!(target:"audit", method=%method_name, "mandatory web audit failed: {error}");
            return (StatusCode::SERVICE_UNAVAILABLE, "audit unavailable").into_response();
        }
        Response::from_parts(parts, axum::body::Body::from(body_for_client))
}

fn body_for_audit_len(bytes: &axum::body::Bytes) -> i64 { bytes.len() as i64 }

// --- Vault / status ---

async fn status(State(st): State<Shared>) -> ApiResult {
    Ok(Json(json!({
        "vault_initialized": st.vault.is_initialized().map_err(ApiError::from)?,
        "vault_unlocked": st.vault.is_unlocked(),
        "version": env!("CARGO_PKG_VERSION"),
    })))
}

#[derive(Deserialize)]
struct MasterPassword {
    master_password: String,
}

async fn vault_init(State(st): State<Shared>, Json(req): Json<MasterPassword>) -> ApiResult {
    st.vault.init(&req.master_password).map_err(ApiError::from)?;
    Ok(Json(json!({ "ok": true })))
}

async fn vault_unlock(State(st): State<Shared>, Json(req): Json<MasterPassword>) -> ApiResult {
    st.vault.unlock(&req.master_password).map_err(ApiError::from)?;
    Ok(Json(json!({ "ok": true })))
}

// --- Hosts ---

async fn get_hosts(State(st): State<Shared>) -> ApiResult {
    let hosts = st.list_host_details().await.map_err(ApiError::from)?;
    Ok(Json(json!({ "hosts": hosts })))
}

async fn add_host(State(st): State<Shared>, Json(spec): Json<HostSpec>) -> ApiResult {
    let id = st.add_host(spec).map_err(ApiError::from)?;
    Ok(Json(json!({ "host_id": id })))
}

// --- JumpServer inventory ---

async fn get_jumpserver_assets(State(st): State<Shared>) -> ApiResult {
    let assets = st.jumpserver_assets().await.map_err(ApiError::from)?;
    Ok(Json(json!({ "assets": assets })))
}

async fn get_jumpserver_accounts(
    State(st): State<Shared>,
    Path(asset_id): Path<String>,
) -> ApiResult {
    let accounts = st.jumpserver_accounts(&asset_id).await.map_err(ApiError::from)?;
    Ok(Json(json!({ "accounts": accounts })))
}

async fn update_host(
    State(st): State<Shared>,
    Path(id): Path<String>,
    Json(spec): Json<HostSpec>,
) -> ApiResult {
    st.update_host(&id, spec).map_err(ApiError::from)?;
    Ok(Json(json!({ "ok": true })))
}

async fn remove_host(State(st): State<Shared>, Path(id): Path<String>) -> ApiResult {
    st.remove_host(&id).await.map_err(ApiError::from)?;
    Ok(Json(json!({ "ok": true })))
}

async fn connect_host(State(st): State<Shared>, Path(id): Path<String>) -> ApiResult {
    st.connect_host(&id).await.map_err(ApiError::from)?;
    Ok(Json(json!({ "status": "connected" })))
}

async fn disconnect_host(State(st): State<Shared>, Path(id): Path<String>) -> ApiResult {
    st.disconnect_host(&id).await.map_err(ApiError::from)?;
    Ok(Json(json!({ "status": "disconnected" })))
}

async fn reveal_host(
    State(st): State<Shared>,
    Path(id): Path<String>,
    Json(req): Json<MasterPassword>,
) -> ApiResult {
    let (auth, jumps) = st.vault.reveal_credentials(&id, &req.master_password).map_err(ApiError::from)?;
    Ok(Json(json!({ "auth": auth, "jump_hosts": jumps })))
}

// --- Sessions ---

async fn get_sessions(State(st): State<Shared>) -> ApiResult {
    let sessions = st.list_sessions().await;
    Ok(Json(json!({ "sessions": sessions })))
}

async fn close_session(State(st): State<Shared>, Path(id): Path<String>) -> ApiResult {
    st.close_pty(&id).await.map_err(ApiError::from)?;
    Ok(Json(json!({ "ok": true })))
}

// --- Audit ---

#[derive(Deserialize, Default)]
struct AuditQuery {
    from: Option<String>, to: Option<String>, method: Option<String>, methods: Option<Vec<String>>, source: Option<String>,
    host_id: Option<String>, session_id: Option<String>, status: Option<String>, error_code: Option<String>,
    sort_by: Option<String>, order: Option<String>, limit: Option<usize>, cursor: Option<String>,
}

async fn get_audit(State(st): State<Shared>, Query(q): Query<AuditQuery>) -> ApiResult {
    if q.methods.as_ref().is_some_and(|methods| methods.len() > 32) {
        return Err(ApiError(ConnectorError::bad_request("at most 32 methods may be selected")));
    }
    let filter = AuditFilter { from:q.from,to:q.to,method:q.method,methods:q.methods.unwrap_or_default(),source:q.source,host_id:q.host_id,session_id:q.session_id,status:q.status,error_code:q.error_code,sort_by:q.sort_by,order:q.order,limit:q.limit,cursor:q.cursor };
    let (entries,next_cursor)=st.audit.query(&filter).map_err(|e|ApiError(ConnectorError::bad_request(format!("invalid audit query: {e}"))))?;
    Ok(Json(json!({"entries":entries,"next_cursor":next_cursor})))
}

// --- WebSocket terminal takeover ---

async fn attach_session(
    State(st): State<Shared>,
    Path(id): Path<String>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| attach_socket(socket, st, id))
}

/// Bridge a PTY session to a WebSocket: remote bytes -> client, client text/bytes
/// -> remote stdin. Closes when either side ends or the session dies.
async fn attach_socket(socket: WebSocket, st: Shared, session_id: String) {
    let mut rx = match st.sessions.pty_subscribe(&session_id).await {
        Ok(rx) => rx,
        Err(_) => {
            let mut s = socket;
            let _ = s
                .send(Message::Text(
                    json!({ "error": "session_not_found" }).to_string().into(),
                ))
                .await;
            return;
        }
    };

    let (mut sink, mut stream) = {
        use futures_util::StreamExt;
        socket.split()
    };

    // Remote -> client.
    let to_client = tokio::spawn(async move {
        use futures_util::SinkExt;
        loop {
            match rx.recv().await {
                Ok(bytes) => {
                    if sink.send(Message::Binary(bytes.into())).await.is_err() {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            }
        }
    });

    // Client -> remote stdin.
    let st2 = st.clone();
    let sid = session_id.clone();
    let to_remote = tokio::spawn(async move {
        use futures_util::StreamExt;
        while let Some(Ok(msg)) = stream.next().await {
            let bytes = match msg {
                Message::Text(t) => t.as_bytes().to_vec(),
                Message::Binary(b) => b.to_vec(),
                Message::Close(_) => break,
                _ => continue,
            };
            if st2.pty_input_ws(&sid, bytes).await.is_err() {
                break;
            }
        }
    });

    // When either direction finishes, abort the other.
    tokio::select! {
        _ = to_client => {},
        _ = to_remote => {},
    }
}

fn stable_route(path: &str) -> &str {
    let path = path.strip_prefix("/api").unwrap_or(path);
    const KNOWN: &[(&str, &str)] = &[
        ("/status", "status"), ("/vault/init", "vault/init"), ("/vault/unlock", "vault/unlock"),
        ("/hosts", "hosts"), ("/jumpserver/assets", "jumpserver/assets"), ("/audit", "audit"),
        ("/sessions", "sessions"),
    ];
    for (prefix, route) in KNOWN { if path == *prefix { return route; } }
    if path.starts_with("/jumpserver/assets/") { return "jumpserver/assets/{asset_id}/accounts"; }
    if path.starts_with("/hosts/") {
        if path.ends_with("/connect") { return "hosts/{id}/connect"; }
        if path.ends_with("/disconnect") { return "hosts/{id}/disconnect"; }
        if path.ends_with("/reveal") { return "hosts/{id}/reveal"; }
        return "hosts/{id}";
    }
    if path.starts_with("/sessions/") {
        if path.ends_with("/close") { return "sessions/{id}/close"; }
        if path.ends_with("/attach") { return "sessions/{id}/attach"; }
    }
    "unmatched"
}

#[cfg(test)]
mod web_audit_tests {
    use super::*;
    use crate::audit::AuditFilter;
    use crate::config::Config;
    use crate::vault::Vault;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn test_state() -> (Shared, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("ssh-connector-web-audit-{}", time::OffsetDateTime::now_utc().unix_timestamp_nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        let vault = Arc::new(Vault::open(&dir.join("vault.db")).unwrap());
        vault.init("unit-test-only-master").unwrap();
        let audit = Arc::new(crate::audit::AuditLog::try_new(dir.join("audit")).unwrap());
        let config = Config::load_or_init(&dir).unwrap();
        let state = AppState::new(vault, audit, config, "local-test-token".to_string()).unwrap();
        (state, dir)
    }

    #[tokio::test]
    async fn status_handler_has_one_audit_event_and_preserves_response() {
        let (state, _) = test_state();
        let app = router(state.clone(), std::path::PathBuf::from("static"));
        let response = app.oneshot(axum::http::Request::builder().uri("/api/status").body(axum::body::Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let (rows, _) = state.audit.query(&AuditFilter::default()).unwrap();
        assert_eq!(rows.len(), 1, "rows={rows:?}");
        assert_eq!(rows[0]["source"], "web_api");
    }

    #[test]
    fn records_raw_vault_init_input_only_as_safe_structure() {
        let input = crate::mcp_audit_policy::sanitize_input(serde_json::json!({"master_password":"must-not-store"}));
        let output = crate::mcp_audit_policy::sanitize_output(&serde_json::json!({"ok":true}),"POST vault/init");
        assert!(!input.to_string().contains("must-not-store"));
        assert_eq!(output["ok"],true);
    }

    #[tokio::test]
    async fn vault_init_audit_does_not_store_master_password() {
        let (state, _) = test_state();
        // Use a separate, uninitialized vault as init handler is valid only before init.
        let dir = std::env::temp_dir().join(format!("ssh-connector-web-vault-init-{}", time::OffsetDateTime::now_utc().unix_timestamp_nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        let vault = Arc::new(Vault::open(&dir.join("vault.db")).unwrap());
        let audit = state.audit.clone();
        let config = Config::load_or_init(&dir).unwrap();
        let app_state = AppState::new(vault, audit.clone(), config, "local-test-token".into()).unwrap();
        let app = router(app_state.clone(), std::path::PathBuf::from("static"));
        let payload = serde_json::json!({"master_password":"no-store-this-password"});
        let response=app.oneshot(axum::http::Request::builder().method("POST").uri("/api/vault/init").header("content-type","application/json").body(axum::body::Body::from(payload.to_string())).unwrap()).await.unwrap();
        assert_eq!(response.status(),StatusCode::OK);
        let (rows,_) = audit.query(&AuditFilter::default()).unwrap();
        assert_eq!(rows.len(),1,"rows={rows:?}");
        let row = rows.iter().find(|row|row["method"]=="POST vault/init").expect("vault init event");
        let serialized=row.to_string();
        assert!(!serialized.contains("no-store-this-password"));
        assert_eq!(row["source"],"web_api");
    }
}


#[cfg(test)]
mod web_limit_tests {
    use super::*;
    use crate::{config::Config,vault::Vault};
    use std::sync::Arc;
    use tower::ServiceExt;

    #[tokio::test]
    async fn rejects_large_request_body_without_forwarding_empty_body() {
        let root=std::env::temp_dir().join(format!("web-body-cap-{}",time::OffsetDateTime::now_utc().unix_timestamp_nanos()));
        std::fs::create_dir_all(&root).unwrap();
        let vault=Arc::new(Vault::open(&root.join("vault.db")).unwrap());
        let audit=Arc::new(crate::audit::AuditLog::try_new(root.join("audit")).unwrap());
        let config=Config::load_or_init(&root).unwrap();
        let state=AppState::new(vault,audit.clone(),config,"token".into()).unwrap();
        let app=router(state.clone(),std::path::PathBuf::from("static"));
        let huge=vec![b' ';1_048_577];
        let response=app.oneshot(axum::http::Request::builder().method("POST").uri("/api/vault/init").header("content-type","application/json").body(axum::body::Body::from(huge)).unwrap()).await.unwrap();
        assert_eq!(response.status(),StatusCode::PAYLOAD_TOO_LARGE);
        assert!(!state.vault.is_initialized().unwrap());
        let (events,_)=state.audit.query(&AuditFilter::default()).unwrap();
        assert_eq!(events.len(),1);
        assert_eq!(events[0]["input"]["entered"],false);
        assert_eq!(events[0]["error_code"],"body_too_large_or_unreadable");
    }
}


#[cfg(test)]
mod web_audit_query_tests {
    use super::*;
    use crate::{config::Config,vault::Vault};
    use std::sync::Arc;
    use tower::ServiceExt;

    #[tokio::test]
    async fn audit_route_filters_source_and_returns_cursor_shape() {
        let root=std::env::temp_dir().join(format!("web-audit-filter-{}",time::OffsetDateTime::now_utc().unix_timestamp_nanos()));
        std::fs::create_dir_all(&root).unwrap();
        let vault=Arc::new(Vault::open(&root.join("vault.db")).unwrap());vault.init("unit-master").unwrap();
        let audit=Arc::new(crate::audit::AuditLog::try_new(root.join("audit")).unwrap());
        audit.try_record_fields(crate::audit::AuditLog::entry("alpha"),"mcp",serde_json::json!({}),Some(serde_json::json!({"ok":true})),None,None,None,None).unwrap();
        audit.try_record_fields(crate::audit::AuditLog::entry("beta"),"web_api",serde_json::json!({}),Some(serde_json::json!({"ok":true})),None,None,None,None).unwrap();
        let state=AppState::new(vault,audit,Config::load_or_init(&root).unwrap(),"token".into()).unwrap();
        let app=router(state,std::path::PathBuf::from("static"));
        let response=app.oneshot(axum::http::Request::builder().uri("/api/audit?source=mcp&limit=1").body(axum::body::Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(),StatusCode::OK);
        let body=axum::body::to_bytes(response.into_body(),65536).await.unwrap();
        let json:serde_json::Value=serde_json::from_slice(&body).unwrap();
        assert_eq!(json["entries"].as_array().unwrap().len(),1);
        assert_eq!(json["entries"][0]["source"],"mcp");
        assert!(json.get("next_cursor").is_some());
    }
}
