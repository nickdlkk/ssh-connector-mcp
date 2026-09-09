//! Web management API (human-facing). Bound to loopback only by the daemon.
//!
//! This is the ONLY surface that can reveal stored credentials, and only after
//! re-supplying the master password. Vault init/unlock also live here. The
//! static SPA in `static/` is served as a fallback.

use crate::error::{ConnectorError, ErrorCode};
use crate::state::AppState;
use crate::types::HostSpec;
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
        .with_state(state);

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
    st.vault
        .init(&req.master_password)
        .map_err(ApiError::from)?;
    st.audit.record(
        crate::audit::AuditLog::entry("vault_init").with_detail(json!({ "source": "web" })),
    );
    Ok(Json(json!({ "ok": true })))
}

async fn vault_unlock(State(st): State<Shared>, Json(req): Json<MasterPassword>) -> ApiResult {
    st.vault
        .unlock(&req.master_password)
        .map_err(ApiError::from)?;
    st.audit.record(
        crate::audit::AuditLog::entry("vault_unlock").with_detail(json!({ "source": "web" })),
    );
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
    // Human-only, master-password-gated credential reveal.
    let (auth, jumps) = st
        .vault
        .reveal_credentials(&id, &req.master_password)
        .map_err(ApiError::from)?;
    st.audit.record(
        crate::audit::AuditLog::entry("credential_reveal")
            .with_host(&id)
            .with_detail(json!({ "source": "web" })),
    );
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

#[derive(Deserialize)]
struct AuditQuery {
    #[serde(default = "default_limit")]
    limit: usize,
}
fn default_limit() -> usize {
    200
}

async fn get_audit(State(st): State<Shared>, Query(q): Query<AuditQuery>) -> ApiResult {
    let entries = st.audit.tail(q.limit.min(2000));
    Ok(Json(json!({ "entries": entries })))
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
