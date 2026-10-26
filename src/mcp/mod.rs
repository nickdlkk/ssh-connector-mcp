//! MCP server: the AI-facing tool surface.
//!
//! Security invariant: tools here NEVER return credential plaintext. Host
//! creation/update accepts secrets (write-only), but every read path returns
//! redacted summaries. Credential reveal is exclusively a Web-UI (human) action
//! gated on the master password and is deliberately absent from this surface.
//!
//! Two transports share one tool router:
//! - `serve_http` mounts a Streamable-HTTP service into the daemon's axum app.
//! - `run_stdio_shim` is a thin stdio<->HTTP forwarder so editors that speak
//!   stdio MCP can reach a already-running daemon.

use crate::error::ConnectorError;
use crate::jumpserver::{Account, Asset};
use crate::state::AppState;
use crate::types::{ExecPayload, HostSpec, KeyName};
use base64::Engine;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::ToolCallContext;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::{CallToolResult, JsonObject, ServerCapabilities, ServerInfo};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData, ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::sync::Arc;

const SERVER_INSTRUCTIONS: &str = "SSH maintenance connector. When the user asks to operate SSH hosts, remote Linux \
machines, VPS instances, or server-side files and commands that are available in this connector, prefer these MCP tools over spawning local `ssh`, `scp`, or `sftp` shell commands. Start with `host_list` to discover configured hosts and connection state. For JumpServer asset/account lookup, use `jumpserver_search_asset_accounts` with a machine-name/FQDN/IP fragment to return matching host metadata and non-secret accounts in one call. Use `jumpserver_asset_list` and `jumpserver_asset_accounts` when you need separate discovery steps or the full inventory. For file operations, pass the discovered `asset_id` and authorized `account_id` to the JumpServer-specific `jumpserver_sftp_*` tools, which use KoKo's SFTP subsystem. These tools resolve the asset/account through the configured JumpServer API and must not use ordinary `host_id` SFTP tools for JumpServer targets. Direct `exec` and ordinary `session_open`/`session_open_root` are forbidden for recognized JumpServer-managed targets; they return `jumpserver_exec_denied` before making an SSH connection. Do not manually add a host for each JumpServer asset or use a direct connection as a fallback. Use `host_connect` only for explicit checks of persisted hosts. JumpServer errors are structured: HTTP 401 means credentials/signature may be expired/revoked/invalid or system clock may be skewed; HTTP 403 means permission/org scope may be insufficient; HTTP 404 is NOT evidence of expired authorization and can mean an asset/account binding, visibility, or API route/version problem. For 404, refresh the asset list once and compare one known control asset; preserve status/endpoint, do not guess IDs, loop retries, or fall back to direct SSH. Ask a JumpServer administrator to verify API credentials, organization and the asset's account binding. Hosts and credentials are managed by a human via the Web UI or config-file provider; credentials are never returned. Use `exec` only for isolated one-shot commands on ordinary SSH hosts, `script` for multi-line non-interactive work on ordinary SSH hosts, `raw` only when you intentionally own shell quoting, `session_open` for stateful work on ordinary hosts, `session_open_root` for configured su escalation on ordinary hosts, and SFTP tools for file transfer.";

fn err_to_mcp(e: ConnectorError) -> ErrorData {
    // Surface our structured error code + context as MCP error data so the AI
    // can branch on `code` (e.g. host_key_mismatch vs auth_failed).
    let stable_code = e.code.as_str();
    let mut data = serde_json::to_value(&e).ok();
    if let Some(object) = data.as_mut().and_then(Value::as_object_mut) {
        object.insert("code".into(), Value::String(stable_code.into()));
    }
    if matches!(
        e.code,
        crate::error::ErrorCode::JumpServerExecDenied
            | crate::error::ErrorCode::JumpServerSessionRequired
    ) {
        return ErrorData::new(
            rmcp::model::ErrorCode::INVALID_PARAMS,
            e.message.clone(),
            data,
        );
    }
    ErrorData::internal_error(e.message.clone(), data)
}

// --- Tool request types (AI-facing input schemas) ---

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TotpUnlockRequest {
    pub code: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddHostRequest {
    #[serde(flatten)]
    pub spec: HostSpec,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateHostRequest {
    pub host_id: String,
    #[serde(flatten)]
    pub spec: HostSpec,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct HostIdRequest {
    pub host_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExecRequest {
    pub host_id: String,
    /// Preferred one-shot command form. Exactly one of argv, script, or raw must be provided.
    #[serde(default)]
    pub argv: Option<Vec<String>>,
    /// Multi-line shell script content. Exactly one of argv, script, or raw must be provided.
    #[serde(default)]
    pub script: Option<String>,
    /// Raw command string. Exactly one of argv, script, or raw must be provided.
    #[serde(default)]
    pub raw: Option<String>,
}

struct NormalizedExecRequest {
    host_id: String,
    payload: ExecPayload,
}

fn exec_payload_from_request(req: ExecRequest) -> Result<NormalizedExecRequest, ErrorData> {
    let selected = [
        req.argv.as_ref().map(|_| "argv"),
        req.script.as_ref().map(|_| "script"),
        req.raw.as_ref().map(|_| "raw"),
    ]
    .into_iter()
    .flatten()
    .count();

    if selected != 1 {
        return Err(ErrorData::invalid_params(
            "exec requires exactly one of argv, script, or raw",
            None,
        ));
    }

    let payload = if let Some(argv) = req.argv {
        ExecPayload::Argv { argv }
    } else if let Some(script) = req.script {
        ExecPayload::Script { script }
    } else if let Some(raw) = req.raw {
        ExecPayload::Raw { raw }
    } else {
        unreachable!("selected count was checked");
    };

    Ok(NormalizedExecRequest {
        host_id: req.host_id,
        payload,
    })
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct JumpServerSftpRequest {
    pub asset_id: String,
    pub account_id: String,
    pub path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct JumpServerSftpPutRequest {
    pub asset_id: String,
    pub account_id: String,
    pub path: String,
    pub content: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct JumpServerSftpPutBase64Request {
    pub asset_id: String,
    pub account_id: String,
    pub path: String,
    pub content_base64: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct JumpServerSftpDownloadRequest {
    pub asset_id: String,
    pub account_id: String,
    pub remote_path: String,
    pub local_path: String,
    #[serde(default)]
    pub overwrite: bool,
    #[serde(default = "default_true")]
    pub create_parent_dirs: bool,
    #[serde(default = "default_transfer_chunk_size")]
    pub chunk_size_bytes: usize,
    #[serde(default = "default_true")]
    pub verify_sha256: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct JumpServerSftpUploadRequest {
    pub asset_id: String,
    pub account_id: String,
    pub local_path: String,
    pub remote_path: String,
    #[serde(default)]
    pub overwrite: bool,
    #[serde(default = "default_true")]
    pub create_parent_dirs: bool,
    #[serde(default = "default_transfer_chunk_size")]
    pub chunk_size_bytes: usize,
    #[serde(default = "default_true")]
    pub verify_sha256: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct OpenPtyRequest {
    pub host_id: String,
    #[serde(default = "default_rows")]
    pub rows: u16,
    #[serde(default = "default_cols")]
    pub cols: u16,
}

fn default_rows() -> u16 {
    24
}
fn default_cols() -> u16 {
    80
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SessionExecRequest {
    pub session_id: String,
    /// One single-line raw shell command, executed in the existing shell.
    pub raw: String,
    /// Maximum initial wait in milliseconds. Defaults to 5000; maximum 300000.
    #[serde(default)]
    pub wait_ms: Option<u64>,
    /// Maximum merged PTY output bytes. Defaults to configured output cap; maximum 1048576.
    pub max_output_bytes: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SessionExecReadRequest {
    pub session_id: String,
    /// Opaque token returned while session_exec is still running.
    pub token: String,
    /// Optional long-poll duration in milliseconds. Defaults to 0; max 300000.
    #[serde(default)]
    pub wait_ms: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SessionIdRequest {
    pub session_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SendTextRequest {
    pub session_id: String,
    pub text: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SendKeyRequest {
    pub session_id: String,
    pub key: KeyName,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ResizeRequest {
    pub session_id: String,
    pub rows: u16,
    pub cols: u16,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SftpListRequest {
    pub host_id: String,
    pub path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SftpGetRequest {
    pub host_id: String,
    pub path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SftpPutRequest {
    pub host_id: String,
    pub path: String,
    /// File content. Text is sent as-is (UTF-8).
    pub content: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SftpPutBase64Request {
    pub host_id: String,
    pub path: String,
    /// Base64-encoded file content for small binary-safe uploads.
    pub content_base64: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SftpDownloadFileRequest {
    pub host_id: String,
    pub remote_path: String,
    /// Local destination path. Must be under /tmp or the daemon's current project directory.
    pub local_path: String,
    /// Defaults to false. Set true to overwrite an existing local destination.
    #[serde(default)]
    pub overwrite: bool,
    /// Create missing local parent directories. Defaults to true.
    #[serde(default = "default_true")]
    pub create_parent_dirs: bool,
    /// Streaming buffer size, from 64 KiB through 8 MiB. Defaults to 256 KiB.
    #[serde(default = "default_transfer_chunk_size")]
    pub chunk_size_bytes: usize,
    /// Compare the received stream, local temp file, and remote SHA-256. Defaults to true.
    #[serde(default = "default_true")]
    pub verify_sha256: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SftpUploadFileRequest {
    pub host_id: String,
    /// Local source file path. Must be under /tmp or the daemon's current project directory.
    pub local_path: String,
    pub remote_path: String,
    /// Defaults to false. Set true to replace an existing remote file.
    #[serde(default)]
    pub overwrite: bool,
    /// Create missing remote parent directories. Defaults to true.
    #[serde(default = "default_true")]
    pub create_parent_dirs: bool,
    /// Streaming buffer size, from 64 KiB through 8 MiB. Defaults to 256 KiB.
    #[serde(default = "default_transfer_chunk_size")]
    pub chunk_size_bytes: usize,
    /// Compare local and server-side SHA-256 before commit. Defaults to true.
    #[serde(default = "default_true")]
    pub verify_sha256: bool,
}

fn default_true() -> bool {
    true
}

fn default_transfer_chunk_size() -> usize {
    256 * 1024
}

/// The MCP tool server. Clones share one `Arc<AppState>`.
#[derive(Clone)]
pub struct McpServer {
    state: Arc<AppState>,
    tool_router: ToolRouter<Self>,
}

// --- Tool output types (need object-rooted JSON schemas for MCP) ---

use crate::types::{DirEntry, HostSummary, SessionInfo};

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct HostListResult {
    pub hosts: Vec<HostSummary>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct JumpServerAssetListResult {
    pub assets: Vec<Asset>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct JumpServerAccountListResult {
    pub accounts: Vec<Account>,
}

#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
pub struct JumpServerAccountSearchItem {
    pub id: String,
    pub name: Option<String>,
    pub username: Option<String>,
    pub privileged: Option<bool>,
    pub secret_type: Option<serde_json::Value>,
}

#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
pub struct JumpServerAssetAccountSearchResult {
    pub asset_id: String,
    pub name: String,
    pub address: String,
    pub platform: Option<serde_json::Value>,
    pub protocols: Vec<crate::jumpserver::Protocol>,
    pub accounts: Vec<JumpServerAccountSearchItem>,
    pub account_lookup_error: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct JumpServerAssetSearchRequest {
    /// Case-insensitive substring to match against asset name or address (hostname/FQDN/IP).
    pub query: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct JumpServerAssetAccountsRequest {
    pub asset_id: String,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct JumpServerAccountSearchResult {
    pub matches: Vec<JumpServerAssetAccountSearchResult>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct JumpServerSessionOpenRequest {
    pub asset_id: String,
    pub account_id: String,
    #[serde(default = "default_rows")]
    pub rows: u16,
    #[serde(default = "default_cols")]
    pub cols: u16,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct HostIdResult {
    pub host_id: String,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct OkResult {
    pub ok: bool,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct ConnectResult {
    pub status: String,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct SessionListResult {
    pub sessions: Vec<SessionInfo>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct SftpListResult {
    pub entries: Vec<DirEntry>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct SftpGetResult {
    pub content: String,
    pub bytes: usize,
    pub had_invalid_utf8: bool,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct SftpGetBase64Result {
    pub content_base64: String,
    pub bytes: usize,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct SftpFileTransferResult {
    pub local_path: String,
    pub remote_path: String,
    pub bytes: u64,
    pub sha256: String,
    pub verified: bool,
}

impl McpServer {
    pub fn new(state: Arc<AppState>) -> Self {
        let mut tool_router = Self::tool_router();
        sanitize_tool_schemas_for_ai_clients(&mut tool_router);
        Self { state, tool_router }
    }
}

/// Codex and some OpenAI-compatible clients are stricter than full JSON Schema:
/// they expect OpenAI function-style parameter schemas and may reject a whole
/// MCP server when any tool advertises `oneOf`, `$defs/$ref`, nullable type
/// arrays, or Rust-specific integer formats. Keep the business structs typed,
/// but publish a conservative schema surface.
fn sanitize_tool_schemas_for_ai_clients(router: &mut ToolRouter<McpServer>) {
    for route in router.map.values_mut() {
        route.attr.input_schema = Arc::new(sanitize_schema_object(&route.attr.input_schema));
        route.attr.output_schema = None;
    }
}

fn sanitize_schema_object(schema: &JsonObject) -> JsonObject {
    let mut root = Value::Object(schema.clone());
    let defs = root
        .get("$defs")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    sanitize_schema_value(&mut root, &defs);
    match root {
        Value::Object(map) => map,
        _ => JsonObject::new(),
    }
}

fn sanitize_schema_value(value: &mut Value, defs: &Map<String, Value>) {
    match value {
        Value::Object(map) => {
            if let Some(replacement) = expand_ref(map, defs) {
                *value = replacement;
                sanitize_schema_value(value, defs);
                return;
            }

            let one_of = map.remove("oneOf").or_else(|| map.remove("anyOf"));
            if let Some(Value::Array(variants)) = one_of {
                merge_variants_into_object(map, variants, defs);
            }

            map.remove("$schema");
            map.remove("$defs");
            map.remove("format");
            map.remove("const");

            if let Some(Value::Array(types)) = map.get_mut("type") {
                let first_non_null = types
                    .iter()
                    .find(|ty| ty.as_str() != Some("null"))
                    .cloned()
                    .unwrap_or_else(|| Value::String("string".to_string()));
                map.insert("type".to_string(), first_non_null);
            }

            for child in map.values_mut() {
                sanitize_schema_value(child, defs);
            }
        }
        Value::Array(items) => {
            for item in items {
                sanitize_schema_value(item, defs);
            }
        }
        _ => {}
    }
}

fn expand_ref(map: &Map<String, Value>, defs: &Map<String, Value>) -> Option<Value> {
    let ref_name = map
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|s| s.strip_prefix("#/$defs/"))?;
    let mut replacement = defs.get(ref_name)?.clone();
    if let (Value::Object(dst), Some(description)) =
        (&mut replacement, map.get("description").cloned())
    {
        dst.entry("description".to_string()).or_insert(description);
    }
    Some(replacement)
}

fn merge_variants_into_object(
    map: &mut Map<String, Value>,
    variants: Vec<Value>,
    defs: &Map<String, Value>,
) {
    let mut merged_props = Map::new();
    let mut enum_values = Vec::new();

    for mut variant in variants {
        sanitize_schema_value(&mut variant, defs);
        let Value::Object(obj) = variant else {
            continue;
        };

        if let Some(Value::Array(values)) = obj.get("enum") {
            enum_values.extend(values.iter().cloned());
        }

        if let Some(Value::Object(props)) = obj.get("properties") {
            for (key, value) in props {
                merged_props
                    .entry(key.clone())
                    .or_insert_with(|| value.clone());
            }
        }
    }

    if !merged_props.is_empty() {
        let props = map
            .entry("properties".to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(existing) = props {
            for (key, value) in merged_props {
                existing.entry(key).or_insert(value);
            }
        }
    }

    if !enum_values.is_empty() {
        map.insert("enum".to_string(), Value::Array(enum_values));
        map.insert("type".to_string(), Value::String("string".to_string()));
    } else {
        map.entry("type".to_string())
            .or_insert_with(|| Value::String("object".to_string()));
    }

    // The runtime still validates the real typed shape. For schema conversion,
    // optional is better than advertising impossible cross-variant requirements.
    map.remove("required");
}

#[tool_router]
impl McpServer {
    #[tool(
        description = "Unlock the Vault with a human-provided current 6-digit TOTP code. Ask the user for the code first; never guess, retry automatically, or repeat the code. The code is not retained in audit records."
    )]
    async fn vault_unlock_totp(
        &self,
        Parameters(req): Parameters<TotpUnlockRequest>,
    ) -> Result<Json<OkResult>, ErrorData> {
        self.state
            .vault
            .unlock_with_totp(&self.state.totp, &req.code)
            .map_err(|_| ErrorData::invalid_params("invalid code", None))?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(
        description = "List all configured hosts with connection status. Returns redacted summaries only — never credentials."
    )]
    async fn host_list(&self) -> Result<Json<HostListResult>, ErrorData> {
        let hosts = self.state.list_hosts().await.map_err(err_to_mcp)?;
        Ok(Json(HostListResult { hosts }))
    }

    #[tool(
        description = "Create a new SSH host and encrypted credential entry. Required fields: alias, host, user, auth. Optional fields: port (default 22), jump_hosts, env, become_root. Auth is a tagged object: password = {\"type\":\"password\",\"password\":\"...\"}; private_key = {\"type\":\"private_key\",\"key_pem\":\"-----BEGIN OPENSSH PRIVATE KEY-----\\n...\",\"passphrase\":\"optional\"}; keyboard_interactive = {\"type\":\"keyboard_interactive\",\"answers\":[\"answer1\",\"answer2\"]}. jump_hosts is an ordered bastion chain: [{\"host\":\"bastion.example.com\",\"port\":22,\"user\":\"root\",\"auth\":{...}}], and each hop has its own auth object. become_root enables login-as-user-then-su workflows for session_open_root: {\"enabled\":true,\"command\":\"su -\",\"password\":\"root-password\",\"prompt_timeout_ms\":5000}. env is a string key/value object applied to interactive sessions. Secrets are stored encrypted and are write-only to AI; read tools return redacted summaries. Returns the new host_id."
    )]
    async fn host_add(
        &self,
        Parameters(req): Parameters<AddHostRequest>,
    ) -> Result<Json<HostIdResult>, ErrorData> {
        let host_id = self.state.add_host(req.spec).map_err(err_to_mcp)?;
        Ok(Json(HostIdResult { host_id }))
    }

    #[tool(
        description = "Update an existing host wholesale by host_id. Provide host_id plus the same full host shape as host_add: alias, host, user, auth, optional port, optional jump_hosts, optional env, optional become_root. Auth shapes are: {\"type\":\"password\",\"password\":\"...\"}, {\"type\":\"private_key\",\"key_pem\":\"-----BEGIN OPENSSH PRIVATE KEY-----\\n...\",\"passphrase\":\"optional\"}, or {\"type\":\"keyboard_interactive\",\"answers\":[\"answer1\",\"answer2\"]}. jump_hosts entries are {host, port, user, auth} and each hop authenticates independently. become_root is {\"enabled\":true,\"command\":\"su -\",\"password\":\"root-password\",\"prompt_timeout_ms\":5000} for session_open_root."
    )]
    async fn host_update(
        &self,
        Parameters(req): Parameters<UpdateHostRequest>,
    ) -> Result<Json<OkResult>, ErrorData> {
        if self
            .state
            .is_jumpserver_target(&req.host_id)
            .map_err(err_to_mcp)?
        {
            return Err(err_to_mcp(crate::state::jumpserver_session_required()));
        }
        self.state
            .update_host(&req.host_id, req.spec)
            .map_err(err_to_mcp)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(description = "Delete a host and drop any live connection.")]
    async fn host_remove(
        &self,
        Parameters(req): Parameters<HostIdRequest>,
    ) -> Result<Json<OkResult>, ErrorData> {
        if self
            .state
            .is_jumpserver_target(&req.host_id)
            .map_err(err_to_mcp)?
        {
            return Err(err_to_mcp(crate::state::jumpserver_session_required()));
        }
        self.state
            .remove_host(&req.host_id)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(
        description = "Open/establish the SSH transport to a host (runs the full jump chain and host-key TOFU). Idempotent."
    )]
    async fn host_connect(
        &self,
        Parameters(req): Parameters<HostIdRequest>,
    ) -> Result<Json<ConnectResult>, ErrorData> {
        self.state
            .connect_host(&req.host_id)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(ConnectResult {
            status: "connected".into(),
        }))
    }

    #[tool(
        description = "Disconnect and drop a host's live SSH transport. One-shot exec, PTY, and SFTP can reconnect on demand later."
    )]
    async fn host_disconnect(
        &self,
        Parameters(req): Parameters<HostIdRequest>,
    ) -> Result<Json<ConnectResult>, ErrorData> {
        self.state
            .disconnect_host(&req.host_id)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(ConnectResult {
            status: "disconnected".into(),
        }))
    }

    #[tool(
        description = "Run a one-shot command and wait for it to finish on ordinary SSH hosts. Direct exec is forbidden for JumpServer-managed targets and returns jumpserver_exec_denied; use jumpserver_session_open and reuse its session_id with session tools instead. Choose exactly one payload: argv (array, auto-quoted), script (multi-line), or raw (caller owns quoting). Returns stdout/stderr/exit_code with truncation and timeout flags."
    )]
    async fn exec(
        &self,
        Parameters(req): Parameters<ExecRequest>,
    ) -> Result<Json<crate::types::ExecResult>, ErrorData> {
        let payload = exec_payload_from_request(req)?;
        let r = self
            .state
            .exec(&payload.host_id, &payload.payload)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(r))
    }

    #[tool(
        description = "List assets available from the configured JumpServer API. Returns metadata only; no credentials or secrets."
    )]
    async fn jumpserver_asset_list(&self) -> Result<Json<JumpServerAssetListResult>, ErrorData> {
        let assets = self.state.jumpserver_assets().await.map_err(err_to_mcp)?;
        Ok(Json(JumpServerAssetListResult { assets }))
    }

    #[tool(
        description = "Search JumpServer assets by case-insensitive substring of machine name or address (hostname/FQDN/IP), and return each matching host's non-secret account metadata in one call."
    )]
    async fn jumpserver_search_asset_accounts(
        &self,
        Parameters(req): Parameters<JumpServerAssetSearchRequest>,
    ) -> Result<Json<JumpServerAccountSearchResult>, ErrorData> {
        let query = req.query.trim();
        if query.is_empty() {
            return Err(ErrorData::invalid_params("query must not be empty", None));
        }
        let assets = self.state.jumpserver_assets().await.map_err(err_to_mcp)?;
        let matches: Vec<_> = assets
            .into_iter()
            .filter(|asset| asset.name.to_lowercase().contains(&query.to_lowercase())
                || asset.address.to_lowercase().contains(&query.to_lowercase()))
            .map(|asset| async move {
                let (accounts, account_lookup_error) = match self.state.jumpserver_accounts(&asset.id).await {
                    Ok(accounts) => (accounts.into_iter().map(|account| JumpServerAccountSearchItem {
                        id: account.id,
                        name: account.name,
                        username: account.username,
                        privileged: account.privileged,
                        secret_type: account.secret_type,
                    }).collect(), None),
                    Err(error) => (Vec::new(), Some(format!("{}: {}", error.code.as_str(), error.message))),
                };
                JumpServerAssetAccountSearchResult {
                    asset_id: asset.id,
                    name: asset.name,
                    address: asset.address,
                    platform: asset.platform,
                    protocols: asset.protocols,
                    accounts,
                    account_lookup_error,
                }
            })
            .collect::<Vec<_>>();
        let matches = futures_util::future::join_all(matches).await;
        Ok(Json(JumpServerAccountSearchResult { matches }))
    }

    #[tool(
        description = "List JumpServer-managed accounts for an asset discovered by jumpserver_asset_list. Returns account metadata only; credentials are never returned."
    )]
    async fn jumpserver_asset_accounts(
        &self,
        Parameters(req): Parameters<JumpServerAssetAccountsRequest>,
    ) -> Result<Json<JumpServerAccountListResult>, ErrorData> {
        let accounts = self
            .state
            .jumpserver_accounts(&req.asset_id)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(JumpServerAccountListResult { accounts }))
    }

    #[tool(
        description = "Open a persistent PTY through JumpServer for an API-discovered asset/account. This is the supported way to access JumpServer-managed targets; direct exec and ordinary session_open are denied for those targets. Reuse the returned session_id with session_send_text, session_read, session_exec, and other session tools; do not open a new session for each command."
    )]
    async fn jumpserver_session_open(
        &self,
        Parameters(req): Parameters<JumpServerSessionOpenRequest>,
    ) -> Result<Json<crate::types::SessionInfo>, ErrorData> {
        let info = self
            .state
            .jumpserver_asset_session(&req.asset_id, &req.account_id, req.rows, req.cols)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(info))
    }

    #[tool(
        description = "Open a persistent interactive PTY session (stateful shell) on an ordinary SSH host. For JumpServer-managed assets, use jumpserver_session_open; this tool is rejected for recognized JumpServer targets. Returns session metadata including session_id."
    )]
    async fn session_open(
        &self,
        Parameters(req): Parameters<OpenPtyRequest>,
    ) -> Result<Json<crate::types::SessionInfo>, ErrorData> {
        let info = self
            .state
            .open_pty(&req.host_id, req.rows, req.cols)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(info))
    }

    #[tool(
        description = "Open a persistent interactive PTY session and automatically become root using the host's encrypted become_root config. Configure hosts with become_root: {\"enabled\":true,\"command\":\"su -\",\"password\":\"root-password\",\"prompt_timeout_ms\":5000}. This is for login-as-user-then-`su` workflows; it does not expose the root password to the AI."
    )]
    async fn session_open_root(
        &self,
        Parameters(req): Parameters<OpenPtyRequest>,
    ) -> Result<Json<crate::types::SessionInfo>, ErrorData> {
        let info = self
            .state
            .open_root_pty(&req.host_id, req.rows, req.cols)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(info))
    }

    #[tool(description = "List all live PTY sessions with idle TTL remaining.")]
    async fn session_list(&self) -> Result<Json<SessionListResult>, ErrorData> {
        let sessions = self.state.list_sessions().await;
        Ok(Json(SessionListResult { sessions }))
    }

    #[tool(
        description = "Execute one single-line raw shell command in an existing PTY shell, preserving shell state and keeping the session open. Unlike exec, it uses the existing PTY; stdout/stderr are merged. The command may change remote state. Initial wait_ms defaults to 5000 and only limits this call; expiration does not cancel the remote command. If still running, timed_out=true and an opaque token is returned for session_exec_read. Concurrent commands and terminal input are rejected as session_busy while it runs. Audit stores metadata only, not command or output."
    )]
    async fn session_exec(
        &self,
        Parameters(req): Parameters<SessionExecRequest>,
    ) -> Result<Json<crate::types::SessionExecResult>, ErrorData> {
        if req.wait_ms.is_some_and(|n| n > 300_000) {
            return Err(ErrorData::invalid_params(
                "wait_ms must be at most 300000",
                None,
            ));
        }
        if req.max_output_bytes == Some(0) || req.max_output_bytes.is_some_and(|n| n > 1_048_576) {
            return Err(ErrorData::invalid_params(
                "max_output_bytes must be between 1 and 1048576",
                None,
            ));
        }
        let result = self
            .state
            .pty_exec(&req.session_id, &req.raw, req.wait_ms, req.max_output_bytes)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(result))
    }

    #[tool(
        description = "Poll a running session_exec command using its opaque token. Returns only output produced since the previous poll. If still running, timed_out=true and the same token is returned; when finished, exit_code is returned and token becomes null. This does not cancel or interrupt the command."
    )]
    async fn session_exec_read(
        &self,
        Parameters(req): Parameters<SessionExecReadRequest>,
    ) -> Result<Json<crate::types::SessionExecResult>, ErrorData> {
        if req.wait_ms.is_some_and(|n| n > 300_000) {
            return Err(ErrorData::invalid_params(
                "wait_ms must be at most 300000",
                None,
            ));
        }
        let result = self
            .state
            .pty_exec_read(&req.session_id, &req.token, req.wait_ms)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(result))
    }

    #[tool(
        description = "Send literal text to a PTY session's stdin (no implicit newline — include \\n or use a key to submit)."
    )]
    async fn session_send_text(
        &self,
        Parameters(req): Parameters<SendTextRequest>,
    ) -> Result<Json<OkResult>, ErrorData> {
        self.state
            .pty_send_text(&req.session_id, &req.text)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(
        description = "Send a semantic key (enter, tab, up, ctrl_c, f(n), etc.) to a PTY session."
    )]
    async fn session_send_key(
        &self,
        Parameters(req): Parameters<SendKeyRequest>,
    ) -> Result<Json<OkResult>, ErrorData> {
        self.state
            .pty_send_key(&req.session_id, &req.key)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(
        description = "Get a structured snapshot of a PTY session's current screen (rows of text, cursor, attributes, alt-screen flag, seq)."
    )]
    async fn session_screen(
        &self,
        Parameters(req): Parameters<SessionIdRequest>,
    ) -> Result<Json<crate::types::ScreenSnapshot>, ErrorData> {
        let snap = self
            .state
            .pty_snapshot(&req.session_id)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(snap))
    }

    #[tool(
        description = "Read newly produced text from a PTY session since the last read. Includes a heuristic likely_waiting_input flag."
    )]
    async fn session_read(
        &self,
        Parameters(req): Parameters<SessionIdRequest>,
    ) -> Result<Json<crate::types::ReadResult>, ErrorData> {
        let r = self
            .state
            .pty_read(&req.session_id)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(r))
    }

    #[tool(description = "Resize a PTY session's terminal.")]
    async fn session_resize(
        &self,
        Parameters(req): Parameters<ResizeRequest>,
    ) -> Result<Json<OkResult>, ErrorData> {
        self.state
            .pty_resize(&req.session_id, req.rows, req.cols)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(description = "Close a PTY session and free its channel.")]
    async fn session_close(
        &self,
        Parameters(req): Parameters<SessionIdRequest>,
    ) -> Result<Json<OkResult>, ErrorData> {
        self.state
            .close_pty(&req.session_id)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(description = "List files in an authorized JumpServer asset directory via KoKo SFTP. Requires asset_id/account_id from the JumpServer API discovery tools.")]
    async fn jumpserver_sftp_list(&self, Parameters(req): Parameters<JumpServerSftpRequest>) -> Result<Json<SftpListResult>, ErrorData> {
        let entries = self.state.jumpserver_sftp_list(&req.asset_id, &req.account_id, &req.path).await.map_err(err_to_mcp)?;
        Ok(Json(SftpListResult { entries }))
    }

    #[tool(description = "Read a UTF-8 text file from an authorized JumpServer asset via KoKo SFTP.")]
    async fn jumpserver_sftp_get(&self, Parameters(req): Parameters<JumpServerSftpRequest>) -> Result<Json<SftpGetResult>, ErrorData> {
        let bytes = self.state.jumpserver_sftp_get(&req.asset_id, &req.account_id, &req.path).await.map_err(err_to_mcp)?;
        let (content, had_invalid_utf8) = match std::str::from_utf8(&bytes) { Ok(s) => (s.to_string(), false), Err(_) => (String::from_utf8_lossy(&bytes).into_owned(), true) };
        Ok(Json(SftpGetResult { content, bytes: bytes.len(), had_invalid_utf8 }))
    }

    #[tool(description = "Write a UTF-8 text file to an authorized JumpServer asset via KoKo SFTP; overwrites the destination.")]
    async fn jumpserver_sftp_put(&self, Parameters(req): Parameters<JumpServerSftpPutRequest>) -> Result<Json<OkResult>, ErrorData> {
        self.state.jumpserver_sftp_put(&req.asset_id, &req.account_id, &req.path, req.content.as_bytes()).await.map_err(err_to_mcp)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(description = "Upload a small binary file to an authorized JumpServer asset via KoKo SFTP using base64; overwrites the destination.")]
    async fn jumpserver_sftp_put_base64(&self, Parameters(req): Parameters<JumpServerSftpPutBase64Request>) -> Result<Json<OkResult>, ErrorData> {
        let bytes = base64::engine::general_purpose::STANDARD.decode(req.content_base64.as_bytes()).map_err(|e| ErrorData::invalid_params(format!("invalid base64 content: {e}"), None))?;
        self.state.jumpserver_sftp_put(&req.asset_id, &req.account_id, &req.path, &bytes).await.map_err(err_to_mcp)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(description = "Download a file from an authorized JumpServer asset via KoKo SFTP to a local path. Uses streaming chunks, SHA-256 verification, and the local path safety restrictions.")]
    async fn jumpserver_sftp_download_file(&self, Parameters(req): Parameters<JumpServerSftpDownloadRequest>) -> Result<Json<SftpFileTransferResult>, ErrorData> {
        let r = self.state.jumpserver_sftp_download_file(&req.asset_id, &req.account_id, &req.remote_path, &req.local_path, req.overwrite, req.create_parent_dirs, req.chunk_size_bytes, req.verify_sha256).await.map_err(err_to_mcp)?;
        Ok(Json(SftpFileTransferResult { local_path: r.local_path.display().to_string(), remote_path: r.remote_path, bytes: r.bytes, sha256: r.sha256, verified: r.verified }))
    }

    #[tool(description = "Upload a local file to an authorized JumpServer asset via KoKo SFTP. Uses streaming chunks, SHA-256 verification, remote temporary-file commit, and overwrite safety controls.")]
    async fn jumpserver_sftp_upload_file(&self, Parameters(req): Parameters<JumpServerSftpUploadRequest>) -> Result<Json<SftpFileTransferResult>, ErrorData> {
        let r = self.state.jumpserver_sftp_upload_file(&req.asset_id, &req.account_id, &req.local_path, &req.remote_path, req.overwrite, req.create_parent_dirs, req.chunk_size_bytes, req.verify_sha256).await.map_err(err_to_mcp)?;
        Ok(Json(SftpFileTransferResult { local_path: r.local_path.display().to_string(), remote_path: r.remote_path, bytes: r.bytes, sha256: r.sha256, verified: r.verified }))
    }

    #[tool(description = "List a remote directory over SFTP.")]
    async fn sftp_list(
        &self,
        Parameters(req): Parameters<SftpListRequest>,
    ) -> Result<Json<SftpListResult>, ErrorData> {
        let entries = self
            .state
            .sftp_list(&req.host_id, &req.path)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(SftpListResult { entries }))
    }

    #[tool(
        description = "Read a remote text file over SFTP. Returns content as a UTF-8 string (invalid bytes are flagged)."
    )]
    async fn sftp_get(
        &self,
        Parameters(req): Parameters<SftpGetRequest>,
    ) -> Result<Json<SftpGetResult>, ErrorData> {
        let bytes = self
            .state
            .sftp_get(&req.host_id, &req.path)
            .await
            .map_err(err_to_mcp)?;
        let (content, had_invalid_utf8) = match std::str::from_utf8(&bytes) {
            Ok(s) => (s.to_string(), false),
            Err(_) => (String::from_utf8_lossy(&bytes).into_owned(), true),
        };
        Ok(Json(SftpGetResult {
            content,
            bytes: bytes.len(),
            had_invalid_utf8,
        }))
    }

    #[tool(
        description = "Read a small remote file over SFTP as base64. Use only for small binary files where returning content in the MCP response is acceptable. For large files, archives, APKs, zip/tar/gz, installers, images, or anything likely to exceed context limits, use sftp_download_file instead."
    )]
    async fn sftp_get_base64(
        &self,
        Parameters(req): Parameters<SftpGetRequest>,
    ) -> Result<Json<SftpGetBase64Result>, ErrorData> {
        let bytes = self
            .state
            .sftp_get(&req.host_id, &req.path)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(SftpGetBase64Result {
            content_base64: base64::engine::general_purpose::STANDARD.encode(&bytes),
            bytes: bytes.len(),
        }))
    }

    #[tool(description = "Write a remote UTF-8 text file over SFTP (overwrites).")]
    async fn sftp_put(
        &self,
        Parameters(req): Parameters<SftpPutRequest>,
    ) -> Result<Json<OkResult>, ErrorData> {
        self.state
            .sftp_put(&req.host_id, &req.path, req.content.as_bytes())
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(
        description = "Write a small remote file over SFTP from base64 (overwrites). Use only for small binary payloads. For large files, archives, APKs, zip/tar/gz, installers, images, or anything likely to exceed context limits, put the file under /tmp or the current project and use sftp_upload_file instead."
    )]
    async fn sftp_put_base64(
        &self,
        Parameters(req): Parameters<SftpPutBase64Request>,
    ) -> Result<Json<OkResult>, ErrorData> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(req.content_base64.as_bytes())
            .map_err(|e| ErrorData::invalid_params(format!("invalid base64 content: {e}"), None))?;
        self.state
            .sftp_put(&req.host_id, &req.path, &bytes)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(
        description = "Atomically download a remote file over SFTP to a local path without putting content in MCP context. local_path must be under /tmp or the daemon's current project. The transfer streams in configurable chunks to a same-directory .part file, creates missing local parents by default, fsyncs, verifies size and SHA-256 by default, then commits without exposing a partial destination. overwrite defaults to false. Returns bytes, sha256, and verified. Prefer this for large binaries, archives, APKs, installers, images, and exact-byte transfers."
    )]
    async fn sftp_download_file(
        &self,
        Parameters(req): Parameters<SftpDownloadFileRequest>,
    ) -> Result<Json<SftpFileTransferResult>, ErrorData> {
        let r = self
            .state
            .sftp_download_file(
                &req.host_id,
                &req.remote_path,
                &req.local_path,
                req.overwrite,
                req.create_parent_dirs,
                req.chunk_size_bytes,
                req.verify_sha256,
            )
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(SftpFileTransferResult {
            local_path: r.local_path.display().to_string(),
            remote_path: r.remote_path,
            bytes: r.bytes,
            sha256: r.sha256,
            verified: r.verified,
        }))
    }

    #[tool(
        description = "Atomically upload a local file over SFTP without putting content in MCP parameters. local_path must be under /tmp or the daemon's current project. The transfer streams in configurable chunks to a same-directory remote .part file, creates missing remote parents by default, verifies remote size and SHA-256 by default, then renames into place. overwrite defaults to false and uses a rollback backup when replacing. Failed transfers remove temporary files. Returns bytes, sha256, and verified. Prefer this for large binaries, archives, APKs, installers, images, and exact-byte transfers."
    )]
    async fn sftp_upload_file(
        &self,
        Parameters(req): Parameters<SftpUploadFileRequest>,
    ) -> Result<Json<SftpFileTransferResult>, ErrorData> {
        let r = self
            .state
            .sftp_upload_file(
                &req.host_id,
                &req.local_path,
                &req.remote_path,
                req.overwrite,
                req.create_parent_dirs,
                req.chunk_size_bytes,
                req.verify_sha256,
            )
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(SftpFileTransferResult {
            local_path: r.local_path.display().to_string(),
            remote_path: r.remote_path,
            bytes: r.bytes,
            sha256: r.sha256,
            verified: r.verified,
        }))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for McpServer {
    fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResult, ErrorData>> + Send + '_ {
        async move {
            let method = request.name.to_string();
            let input = crate::mcp_audit_policy::sanitize_input(Value::Object(
                request.arguments.clone().unwrap_or_default(),
            ));
            let started = std::time::Instant::now();
            let input_copy = input.clone();
            let result = self
                .tool_router
                .call(ToolCallContext::new(self, request, context))
                .await;
            let elapsed = started.elapsed().as_millis() as i64;
            match result {
                Ok(output) => {
                    let output_value = Some(crate::mcp_audit_policy::sanitize_output(
                        &serde_json::to_value(&output).unwrap_or(Value::Null),
                        &method,
                    ));
                    let audit_result = self.state.audit.try_record_fields(
                        crate::audit::AuditLog::entry(&method),
                        "mcp",
                        input,
                        output_value,
                        Some(elapsed),
                        None,
                        None,
                        None,
                    );
                    if let Err(error) = audit_result {
                        tracing::error!(target:"audit",method=%method,"mandatory MCP audit failed: {error}");
                        return Err(ErrorData::internal_error(
                            "audit unavailable".to_string(),
                            None,
                        ));
                    }
                    Ok(output)
                }
                Err(error) => {
                    // Persist the stable public policy code, not Rust's Debug
                    // spelling (for example `JumpServerExecDenied`).
                    let code = error.data.as_ref().and_then(|d| d.get("code")).and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| error.code.0.to_string());
                    let audit_result = self.state.audit.try_record_fields(
                        crate::audit::AuditLog::entry(&method),
                        "mcp",
                        input_copy,
                        Some(serde_json::json!({"error_code":code})),
                        Some(elapsed),
                        None,
                        None,
                        Some(&code),
                    );
                    if let Err(audit_error) = audit_result {
                        tracing::error!(target:"audit",method=%method,"mandatory MCP audit failed for error response: {audit_error}");
                        return Err(ErrorData::internal_error(
                            "audit unavailable".to_string(),
                            None,
                        ));
                    }
                    Err(error)
                }
            }
        }
    }

    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(SERVER_INSTRUCTIONS)
    }
}

use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};

/// Build a Streamable-HTTP MCP service that the daemon mounts under `/mcp`.
/// Each connection gets a fresh `McpServer` sharing the same `AppState`.
pub fn build_http_service(
    state: Arc<AppState>,
) -> StreamableHttpService<McpServer, LocalSessionManager> {
    StreamableHttpService::new(
        move || Ok(McpServer::new(state.clone())),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    )
}

/// Serve the MCP tool surface over stdio (for editors that speak stdio MCP).
/// Spins up its own full `AppState`; runs until the client disconnects.
pub async fn serve_stdio(state: Arc<AppState>) -> anyhow::Result<()> {
    use rmcp::ServiceExt;
    use rmcp::transport::stdio;
    let service = McpServer::new(state).serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jumpserver_policy_error_keeps_stable_code_in_mcp_structured_data() {
        for code in [
            crate::error::ErrorCode::JumpServerExecDenied,
            crate::error::ErrorCode::JumpServerSessionRequired,
        ] {
            let error = ConnectorError::new(code, "policy rejected");
            let mcp_error = err_to_mcp(error);
            assert_eq!(mcp_error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
            assert_eq!(
                mcp_error.data.as_ref().and_then(|data| data.get("code")).and_then(Value::as_str),
                Some(code.as_str())
            );
        }
    }

    #[test]
    fn ai_tool_surface_has_transfers_but_no_credential_reveal() {
        let router = McpServer::tool_router();
        let names: Vec<String> = router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.into_owned())
            .collect();
        assert!(names.iter().any(|name| name == "sftp_download_file"));
        assert!(names.iter().any(|name| name == "sftp_upload_file"));
        assert!(names.iter().any(|name| name == "jumpserver_sftp_list"));
        assert!(names.iter().any(|name| name == "jumpserver_sftp_get"));
        assert!(names.iter().any(|name| name == "jumpserver_sftp_put"));
        assert!(names.iter().any(|name| name == "jumpserver_sftp_put_base64"));
        assert!(names.iter().any(|name| name == "jumpserver_sftp_download_file"));
        assert!(names.iter().any(|name| name == "jumpserver_sftp_upload_file"));
        assert!(names.iter().any(|name| name == "jumpserver_search_asset_accounts"));
        assert!(names.iter().any(|name| name == "session_exec"));
        assert!(names.iter().any(|name| name == "session_exec_read"));
        assert!(names.iter().any(|name| name == "vault_unlock_totp"));
        assert!(!names.iter().any(|name| name.contains("reveal")));
        assert!(!names.iter().any(|name| name.contains("credential_get")));
    }

    #[test]
    fn totp_request_schema_requires_six_digit_code() {
        let mut router = McpServer::tool_router();
        sanitize_tool_schemas_for_ai_clients(&mut router);
        let tool = router.get("vault_unlock_totp").unwrap();
        let props = tool.input_schema["properties"].as_object().unwrap();
        assert!(props.contains_key("code"));
        assert!(
            tool.input_schema["required"]
                .as_array()
                .is_some_and(|a| a.iter().any(|v| v == "code"))
        );
        let desc = tool.description.as_deref().unwrap_or_default();
        assert!(desc.contains("Ask the user"));
        assert!(desc.contains("never guess"));
    }

    #[test]
    fn large_transfer_schema_exposes_safety_controls() {
        let mut router = McpServer::tool_router();
        sanitize_tool_schemas_for_ai_clients(&mut router);
        let upload = router.get("sftp_upload_file").unwrap();
        let properties = upload.input_schema["properties"].as_object().unwrap();
        for field in [
            "overwrite",
            "create_parent_dirs",
            "chunk_size_bytes",
            "verify_sha256",
        ] {
            assert!(properties.contains_key(field), "missing {field}");
        }
    }

    #[test]
    fn initialization_instructions_explain_jumpserver_auth_and_404() {
        assert!(SERVER_INSTRUCTIONS.contains("HTTP 401"));
        assert!(SERVER_INSTRUCTIONS.contains("HTTP 404 is NOT evidence of expired authorization"));
        assert!(SERVER_INSTRUCTIONS.contains("do not guess IDs"));
        assert!(SERVER_INSTRUCTIONS.contains("Direct `exec`"));
        assert!(SERVER_INSTRUCTIONS.contains("Do not manually add a host for each JumpServer asset"));
    }

    #[test]
    fn jumpserver_tool_descriptions_require_session_reuse() {
        let router = McpServer::tool_router();
        let exec = router.get("exec").unwrap();
        let exec_description = exec.description.as_deref().unwrap_or_default();
        assert!(exec_description.contains("forbidden for JumpServer-managed targets"));
        assert!(exec_description.contains("jumpserver_session_open"));

        let open = router.get("jumpserver_session_open").unwrap();
        let open_description = open.description.as_deref().unwrap_or_default().to_ascii_lowercase();
        assert!(open_description.contains("reuse the returned session_id"));
        assert!(open_description.contains("do not open a new session"));
    }
}
