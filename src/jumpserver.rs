//! JumpServer API-backed asset/account discovery and KoKo target resolution.
use crate::config::JumpServerConfig;
use crate::error::{ConnectorError, ErrorCode, Result};
use crate::types::{AuthMethod, HostConfig};
use base64::Engine;
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, Default)]
pub struct Asset {
    pub id: String,
    pub name: String,
    pub address: String,
    #[serde(default)]
    pub platform: Option<serde_json::Value>,
    #[serde(default)]
    pub protocols: Vec<Protocol>,
    #[serde(default)]
    pub accounts_amount: Option<u64>,
    /// JumpServer node/group path or object, depending on API version.
    #[serde(default)]
    pub node: Option<serde_json::Value>,
    #[serde(default)]
    pub nodes: Vec<serde_json::Value>,
    #[serde(default)]
    pub labels: Vec<serde_json::Value>,
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, Default)]
pub struct Protocol {
    pub name: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, Default)]
pub struct Account {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub privileged: Option<bool>,
    /// May be a string or an object in different JumpServer versions.
    #[serde(default)]
    pub secret_type: Option<serde_json::Value>,
    #[serde(default)]
    pub asset: Option<serde_json::Value>,
    #[serde(default)]
    pub account: Option<serde_json::Value>,
    #[serde(default)]
    pub account_template: Option<serde_json::Value>,
    #[serde(default)]
    pub account_group: Option<serde_json::Value>,
    #[serde(default)]
    pub groups: Vec<serde_json::Value>,
    #[serde(default)]
    pub labels: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct Page<T> {
    #[serde(default)]
    results: Vec<T>,
}

#[derive(Debug, Clone)]
pub struct JumpServerClient {
    cfg: JumpServerConfig,
    http: Client,
}

impl JumpServerClient {
    pub fn new(cfg: JumpServerConfig) -> Result<Self> {
        let http = Client::builder()
            .danger_accept_invalid_certs(!cfg.verify_tls)
            .build()
            .map_err(|e| ConnectorError::internal(format!("build JumpServer HTTP client: {e}")))?;
        Ok(Self { cfg, http })
    }

    fn api_url(&self, path: &str) -> String {
        format!("{}{}", self.cfg.api_url.trim_end_matches('/'), path)
    }

    fn secret(&self, env_name: &str) -> Result<String> {
        std::env::var(env_name).map_err(|_| {
            ConnectorError::new(
                ErrorCode::AuthFailed,
                format!("JumpServer credential env var {env_name} is not set"),
            )
        })
    }

    pub fn ssh_password_host_id(&self) -> &str {
        &self.cfg.ssh_password_host_id
    }

    fn signed_headers(&self, method: &str, path_and_query: &str) -> Result<Vec<(String, String)>> {
        let ak = self.secret(&self.cfg.api_access_key_env)?;
        let sk = self.secret(&self.cfg.api_secret_key_env)?;
        let date = httpdate::fmt_http_date(std::time::SystemTime::now());
        let canonical = format!(
            "(request-target): {} {}\naccept: application/json\ndate: {}",
            method.to_lowercase(),
            path_and_query,
            date
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(sk.as_bytes())
            .map_err(|_| ConnectorError::internal("invalid JumpServer secret key"))?;
        mac.update(canonical.as_bytes());
        let sig = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        Ok(vec![
            ("Accept".into(), "application/json".into()),
            ("Date".into(), date),
            ("X-JMS-ORG".into(), self.cfg.org_id.clone()),
            (
                "Authorization".into(),
                format!(
                    "Signature keyId=\"{ak}\",algorithm=\"hmac-sha256\",headers=\"(request-target) accept date\",signature=\"{sig}\""
                ),
            ),
        ])
    }

    async fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
        let url = self.api_url(path);
        let parsed = reqwest::Url::parse(&url)
            .map_err(|e| ConnectorError::internal(format!("invalid JumpServer URL: {e}")))?;
        let signed_path = match parsed.query() {
            Some(query) => format!("{}?{}", parsed.path(), query),
            None => parsed.path().to_string(),
        };
        let mut req = self.http.get(url);
        for (key, value) in self.signed_headers("GET", &signed_path)? {
            req = req.header(key, value);
        }
        let resp = req.send().await.map_err(|e| {
            ConnectorError::new(ErrorCode::SshConnectFailed, format!("JumpServer API request failed: {e}"))
        })?;
        let status = resp.status();
        if !status.is_success() {
            let status_code = status.as_u16();
            let message = match status_code {
                401 => "JumpServer API returned HTTP 401 Unauthorized. The API access key/signature may be expired, revoked, clock-skewed, or invalid. Ask an administrator to verify/renew the configured JumpServer API credentials and system time; do not retry the same request or try alternate credentials.".to_string(),
                403 => "JumpServer API returned HTTP 403 Forbidden. The API credential was recognized but may lack permission for this operation/asset, or the requested organization is not accessible. Ask a JumpServer administrator to verify organization and least-privilege API permissions.".to_string(),
                404 => format!("JumpServer API returned HTTP 404 Not Found for endpoint `{}`. This is not proof that authentication expired: it can indicate an inaccessible/missing asset or account binding, wrong API route/version, or object-scoped visibility. Re-discover the asset once and compare a known control asset; do not invent IDs or fall back to a direct connection.", parsed.path()),
                _ => format!("JumpServer API returned HTTP {status} for endpoint `{}`.", parsed.path()),
            };
            let code = if status_code == 401 || status_code == 403 { ErrorCode::AuthFailed } else { ErrorCode::JumpServerApiError };
            return Err(ConnectorError::new(code, message).with_context(serde_json::json!({"http_status":status_code,"endpoint":parsed.path()})));
        }
        resp.json::<T>()
            .await
            .map_err(|e| ConnectorError::internal(format!("decode JumpServer API response: {e}")))
    }

    pub async fn list_assets(&self) -> Result<Vec<Asset>> {
        let page: Page<Asset> = self.get("/api/v1/assets/hosts/?limit=100").await?;
        Ok(page.results)
    }

    pub async fn list_asset_accounts(&self, asset_id: &str) -> Result<Vec<Account>> {
        let asset: serde_json::Value = self.get(&format!("/api/v1/assets/hosts/{asset_id}/")).await?;
        let accounts = asset.get("accounts").and_then(serde_json::Value::as_array).cloned().unwrap_or_default();
        accounts.into_iter().map(|value| serde_json::from_value(value).map_err(|e| ConnectorError::internal(format!("decode JumpServer account: {e}")))).collect()
    }

    pub async fn list_accounts(&self, asset_id: &str) -> Result<Vec<Account>> {
        self.list_asset_accounts(asset_id).await
    }

    pub async fn resolve_target(&self, asset_id: &str, account_id: &str, ssh_auth: AuthMethod) -> Result<HostConfig> {
        let asset = self.list_assets().await?.into_iter().find(|asset| asset.id == asset_id)
            .ok_or_else(|| ConnectorError::bad_request(format!("JumpServer asset not found: {asset_id}")))?;
        let account = self.list_asset_accounts(asset_id).await?.into_iter().find(|account| account.id == account_id)
            .ok_or_else(|| ConnectorError::bad_request(format!("JumpServer account not found: {account_id}")))?;
        let username = account.username.or(account.name).ok_or_else(|| ConnectorError::bad_request("JumpServer account has no username"))?;
        if !asset.protocols.iter().any(|p| p.name.eq_ignore_ascii_case("ssh")) { return Err(ConnectorError::bad_request(format!("asset {} has no SSH protocol", asset.name))); }
        Ok(HostConfig { id: format!("jms:{asset_id}:{account_id}"), alias: format!("{} / {}", asset.name, username), host: self.cfg.koko_host.clone(), port: self.cfg.koko_port, user: format!("{}@{}@{}", self.cfg.ssh_username, username, asset.address), auth: ssh_auth, jump_hosts: vec![], env: Default::default(), become_root: None })
    }

}

pub type SharedJumpServer = Arc<JumpServerClient>;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn mock_response(status: u16, body: &'static str) -> String {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 8192];
            let _ = stream.read(&mut request).await.unwrap();
            let reason = if status == 401 { "Unauthorized" } else if status == 403 { "Forbidden" } else if status == 404 { "Not Found" } else { "Internal Server Error" };
            let response = format!("HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        format!("http://{address}")
    }

    fn client(base: String) -> JumpServerClient {
        JumpServerClient::new(JumpServerConfig { api_url:base, org_id:"org".into(), api_access_key_env:"TEST_AK".into(), api_secret_key_env:"TEST_SK".into(), ssh_username:"u".into(), ssh_password_host_id:"h".into(), koko_host:"koko".into(), koko_port:2222, verify_tls:false }).unwrap()
    }

    #[tokio::test]
    async fn classifies_jumpserver_expired_auth_and_account_404_separately() {
        // SAFETY: these test-only variables are unique to this test and are not
        // read or modified by any other test or production task.
        unsafe {
            std::env::set_var("TEST_AK", "ak");
            std::env::set_var("TEST_SK", "sk");
        }
        let unauthorized=client(mock_response(401,"{}").await).get::<serde_json::Value>("/api/v1/assets/hosts/").await.unwrap_err();
        assert_eq!(unauthorized.code, ErrorCode::AuthFailed);
        assert!(unauthorized.message.contains("expired"));
        assert_eq!(unauthorized.context.as_ref().unwrap()["http_status"],401);

        let forbidden=client(mock_response(403,"{}").await).get::<serde_json::Value>("/api/v1/assets/hosts/").await.unwrap_err();
        assert_eq!(forbidden.code, ErrorCode::AuthFailed);
        assert!(forbidden.message.contains("permission"));

        let missing=client(mock_response(404,"{}").await).get::<serde_json::Value>("/api/v1/assets/hosts/nas/").await.unwrap_err();
        assert_eq!(missing.code, ErrorCode::JumpServerApiError);
        assert!(missing.message.contains("not proof that authentication expired"));
        assert_eq!(missing.context.as_ref().unwrap()["endpoint"],"/api/v1/assets/hosts/nas/");
        unsafe {
            std::env::remove_var("TEST_AK");
            std::env::remove_var("TEST_SK");
        }
    }
}
