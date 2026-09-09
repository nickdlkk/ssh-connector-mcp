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
            return Err(ConnectorError::new(
                ErrorCode::AuthFailed,
                format!("JumpServer API returned HTTP {status}"),
            ));
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
