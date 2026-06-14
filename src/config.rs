use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AcmeSettings {
    pub enabled: bool,
    pub domains: Vec<String>,
    pub email: String,
    #[serde(default = "default_staging")]
    pub staging: bool,
    #[serde(default = "default_cache_dir")]
    pub cache_dir: String,
    pub directory_url: Option<String>,
}

fn default_staging() -> bool {
    true
}

fn default_cache_dir() -> String {
    "certs".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TlsSettings {
    pub enabled: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub acme: Option<AcmeSettings>,
}

/// Maps a JWT/ID-token claim to an HTTP header injected into the upstream request.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OidcAttribute {
    /// The claim name inside the ID token (e.g. "email", "sub", "preferred_username").
    pub claim: String,
    /// The HTTP header name to inject (e.g. "X-Auth-Email", "X-Auth-User").
    pub header: String,
}

/// OIDC Relying-Party configuration for a single route.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OidcSettings {
    pub client_id: String,
    pub client_secret: String,
    /// Authorization endpoint of the Identity Provider (e.g. "https://idp.example.com/authorize").
    pub auth_url: String,
    /// Token endpoint of the Identity Provider (e.g. "https://idp.example.com/token").
    pub token_url: String,
    /// The redirect/callback URI registered with the IdP (e.g. "https://myproxy.example.com/_oidc/callback").
    pub redirect_uri: String,
    /// Optional list of scopes to request. Defaults to ["openid"].
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// Claim-to-header mappings injected into the proxied request.
    #[serde(default)]
    pub attributes: Vec<OidcAttribute>,
}

fn default_scopes() -> Vec<String> {
    vec!["openid".to_string()]
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServerSettings {
    pub addr: String,
    pub grace_period_sec: u64,
    pub log_level: String,
    pub http_addr: Option<String>,
    pub metrics_addr: Option<String>,
    pub tls: Option<TlsSettings>,
    /// Base64-encoded 32-byte secret used to sign the local OIDC session cookie.
    /// If omitted, a random secret is generated at startup.
    pub cookie_secret: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UpstreamRoute {
    pub path: String,
    pub backends: Vec<String>,
    pub tls: bool,
    pub host_header: String,
    #[serde(default = "default_health_check")]
    pub health_check: bool,
    /// Upstream protocol: "http1" for HTTP/1.1, "http2" (default) for HTTP/2 / h2c / gRPC.
    #[serde(default = "default_protocol")]
    pub protocol: String,
    /// Optional per-route OIDC configuration. When set, unauthenticated requests are
    /// redirected to the IdP, and authenticated claims are injected as headers.
    pub oidc: Option<OidcSettings>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UpstreamSettings {
    pub routes: Vec<UpstreamRoute>,
    pub fallback: Option<UpstreamRoute>,
}

fn default_health_check() -> bool {
    true
}

fn default_protocol() -> String {
    "http2".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Settings {
    pub server: ServerSettings,
    pub upstream: UpstreamSettings,
}

impl Settings {
    pub fn new<P: AsRef<Path>>(config_path: P) -> Result<Self, config::ConfigError> {
        let s = config::Config::builder()
            .add_source(config::File::from(config_path.as_ref()))
            // Allow environment variables to override settings (e.g. GPROXY_SERVER__ADDR)
            .add_source(config::Environment::with_prefix("GPROXY").separator("__"))
            .build()?;
        s.try_deserialize()
    }
}
