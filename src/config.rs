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

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServerSettings {
    pub addr: String,
    pub grace_period_sec: u64,
    pub log_level: String,
    pub http_addr: Option<String>,
    pub metrics_addr: Option<String>,
    pub tls: Option<TlsSettings>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UpstreamRoute {
    pub path: String,
    pub backends: Vec<String>,
    pub tls: bool,
    pub host_header: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UpstreamSettings {
    pub routes: Vec<UpstreamRoute>,
    pub fallback: Option<UpstreamRoute>,
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
