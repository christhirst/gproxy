use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct ServerSettings {
    pub addr: String,
    pub grace_period_sec: u64,
    pub log_level: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UpstreamSettings {
    pub backends: Vec<String>,
    pub tls: bool,
    pub host_header: String,
}

#[derive(Debug, Deserialize, Clone)]
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
