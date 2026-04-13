use serde::{Deserialize, Serialize};
use std::fs;
use tracing::{info, warn};

const CONFIG_PATH: &str = "config.json";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub listen_addr: String,
    pub target_addr: String,

    pub max_connections_per_ip: usize,

    pub rate_limit_window_secs: u64,

    pub max_connects_per_window: u32,

    pub blacklist_duration_secs: u64,

    pub strikes_before_ban: u32,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:14443".to_string(),
            target_addr: "127.0.0.1:14445".to_string(),
            max_connections_per_ip: 5,
            rate_limit_window_secs: 2,
            max_connects_per_window: 8,
            blacklist_duration_secs: 30,
            strikes_before_ban: 3,
        }
    }
}

impl AppConfig {
    pub fn load() -> Self {
        match fs::read_to_string(CONFIG_PATH) {
            Ok(data) => match serde_json::from_str(&data) {
                Ok(cfg) => {
                    info!("Loaded config from {CONFIG_PATH}");
                    cfg
                }
                Err(e) => {
                    warn!(error = %e, "Failed to parse {CONFIG_PATH}, using defaults");
                    Self::default()
                }
            },
            Err(_) => {
                warn!("Config not found, creating default {CONFIG_PATH}");
                let cfg = Self::default();
                cfg.save();
                cfg
            }
        }
    }

    pub fn save(&self) {
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = fs::write(CONFIG_PATH, json);
        }
    }

    pub fn listen_port(&self) -> u16 {
        self.listen_addr
            .rsplit(":")
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or(14443)
    }
}
