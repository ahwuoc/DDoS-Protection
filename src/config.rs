use serde::{Deserialize, Serialize};
use std::fs;
use tracing::{info, warn};

const CONFIG_PATH: &str = "config.json";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Mapping {
    pub name: String,
    pub listen_addr: String,
    pub target_addr: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub mappings: Vec<Mapping>,
    pub connection: ConnectionConfig,
    pub rate_limit: RateLimitConfig,
    pub protection: ProtectionConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionConfig {
    pub max_connections_per_ip: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub window_secs: u64,
    pub max_connects_per_window: u32,
    pub max_connects_per_minute: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtectionConfig {
    pub blacklist_duration_secs: u64,
    pub whitelist_after_secs: u64,
    pub strikes_before_ban: u32,
    pub max_syn_per_sec: u32,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            mappings: vec![
                Mapping {
                    name: "Game Port".to_string(),
                    listen_addr: "0.0.0.0:14443".to_string(),
                    target_addr: "127.0.0.1:14443".to_string(),
                }
            ],
            connection: ConnectionConfig {
                max_connections_per_ip: 5,
            },
            rate_limit: RateLimitConfig {
                window_secs: 2,
                max_connects_per_window: 8,
                max_connects_per_minute: 100,
            },
            protection: ProtectionConfig {
                blacklist_duration_secs: 30,
                whitelist_after_secs: 30,
                strikes_before_ban: 3,
                max_syn_per_sec: 100,
            },
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
}
