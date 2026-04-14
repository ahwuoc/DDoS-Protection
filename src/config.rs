use serde::{Deserialize, Serialize};
use std::fs;
use tracing::{info, warn};

const CONFIG_PATH: &str = "config.json";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Mapping {
    pub name: String,
    pub listen_addr: String,
    pub target_port: u16,
    pub allowed_countries: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub target_ip: String,
    pub allowed_countries: Option<Vec<String>>, // Danh sách mặc định cho server này
    pub mappings: Vec<Mapping>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub servers: Vec<ServerConfig>,
    pub connection: ConnectionConfig,
    pub rate_limit: RateLimitConfig,
    pub protection: ProtectionConfig,
    pub geo: GeoConfig,
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
    pub subnet_strike_threshold: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GeoConfig {
    pub enabled: bool,
    pub asn_db_path: String,
    pub country_db_path: String,
    pub datacenter_max_connects_per_minute: u32,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            servers: vec![ServerConfig {
                target_ip: "146.190.88.68".to_string(),
                allowed_countries: Some(vec!["VN".to_string(), "JP".to_string(), "US".to_string()]),
                mappings: vec![
                    Mapping {
                        name: "Game Port".to_string(),
                        listen_addr: "0.0.0.0:14443".to_string(),
                        target_port: 14443,
                        allowed_countries: None,
                    },
                    Mapping {
                        name: "Database Port".to_string(),
                        listen_addr: "0.0.0.0:3306".to_string(),
                        target_port: 3306,
                        allowed_countries: Some(vec!["VN".to_string()]),
                    },
                ],
            }],
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
                subnet_strike_threshold: 3,
            },
            geo: GeoConfig {
                enabled: false,
                asn_db_path: "geoip/GeoLite2-ASN.mmdb".to_string(),
                country_db_path: "geoip/GeoLite2-Country.mmdb".to_string(),
                datacenter_max_connects_per_minute: 10,
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
