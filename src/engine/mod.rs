pub mod constants;
pub mod core;
pub mod geo;
pub mod ops;
pub mod stats;
pub mod tasks;

use crate::config::AppConfig;
use crate::db::IpDatabase;
use crate::kernel::KernelFirewall;
use crate::tracker::*;
use arc_swap::ArcSwap;
use dashmap::{DashMap, DashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

pub struct ConnectionTracker {
    pub(crate) stats: Arc<DashMap<IpAddr, IpStats>>,
    pub(crate) permanent_bans: Arc<DashSet<IpAddr>>,
    pub(crate) whitelist: Arc<DashSet<IpAddr>>,
    pub(crate) kernel_fw: Arc<KernelFirewall>,
    pub(crate) config: Arc<ArcSwap<AppConfig>>,
    pub(crate) subnet_strikes: Arc<DashMap<String, u32>>,
    pub(crate) asn_reader: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
    pub(crate) country_reader: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
    pub(crate) ban_queue: Arc<Mutex<Vec<Ipv4Addr>>>,
    pub(crate) db_ban_queue: Arc<Mutex<Vec<(String, u32, String, String, String)>>>,
    pub(crate) db: Arc<IpDatabase>,
    pub(crate) active_listeners: Arc<DashSet<String>>,
}

impl ConnectionTracker {
    pub fn new(
        config: Arc<AppConfig>,
        kernel_fw: Arc<KernelFirewall>,
        db: Arc<IpDatabase>,
    ) -> Self {
        let mut asn_reader: Option<Arc<maxminddb::Reader<Vec<u8>>>> = None;
        let mut country_reader: Option<Arc<maxminddb::Reader<Vec<u8>>>> = None;

        if config.geo.enabled {
            match maxminddb::Reader::open_readfile(&config.geo.asn_db_path) {
                Ok(r) => {
                    info!("Loaded MaxMind ASN DB from {}", config.geo.asn_db_path);
                    asn_reader = Some(Arc::new(r));
                }
                Err(e) => warn!(
                    "Failed to load MaxMind ASN DB {}: {e}",
                    config.geo.asn_db_path
                ),
            }
            match maxminddb::Reader::open_readfile(&config.geo.country_db_path) {
                Ok(r) => {
                    info!(
                        "Loaded MaxMind Country DB from {}",
                        config.geo.country_db_path
                    );
                    country_reader = Some(Arc::new(r));
                }
                Err(e) => warn!(
                    "Failed to load MaxMind Country DB {}: {e}",
                    config.geo.country_db_path
                ),
            }
        }

        let tracker = Self {
            stats: Arc::new(DashMap::new()),
            permanent_bans: Arc::new(DashSet::new()),
            whitelist: Arc::new(DashSet::new()),
            kernel_fw,
            config: Arc::new(ArcSwap::from(config)),
            subnet_strikes: Arc::new(DashMap::new()),
            asn_reader,
            country_reader,
            ban_queue: Arc::new(Mutex::new(Vec::new())),
            db_ban_queue: Arc::new(Mutex::new(Vec::new())),
            db: db.clone(),
            active_listeners: Arc::new(DashSet::new()),
        };

        if tracker.db.is_whitelist_empty() && tracker.db.blacklist_count() == 0 {
            if let Err(e) = tracker.db.migrate_ips_from_files() {
                warn!("Failed to migrate legacy files: {e}");
            }
        }

        tracker.load_banned_ips();
        tracker.load_whitelist_ips();
        tracker
    }

    pub fn reload_config(&self, new_config: Arc<AppConfig>) {
        self.config.store(new_config);
        info!("ConnectionTracker configuration reloaded");
    }
}
