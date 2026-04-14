use crate::config::AppConfig;
use crate::kernel::KernelFirewall;
use dashmap::{DashMap, DashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

const BANNED_FILE: &str = "banned_ips.txt";
const WHITELIST_FILE: &str = "whitelist_ips.txt";
const CLEANUP_INTERVAL_SECS: u64 = 900;

#[derive(Clone, Debug)]
struct IpStats {
    active_connections: usize,
    connects_in_window: u32,
    window_start: Instant,
    minute_start: Instant,
    connects_in_minute: u32,
    blacklisted_until: Option<Instant>,
    strikes: u32,
}

impl Default for IpStats {
    fn default() -> Self {
        Self {
            active_connections: 0,
            connects_in_window: 0,
            window_start: Instant::now(),
            minute_start: Instant::now(),
            connects_in_minute: 0,
            blacklisted_until: None,
            strikes: 0,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum CheckResult {
    Allowed,
    Rejected(&'static str),
    BannedPermanently(&'static str),
}

pub struct IpInfo {
    pub country: String,
    pub asn_org: String,
}

pub struct ConnectionTracker {
    stats: Arc<DashMap<String, IpStats>>,
    permanent_bans: Arc<DashSet<String>>,
    whitelist: Arc<DashSet<String>>,
    kernel_fw: Arc<KernelFirewall>,
    config: Arc<AppConfig>,
    subnet_strikes: Arc<DashMap<String, u32>>,
    asn_reader: Option<maxminddb::Reader<Vec<u8>>>,
    country_reader: Option<maxminddb::Reader<Vec<u8>>>,
}

impl ConnectionTracker {
    pub fn new(config: Arc<AppConfig>, kernel_fw: Arc<KernelFirewall>) -> Self {
        let mut asn_reader = None;
        let mut country_reader = None;

        if config.geo.enabled {
            match maxminddb::Reader::open_readfile(&config.geo.asn_db_path) {
                Ok(r) => {
                    info!("Loaded MaxMind ASN DB from {}", config.geo.asn_db_path);
                    asn_reader = Some(r);
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
                    country_reader = Some(r);
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
            config,
            subnet_strikes: Arc::new(DashMap::new()),
            asn_reader,
            country_reader,
        };
        tracker.load_banned_ips();
        tracker.load_whitelist_ips();
        tracker
    }

    fn load_banned_ips(&self) {
        if let Ok(data) = fs::read_to_string(BANNED_FILE) {
            for line in data.lines() {
                let ip = line.split("] ").nth(1).unwrap_or(line).trim();
                if !ip.is_empty() {
                    self.permanent_bans.insert(ip.to_string());
                    if let Ok(ipv4) = ip.parse::<Ipv4Addr>() {
                        let _ = self.kernel_fw.ban(ipv4);
                    }
                }
            }
        }
    }

    fn load_whitelist_ips(&self) {
        if let Ok(data) = fs::read_to_string(WHITELIST_FILE) {
            for line in data.lines() {
                let ip = line.trim();
                if !ip.is_empty() {
                    self.whitelist.insert(ip.to_string());
                    if let Ok(ipv4) = ip.parse::<Ipv4Addr>() {
                        let _ = self.kernel_fw.whitelist(ipv4);
                    }
                }
            }
        }
        if !self.whitelist.is_empty() {
            info!(
                count = self.whitelist.len(),
                "Loaded whitelisted IPs from {WHITELIST_FILE}"
            );
        }
    }

    pub fn is_permanently_banned(&self, ip: IpAddr) -> bool {
        self.permanent_bans.contains(&ip.to_string())
    }

    pub fn is_whitelisted(&self, ip: IpAddr) -> bool {
        self.whitelist.contains(&ip.to_string())
    }

    pub fn check_and_track(
        &self,
        ip: IpAddr,
        specific_allowed: Option<&Vec<String>>,
    ) -> CheckResult {
        if self.is_whitelisted(ip) {
            return CheckResult::Allowed;
        }

        let ip_str = ip.to_string();
        let mut stats = self.stats.entry(ip_str.clone()).or_default();
        let now = Instant::now();
        let cfg = &self.config;

        // --- Geo/ASN Filtering ---
        if cfg.geo.enabled {
            // 1. Check Country
            if let Some(ref reader) = self.country_reader {
                if let Ok(country) = reader.lookup::<maxminddb::geoip2::Country>(ip) {
                    if let Some(c) = country.country {
                        if let Some(iso) = c.iso_code {
                            let iso_code = iso.to_string();

                            // Nếu có cấu hình danh sách riêng thì mới check, không thì cho qua
                            if let Some(allowed_list) = specific_allowed {
                                if !allowed_list.contains(&iso_code) {
                                    return CheckResult::Rejected(
                                        "GEO BLOCKED: COUNTRY NOT ALLOWED",
                                    );
                                }
                            }
                        }
                    }
                }
            }

            // 2. Check ASN / Datacenter
            if let Some(ref reader) = self.asn_reader {
                if let Ok(asn) = reader.lookup::<maxminddb::geoip2::Asn>(ip) {
                    if let Some(org) = asn.autonomous_system_organization {
                        let org_lower = org.to_lowercase();
                        let is_dc = org_lower.contains("digitalocean")
                            || org_lower.contains("amazon")
                            || org_lower.contains("google")
                            || org_lower.contains("hetzner")
                            || org_lower.contains("ovh")
                            || org_lower.contains("microsoft")
                            || org_lower.contains("alibaba")
                            || org_lower.contains("tencent")
                            || org_lower.contains("vultr")
                            || org_lower.contains("linode")
                            || org_lower.contains("choopa")
                            || org_lower.contains("m247");

                        if is_dc
                            && stats.connects_in_minute
                                >= cfg.geo.datacenter_max_connects_per_minute
                        {
                            stats.strikes += 1;
                            return CheckResult::Rejected("DATACENTER RATE LIMIT");
                        }
                    }
                }
            }
        }

        if let Some(until) = stats.blacklisted_until {
            if now < until {
                return CheckResult::Rejected("TEMP BLACKLISTED");
            }
            stats.blacklisted_until = None;
        }

        if now.duration_since(stats.window_start) > Duration::from_secs(cfg.rate_limit.window_secs)
        {
            stats.window_start = now;
            stats.connects_in_window = 0;
        }
        stats.connects_in_window += 1;

        if now.duration_since(stats.minute_start) > Duration::from_secs(60) {
            stats.minute_start = now;
            stats.connects_in_minute = 0;
        }
        stats.connects_in_minute += 1;

        if stats.connects_in_window > cfg.rate_limit.max_connects_per_window
            || stats.connects_in_minute > cfg.rate_limit.max_connects_per_minute
        {
            stats.strikes += 1;
            if cfg.protection.strikes_before_ban > 0
                && stats.strikes >= cfg.protection.strikes_before_ban
            {
                self.permanent_bans.insert(ip_str.clone());
                if let IpAddr::V4(ipv4) = ip {
                    let _ = self.kernel_fw.ban(ipv4);

                    let octets = ipv4.octets();
                    let subnet = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
                    let mut s_strikes = self.subnet_strikes.entry(subnet.clone()).or_insert(0);
                    *s_strikes += 1;

                    if *s_strikes >= cfg.protection.subnet_strike_threshold {
                        let _ = self.kernel_fw.ban_subnet(&subnet);
                    }
                }
                return CheckResult::BannedPermanently("STRIKE LIMIT → PERMANENT BAN");
            }

            let duration = cfg.protection.blacklist_duration_secs * stats.strikes as u64;
            stats.blacklisted_until = Some(now + Duration::from_secs(duration));
            return CheckResult::Rejected("RATE LIMIT → TEMP BLACKLIST");
        }

        if stats.active_connections >= cfg.connection.max_connections_per_ip {
            return CheckResult::Rejected("MAX CONCURRENCY");
        }

        stats.active_connections += 1;
        CheckResult::Allowed
    }

    pub fn release_connection(&self, ip: IpAddr) {
        if let Some(mut stats) = self.stats.get_mut(&ip.to_string()) {
            stats.active_connections = stats.active_connections.saturating_sub(1);
        }
    }

    pub async fn mark_as_good(&self, ip: IpAddr) {
        let ip_str = ip.to_string();
        if self.is_whitelisted(ip) {
            return;
        }

        info!(ip = %ip_str, "[*] IP verified as GOOD player -> Adding to Whitelist");
        self.whitelist.insert(ip_str.clone());

        if let Ok(ipv4) = ip_str.parse::<Ipv4Addr>() {
            let _ = self.kernel_fw.whitelist(ipv4);
        }
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(WHITELIST_FILE)
            .await
            .unwrap();
        let _ = file.write_all(format!("{}\n", ip_str).as_bytes()).await;
    }

    pub async fn persist_ban(ip: &str) {
        let Ok(mut file) = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(BANNED_FILE)
            .await
        else {
            return;
        };
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        let _ = file.write_all(format!("[{ts}] {ip}\n").as_bytes()).await;
    }

    pub fn get_ip_info(&self, ip: IpAddr) -> IpInfo {
        let mut country_code = "??".to_string();
        let mut org = "Unknown".to_string();

        if let Some(ref r) = self.country_reader {
            if let Ok(c) = r.lookup::<maxminddb::geoip2::Country>(ip) {
                country_code = c
                    .country
                    .and_then(|co| co.iso_code)
                    .unwrap_or("??")
                    .to_string();
            }
        }
        if let Some(ref r) = self.asn_reader {
            if let Ok(a) = r.lookup::<maxminddb::geoip2::Asn>(ip) {
                org = a
                    .autonomous_system_organization
                    .unwrap_or("Unknown")
                    .to_string();
            }
        }
        IpInfo {
            country: country_code,
            asn_org: org,
        }
    }

    pub fn spawn_cleanup_task(&self) {
        let stats = self.stats.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(CLEANUP_INTERVAL_SECS)).await;
                let now = Instant::now();
                stats.retain(|_, s| {
                    s.blacklisted_until.is_some_and(|until| now < until) || s.active_connections > 0
                });
            }
        });
    }
}
