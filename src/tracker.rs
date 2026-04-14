use crate::config::AppConfig;
use crate::kernel::KernelFirewall;
use anyhow::Result;
use arc_swap::ArcSwap;
use dashmap::{DashMap, DashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

const BANNED_FILE: &str = "banned_ips.txt";
const WHITELIST_FILE: &str = "whitelist_ips.txt";
const CLEANUP_INTERVAL_SECS: u64 = 900;

#[derive(Clone, Debug, PartialEq)]
pub enum IpStatus {
    Normal,
    Whitelisted,
    Banned,
    TempBlacklisted(Instant),
}

#[derive(Clone, Debug)]
struct IpStats {
    active_connections: usize,
    connects_in_window: u32,
    window_start: Instant,
    minute_start: Instant,
    connects_in_minute: u32,
    status: IpStatus,
    strikes: u32,
    /// Cached GeoIP country code (populated on first encounter)
    country: String,
    /// Cached ASN organization (populated on first encounter)
    asn_org: String,
}

impl Default for IpStats {
    fn default() -> Self {
        Self {
            active_connections: 0,
            connects_in_window: 0,
            window_start: Instant::now(),
            minute_start: Instant::now(),
            connects_in_minute: 0,
            status: IpStatus::Normal,
            strikes: 0,
            country: String::new(),
            asn_org: String::new(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum CheckResult {
    Allowed(IpInfo),
    Rejected(&'static str),
    BannedPermanently(&'static str),
}

#[derive(Debug, PartialEq, Clone)]
pub struct IpInfo {
    pub country: String,
    pub asn_org: String,
}

/// Snapshot of a single tracked IP for the realtime monitor
pub struct TrackedIpSnapshot {
    pub ip: IpAddr,
    pub active_connections: usize,
    pub connects_per_min: u32,
    pub strikes: u32,
    pub status: String,
    pub country: String,
    pub asn_org: String,
}

pub struct ConnectionTracker {
    stats: Arc<DashMap<IpAddr, IpStats>>,
    permanent_bans: Arc<DashSet<IpAddr>>,
    whitelist: Arc<DashSet<IpAddr>>,
    kernel_fw: Arc<KernelFirewall>,
    config: ArcSwap<AppConfig>,
    subnet_strikes: Arc<DashMap<String, u32>>,
    asn_reader: Option<maxminddb::Reader<Vec<u8>>>,
    country_reader: Option<maxminddb::Reader<Vec<u8>>>,
    /// Queue of IPs waiting to be banned in nftables (batched for performance)
    ban_queue: Arc<Mutex<Vec<Ipv4Addr>>>,
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
            config: ArcSwap::from(config),
            subnet_strikes: Arc::new(DashMap::new()),
            asn_reader,
            country_reader,
            ban_queue: Arc::new(Mutex::new(Vec::new())),
        };
        tracker.load_banned_ips();
        tracker.load_whitelist_ips();
        tracker
    }

    pub fn reload_config(&self, new_config: Arc<AppConfig>) {
        self.config.store(new_config);
        info!("ConnectionTracker configuration reloaded");
    }

    fn load_banned_ips(&self) {
        if let Ok(data) = fs::read_to_string(BANNED_FILE) {
            let mut ips_to_ban = Vec::new();
            for line in data.lines() {
                let ip_str = line.split("] ").nth(1).unwrap_or(line).trim();
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    self.permanent_bans.insert(ip);
                    if let IpAddr::V4(ipv4) = ip {
                        ips_to_ban.push(ipv4);
                    }
                }
            }
            if !ips_to_ban.is_empty() {
                let _ = self.kernel_fw.ban_bulk(ips_to_ban);
            }
        }
    }

    fn load_whitelist_ips(&self) {
        if let Ok(data) = fs::read_to_string(WHITELIST_FILE) {
            let mut ips_to_white = Vec::new();
            for line in data.lines() {
                let ip_str = line.trim();
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    self.whitelist.insert(ip);
                    if let IpAddr::V4(ipv4) = ip {
                        ips_to_white.push(ipv4);
                    }
                }
            }
            if !ips_to_white.is_empty() {
                let _ = self.kernel_fw.whitelist_bulk(ips_to_white);
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
        self.permanent_bans.contains(&ip)
    }

    pub fn unban(&self, ip: IpAddr) -> Result<()> {
        info!(ip = %ip, "[+] Unbanning IP...");
        self.permanent_bans.remove(&ip);
        if let IpAddr::V4(ipv4) = ip {
            let _ = self.kernel_fw.unban(ipv4);
        }

        let permanent_bans = self.permanent_bans.clone();
        tokio::spawn(async move {
            let mut data = String::new();
            for ban in permanent_bans.iter() {
                data.push_str(&format!("{}\n", ban.key()));
            }
            if let Err(e) = tokio::fs::write(BANNED_FILE, data).await {
                warn!("Failed to update {} after unban: {}", BANNED_FILE, e);
            }
        });

        Ok(())
    }

    pub fn list_banned_ips(&self) -> Vec<IpAddr> {
        self.permanent_bans.iter().map(|kv| *kv.key()).collect()
    }

    pub fn is_whitelisted(&self, ip: IpAddr) -> bool {
        self.whitelist.contains(&ip)
    }

    /// Lookup GeoIP info for an IP and cache it in the stats entry.
    /// Returns (country_code, asn_org) from cache or fresh lookup.
    fn ensure_geo_cached(&self, ip: IpAddr, stats: &mut IpStats) {
        // Already cached?
        if !stats.country.is_empty() {
            return;
        }

        // Lookup country
        if let Some(ref reader) = self.country_reader {
            if let Ok(c) = reader.lookup::<maxminddb::geoip2::Country>(ip) {
                stats.country = c
                    .country
                    .and_then(|co| co.iso_code)
                    .unwrap_or("??")
                    .to_string();
            }
        }
        if stats.country.is_empty() {
            stats.country = "??".to_string();
        }

        // Lookup ASN
        if let Some(ref reader) = self.asn_reader {
            if let Ok(a) = reader.lookup::<maxminddb::geoip2::Asn>(ip) {
                stats.asn_org = a
                    .autonomous_system_organization
                    .unwrap_or("Unknown")
                    .to_string();
            }
        }
        if stats.asn_org.is_empty() {
            stats.asn_org = "Unknown".to_string();
        }
    }

    /// Enqueue an IP for batched nftables ban (non-blocking).
    fn enqueue_ban(&self, ipv4: Ipv4Addr) {
        if let Ok(mut queue) = self.ban_queue.lock() {
            queue.push(ipv4);
        }
    }

    pub fn check_and_track(
        &self,
        ip: IpAddr,
        specific_allowed: Option<&Vec<String>>,
    ) -> CheckResult {
        if self.is_whitelisted(ip) {
            return CheckResult::Allowed(self.get_ip_info(ip));
        }

        let mut stats = self.stats.entry(ip).or_default();
        let now = Instant::now();
        let cfg = self.config.load();

        // Ensure GeoIP is cached on first encounter
        self.ensure_geo_cached(ip, &mut stats);
        let ip_info = IpInfo {
            country: stats.country.clone(),
            asn_org: stats.asn_org.clone(),
        };

        // --- Geo/ASN Filtering (using cached values) ---
        if cfg.geo.enabled {
            // 1. Check Country
            if let Some(allowed_list) = specific_allowed {
                if ip_info.country != "??" && !allowed_list.contains(&ip_info.country) {
                    return CheckResult::Rejected("GEO BLOCKED: COUNTRY NOT ALLOWED");
                }
            }

            // 2. Check ASN / Datacenter
            if ip_info.asn_org != "Unknown" {
                let org_lower = ip_info.asn_org.to_lowercase();
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
                    && stats.connects_in_minute >= cfg.geo.datacenter_max_connects_per_minute
                {
                    stats.strikes += 1;
                    return CheckResult::Rejected("DATACENTER RATE LIMIT");
                }
            }
        }

        match stats.status {
            IpStatus::Banned => return CheckResult::BannedPermanently("BANNED"),
            IpStatus::TempBlacklisted(until) => {
                if now < until {
                    return CheckResult::Rejected("TEMP BLACKLISTED");
                }
                stats.status = IpStatus::Normal;
            }
            IpStatus::Whitelisted => return CheckResult::Allowed(ip_info),
            IpStatus::Normal => {}
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
                stats.status = IpStatus::Banned;
                self.permanent_bans.insert(ip);
                if let IpAddr::V4(ipv4) = ip {
                    // Enqueue instead of blocking nftables call
                    self.enqueue_ban(ipv4);

                    let octets = ipv4.octets();
                    let subnet = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
                    let mut s_strikes = self.subnet_strikes.entry(subnet.clone()).or_insert(0);
                    *s_strikes += 1;

                    if *s_strikes >= cfg.protection.subnet_strike_threshold {
                        // Subnet ban is rare enough to do immediately
                        let _ = self.kernel_fw.ban_subnet(&subnet);
                    }
                }
                return CheckResult::BannedPermanently("STRIKE LIMIT → PERMANENT BAN");
            }

            let duration = cfg.protection.blacklist_duration_secs * stats.strikes as u64;
            stats.status = IpStatus::TempBlacklisted(now + Duration::from_secs(duration));
            return CheckResult::Rejected("RATE LIMIT → TEMP BLACKLIST");
        }

        if stats.active_connections >= cfg.connection.max_connections_per_ip {
            return CheckResult::Rejected("MAX CONCURRENCY");
        }

        stats.active_connections += 1;
        CheckResult::Allowed(ip_info)
    }

    pub fn release_connection(&self, ip: IpAddr) {
        if let Some(mut stats) = self.stats.get_mut(&ip) {
            stats.active_connections = stats.active_connections.saturating_sub(1);
        }
    }

    pub async fn mark_as_good(&self, ip: IpAddr) {
        if self.is_whitelisted(ip) {
            return;
        }

        info!(ip = %ip, "[*] IP verified as GOOD player -> Adding to Whitelist");
        self.whitelist.insert(ip);

        if let Some(mut stats) = self.stats.get_mut(&ip) {
            stats.status = IpStatus::Whitelisted;
        }

        if let IpAddr::V4(ipv4) = ip {
            let _ = self.kernel_fw.whitelist(ipv4);
        }
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(WHITELIST_FILE)
            .await
            .unwrap();
        let _ = file.write_all(format!("{}\n", ip).as_bytes()).await;
    }

    pub async fn persist_ban(ip: &str) {
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        let line = format!("[{}] {}\n", ts, ip);

        match tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(BANNED_FILE)
            .await
        {
            Ok(mut file) => {
                let _ = file.write_all(line.as_bytes()).await;
            }
            Err(e) => {
                eprintln!("Failed to write to {}: {}", BANNED_FILE, e);
            }
        }
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

    pub fn get_stats(&self) -> (usize, usize, usize) {
        let total_active: usize = self
            .stats
            .iter()
            .map(|s| s.value().active_connections)
            .sum();
        (
            self.permanent_bans.len(),
            self.whitelist.len(),
            total_active,
        )
    }

    pub fn list_whitelisted_ips(&self) -> Vec<IpAddr> {
        self.whitelist.iter().map(|kv| *kv.key()).collect()
    }

    /// Returns a snapshot of all currently tracked IPs for the realtime monitor.
    /// Uses cached GeoIP data from IpStats — no re-lookup needed.
    pub fn list_tracked_ips(&self) -> Vec<TrackedIpSnapshot> {
        let mut result: Vec<TrackedIpSnapshot> = self
            .stats
            .iter()
            .filter(|entry| entry.value().active_connections > 0)
            .map(|entry| {
                let ip = *entry.key();
                let s = entry.value();
                let status_str = match &s.status {
                    IpStatus::Normal => "NORMAL".to_string(),
                    IpStatus::Whitelisted => "WHITELISTED".to_string(),
                    IpStatus::Banned => "BANNED".to_string(),
                    IpStatus::TempBlacklisted(_) => "TEMP_BLOCK".to_string(),
                };
                TrackedIpSnapshot {
                    ip,
                    active_connections: s.active_connections,
                    connects_per_min: s.connects_in_minute,
                    strikes: s.strikes,
                    status: status_str,
                    country: if s.country.is_empty() {
                        "??".to_string()
                    } else {
                        s.country.clone()
                    },
                    asn_org: if s.asn_org.is_empty() {
                        "Unknown".to_string()
                    } else {
                        s.asn_org.clone()
                    },
                }
            })
            .collect();
        // Sort by active connections descending
        result.sort_by(|a, b| b.active_connections.cmp(&a.active_connections));
        result
    }

    pub fn spawn_cleanup_task(&self) {
        let stats = self.stats.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(CLEANUP_INTERVAL_SECS)).await;
                let now = Instant::now();
                stats.retain(|_, s| match s.status {
                    IpStatus::TempBlacklisted(until) => now < until,
                    IpStatus::Normal => s.active_connections > 0,
                    _ => true,
                });
            }
        });
    }

    /// Spawn background task that flushes the ban queue every 100ms.
    /// Batches multiple IP bans into a single nftables call.
    pub fn spawn_ban_flush_task(&self) {
        let ban_queue = self.ban_queue.clone();
        let kernel_fw = self.kernel_fw.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let batch: Vec<Ipv4Addr> = {
                    let mut queue = match ban_queue.lock() {
                        Ok(q) => q,
                        Err(_) => continue,
                    };
                    if queue.is_empty() {
                        continue;
                    }
                    queue.drain(..).collect()
                };
                if let Err(e) = kernel_fw.ban_bulk(batch) {
                    warn!("Ban flush failed: {e}");
                }
            }
        });
    }
}
