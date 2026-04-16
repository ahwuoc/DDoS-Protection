use crate::config::AppConfig;
use crate::db::IpDatabase;
use crate::kernel::KernelFirewall;
use crate::tracker::types::*;
use anyhow::Result;
use arc_swap::ArcSwap;
use dashmap::{DashMap, DashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

const CLEANUP_INTERVAL_SECS: u64 = 900;

// --- Behavioral Thresholds ---
const THRESHOLD_IDLE_SECS: u64 = 5;
const THRESHOLD_TINY_PAYLOAD_BYTES: u64 = 128;
const THRESHOLD_SHORT_LIVED_SECS: u64 = 3;
const THRESHOLD_HEAL_MIN_DURATION: u64 = 60;
const THRESHOLD_HEAL_MIN_BYTES: u64 = 512;
const THRESHOLD_BURST_CONNECTS_PER_MIN: u32 = 5;

// --- Behavioral Penalties/Rewards ---
const PENALTY_IDLE_ATTACK: f32 = 5.0;
const PENALTY_PORT_SCAN: f32 = 2.0;
const PENALTY_TINY_PAYLOAD_SPAM: f32 = 2.0;
const PENALTY_LAGGY_USER: f32 = 1.0;
const PENALTY_FREQUENCY_MULTIPLIER: f32 = 2.0;
const REWARD_STABLE_PLAYER: f32 = 3.0;

// --- Smart Enhancements Constants ---
const TRUST_HIGH_BYTES: u64 = 20 * 1024 * 1024;
const TRUST_MEDIUM_BYTES: u64 = 5 * 1024 * 1024;
const MULTIPLIER_HIGH_TRUST: f32 = 0.2;
const MULTIPLIER_MEDIUM_TRUST: f32 = 0.5;
const PENALTY_SKEWED_RATIO: f32 = 1.5;
const SKEWED_RATIO_THRESHOLD: u64 = 10;

pub struct ConnectionTracker {
    pub(crate) stats: Arc<DashMap<IpAddr, IpStats>>,
    pub(crate) permanent_bans: Arc<DashSet<IpAddr>>,
    pub(crate) whitelist: Arc<DashSet<IpAddr>>,
    pub(crate) kernel_fw: Arc<KernelFirewall>,
    pub(crate) config: Arc<ArcSwap<AppConfig>>,
    pub(crate) subnet_strikes: Arc<DashMap<String, u32>>,
    pub(crate) asn_reader: Option<maxminddb::Reader<Vec<u8>>>,
    pub(crate) country_reader: Option<maxminddb::Reader<Vec<u8>>>,
    pub(crate) ban_queue: Arc<Mutex<Vec<Ipv4Addr>>>,
    pub(crate) db_ban_queue: Arc<Mutex<Vec<(String, u32, String, String, String)>>>,
    pub(crate) db: Arc<IpDatabase>,
}

impl ConnectionTracker {
    pub fn new(
        config: Arc<AppConfig>,
        kernel_fw: Arc<KernelFirewall>,
        db: Arc<IpDatabase>,
    ) -> Self {
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
            config: Arc::new(ArcSwap::from(config)),
            subnet_strikes: Arc::new(DashMap::new()),
            asn_reader,
            country_reader,
            ban_queue: Arc::new(Mutex::new(Vec::new())),
            db_ban_queue: Arc::new(Mutex::new(Vec::new())),
            db,
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

    fn load_banned_ips(&self) {
        match self.db.load_banned_ips() {
            Ok(ips) => {
                let mut ips_to_ban = Vec::new();
                for ip in ips {
                    self.permanent_bans.insert(ip);
                    if let IpAddr::V4(ipv4) = ip {
                        ips_to_ban.push(ipv4);
                    }
                }
                if !ips_to_ban.is_empty() {
                    let _ = self.kernel_fw.ban_bulk(ips_to_ban);
                }
            }
            Err(e) => warn!("Failed to load banned IPs from DB: {e}"),
        }
    }

    fn load_whitelist_ips(&self) {
        match self.db.load_whitelisted_ips() {
            Ok(ips) => {
                let mut ips_to_white = Vec::new();
                for ip in ips {
                    self.whitelist.insert(ip);
                    if let IpAddr::V4(ipv4) = ip {
                        ips_to_white.push(ipv4);
                    }
                }
                if !ips_to_white.is_empty() {
                    let _ = self.kernel_fw.whitelist_bulk(ips_to_white);
                }
            }
            Err(e) => warn!("Failed to load whitelisted IPs from DB: {e}"),
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
        if let Err(e) = self.db.unban_ip(&ip.to_string()) {
            warn!("Failed to remove {ip} from DB: {e}");
        }
        if let Some(mut s) = self.stats.get_mut(&ip) {
            s.status = IpStatus::Normal;
            s.strikes = 0;
            s.behavior_score = 0.0;
        }
        Ok(())
    }

    pub fn list_banned_ips(&self) -> Vec<IpAddr> {
        self.permanent_bans.iter().map(|kv| *kv.key()).collect()
    }

    pub fn is_whitelisted(&self, ip: IpAddr) -> bool {
        self.whitelist.contains(&ip)
    }

    fn ensure_geo_cached(&self, ip: IpAddr, stats: &mut IpStats) {
        if !stats.country.is_empty() {
            return;
        }
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
        let mut stats = self.stats.entry(ip).or_default();
        let now = Instant::now();
        let cfg = self.config.load();

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

        self.ensure_geo_cached(ip, &mut stats);
        let ip_info = IpInfo {
            country: stats.country.clone(),
            asn_org: stats.asn_org.clone(),
        };

        if self.is_whitelisted(ip) {
            stats.active_connections += 1;
            stats.status = IpStatus::Whitelisted;
            return CheckResult::Allowed(ip_info);
        }

        if cfg.geo.enabled {
            if let Some(allowed_list) = specific_allowed {
                if ip_info.country != "??" && !allowed_list.contains(&ip_info.country) {
                    return CheckResult::Rejected("GEO BLOCKED: COUNTRY NOT ALLOWED");
                }
            }
            if ip_info.asn_org != "Unknown" {
                let org_lower = ip_info.asn_org.to_lowercase();
                if cfg
                    .geo
                    .datacenter_keywords
                    .iter()
                    .any(|kw| org_lower.contains(kw))
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
            IpStatus::Whitelisted => {}
            IpStatus::Normal => {}
        }

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
                    self.enqueue_ban(ipv4);

                    let octets = ipv4.octets();
                    let subnet = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
                    let mut s_strikes = self.subnet_strikes.entry(subnet.clone()).or_insert(0);
                    *s_strikes += 1;

                    if *s_strikes >= cfg.protection.subnet_strike_threshold {
                        let _ = self.kernel_fw.ban_subnet(&subnet);
                    }
                }
                return CheckResult::BannedPermanently("STRIKE LIMIT -> PERMANENT BAN");
            }
            let duration = cfg.protection.blacklist_duration_secs * stats.strikes as u64;
            stats.status = IpStatus::TempBlacklisted(now + Duration::from_secs(duration));
            return CheckResult::Rejected("RATE LIMIT -> TEMP BLACKLIST");
        }

        if stats.active_connections >= cfg.connection.max_connections_per_ip {
            return CheckResult::Rejected("MAX CONCURRENCY");
        }

        stats.active_connections += 1;

        if cfg.behavioral.enabled {
            if !ip.is_loopback() && !self.is_whitelisted(ip) {
                if stats.behavior_score >= cfg.behavioral.scoring_threshold as f32 {
                    stats.strikes += 1;
                    stats.behavior_score = 0.0;
                    info!(ip = %ip, strikes = stats.strikes, "IP penalized with strike due to high behavioral score during check");

                    if cfg.protection.strikes_before_ban > 0
                        && stats.strikes >= cfg.protection.strikes_before_ban
                    {
                        stats.status = IpStatus::Banned;
                        self.permanent_bans.insert(ip);
                        if let IpAddr::V4(ipv4) = ip {
                            self.enqueue_ban(ipv4);
                            let info = self.get_ip_info(ip);
                            self.persist_ban(
                                &ip.to_string(),
                                stats.strikes,
                                &info.country,
                                &info.asn_org,
                                "BEHAVIORAL_STRIKE_LIMIT_CHECK",
                            );
                        }
                        return CheckResult::BannedPermanently("BEHAVIORAL STRIKE LIMIT EXCEEDED");
                    }
                    let duration = cfg.protection.blacklist_duration_secs * stats.strikes as u64;
                    stats.status = IpStatus::TempBlacklisted(now + Duration::from_secs(duration));
                    return CheckResult::Rejected("BEHAVIORAL ANOMALY -> STRIKE & TEMP BLOCK");
                }
            }
        }
        CheckResult::Allowed(ip_info)
    }
    pub fn is_ip_clean(&self, ip: IpAddr) -> bool {
        if let Some(entry) = self.stats.get(&ip) {
            let s = entry.value();
            s.behavior_score < 1.0 && s.strikes == 0
        } else {
            true
        }
    }

    pub fn release_connection(&self, ip: IpAddr) {
        if let Some(mut stats) = self.stats.get_mut(&ip) {
            stats.active_connections = stats.active_connections.saturating_sub(1);
        }
    }

    pub async fn mark_as_good(&self, ip: IpAddr) {
        if !self.whitelist.insert(ip) {
            return;
        }
        info!(ip = %ip, "[*] IP verified as GOOD player -> Adding to Whitelist");
        let (country, asn_org) = if let Some(mut s) = self.stats.get_mut(&ip) {
            s.status = IpStatus::Whitelisted;
            s.strikes = 0;
            (s.country.clone(), s.asn_org.clone())
        } else {
            let info = self.get_ip_info(ip);
            (info.country, info.asn_org)
        };
        if let IpAddr::V4(ipv4) = ip {
            let _ = self.kernel_fw.whitelist(ipv4);
        }
        let _ = self.db.whitelist_ip(&ip.to_string(), &country, &asn_org);
    }

    pub fn record_connection_report(
        &self,
        ip: IpAddr,
        duration: Duration,
        bytes_sent: u64,
        bytes_recv: u64,
    ) {
        let mut stats = self.stats.entry(ip).or_default();
        let cfg = self.config.load();
        stats.total_bytes_sent += bytes_sent;
        stats.total_bytes_recv += bytes_recv;
        if !cfg.behavioral.enabled || ip.is_loopback() || self.is_whitelisted(ip) {
            return;
        }
        let mut penalty = 0.0;

        // --- SMART ENHANCEMENT: Trust Multiplier ---
        // Highly trusted players (high total recv) receive significantly reduced penalties
        let trust_multiplier = if stats.total_bytes_recv > TRUST_HIGH_BYTES {
            MULTIPLIER_HIGH_TRUST // Reduced penalty for long-term players
        } else if stats.total_bytes_recv > TRUST_MEDIUM_BYTES {
            MULTIPLIER_MEDIUM_TRUST
        } else {
            1.0
        };

        // 1. Action: Connection without data
        if bytes_recv == 0 {
            if duration.as_secs() > THRESHOLD_IDLE_SECS {
                penalty += PENALTY_IDLE_ATTACK;
            } else {
                penalty += PENALTY_PORT_SCAN;
            }
        }
        // 2. Action: Tiny data (Tiny Payload)
        else if bytes_recv < THRESHOLD_TINY_PAYLOAD_BYTES {
            if duration.as_secs() < THRESHOLD_SHORT_LIVED_SECS {
                penalty += PENALTY_TINY_PAYLOAD_SPAM;
            } else {
                penalty += PENALTY_LAGGY_USER;
            }
        }

        // --- SMART ENHANCEMENT: Traffic Ratio Detection ---
        // Game clients usually receive more data than they send.
        // If an IP is sending much more data than it's receiving, it's suspicious.
        if bytes_sent > 1024 && bytes_sent > bytes_recv * SKEWED_RATIO_THRESHOLD {
            penalty += PENALTY_SKEWED_RATIO; // Suspicious upload-to-download ratio
        }

        // Frequency Multiplier: Intensify penalties for spammers
        if stats.connects_in_minute > THRESHOLD_BURST_CONNECTS_PER_MIN {
            penalty *= PENALTY_FREQUENCY_MULTIPLIER;
        }

        // Apply trust multiplier to final penalty
        stats.behavior_score += penalty * trust_multiplier;

        // --- SMART ENHANCEMENT: Enhanced Healing ---
        // Forgiveness mechanism: Clean up history for genuine stable players
        if duration.as_secs() > THRESHOLD_HEAL_MIN_DURATION && bytes_recv > THRESHOLD_HEAL_MIN_BYTES
        {
            let mut reward = REWARD_STABLE_PLAYER;
            // Bonus reward for high volume players
            if bytes_recv > 1024 * 1024 {
                reward += 1.0;
            }

            stats.behavior_score = (stats.behavior_score - reward).max(0.0);
        }

        if penalty > 0.0 {
            debug!(
                ip = %ip,
                duration = ?duration,
                sent = bytes_sent,
                recv = bytes_recv,
                score = stats.behavior_score,
                trust = trust_multiplier,
                "Behavioral penalty (+{:.1} x {:.1}) applied", penalty, trust_multiplier
            );
        }

        if cfg.behavioral.enabled && stats.behavior_score >= cfg.behavioral.scoring_threshold as f32
        {
            if stats.status != IpStatus::Banned {
                stats.strikes += 1;
                stats.behavior_score = 0.0; // Reset after penalty

                info!(ip = %ip, strikes = stats.strikes, "IP penalized with strike due to high behavioral score after disconnect");

                if cfg.protection.strikes_before_ban > 0
                    && stats.strikes >= cfg.protection.strikes_before_ban
                {
                    stats.status = IpStatus::Banned;
                    self.permanent_bans.insert(ip);
                    if let IpAddr::V4(ipv4) = ip {
                        self.enqueue_ban(ipv4);
                        let info = self.get_ip_info(ip);
                        self.persist_ban(
                            &ip.to_string(),
                            stats.strikes,
                            &info.country,
                            &info.asn_org,
                            "BEHAVIORAL_STRIKE_LIMIT",
                        );
                    }
                } else {
                    // Just a strike, will be blocked on next check_and_track attempt
                    // since record_connection_report is usually called at the end.
                }
            }
        }
    }

    pub fn persist_ban(&self, ip: &str, strikes: u32, country: &str, asn_org: &str, reason: &str) {
        if let Ok(mut queue) = self.db_ban_queue.lock() {
            queue.push((
                ip.to_string(),
                strikes,
                country.to_string(),
                asn_org.to_string(),
                reason.to_string(),
            ));
        }
    }

    pub fn get_ip_info(&self, ip: IpAddr) -> IpInfo {
        let mut country = "??".to_string();
        let mut org = "Unknown".to_string();
        if let Some(ref r) = self.country_reader {
            if let Ok(c) = r.lookup::<maxminddb::geoip2::Country>(ip) {
                country = c
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
            country,
            asn_org: org,
        }
    }

    pub fn get_stats(&self) -> (usize, usize, usize) {
        let total_active: usize = self
            .stats
            .iter()
            .map(|s| s.value().active_connections)
            .sum();

        let mut banned_ips = std::collections::HashSet::new();
        for ip in self.permanent_bans.iter() {
            banned_ips.insert(*ip);
        }
        for entry in self.stats.iter() {
            if entry.value().status == IpStatus::Banned {
                banned_ips.insert(*entry.key());
            }
        }

        (banned_ips.len(), self.whitelist.len(), total_active)
    }

    pub fn get_ip_stats(&self, ip: IpAddr) -> Option<IpStats> {
        self.stats.get(&ip).map(|s| s.clone())
    }

    pub fn list_whitelisted_ips(&self) -> Vec<IpAddr> {
        self.whitelist.iter().map(|kv| *kv.key()).collect()
    }

    pub fn list_tracked_ips(&self) -> Vec<TrackedIpSnapshot> {
        let mut result: Vec<TrackedIpSnapshot> = self
            .stats
            .iter()
            .filter(|entry| {
                let s = entry.value();
                s.active_connections > 0
                    || s.behavior_score > 0.0
                    || s.total_bytes_recv > 0
                    || s.connects_in_minute > 0
            })
            .map(|entry| {
                let ip = *entry.key();
                let s = entry.value();
                TrackedIpSnapshot {
                    ip,
                    active_connections: s.active_connections,
                    connects_per_min: s.connects_in_minute,
                    strikes: s.strikes,
                    behavior_score: s.behavior_score,
                    total_bytes_sent: s.total_bytes_sent,
                    total_bytes_recv: s.total_bytes_recv,
                    status: match &s.status {
                        IpStatus::Normal => "NORMAL".to_string(),
                        IpStatus::Whitelisted => "WHITELISTED".to_string(),
                        IpStatus::Banned => "BANNED".to_string(),
                        IpStatus::TempBlacklisted(_) => "TEMP_BLOCK".to_string(),
                    },
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
        result.sort_by(|a, b| b.active_connections.cmp(&a.active_connections));
        result
    }

    pub fn spawn_cleanup_task(&self) {
        let stats = self.stats.clone();
        let config_swap = self.config.clone();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(CLEANUP_INTERVAL_SECS)).await;
                let now = Instant::now();
                let _cfg = config_swap.load();

                stats.retain(|ip, s| {
                    if s.behavior_score > 0.0 {
                        s.behavior_score = (s.behavior_score - 1.0).max(0.0);
                    }

                    match s.status {
                        IpStatus::TempBlacklisted(until) => now < until,
                        IpStatus::Normal => {
                            s.active_connections > 0
                                || s.behavior_score > 0.0
                                || s.connects_in_minute > 0
                        }
                        IpStatus::Banned | IpStatus::Whitelisted => {
                            if s.active_connections > 0 {
                                true
                            } else {
                                debug!(ip = %ip, "Removing inactive persistent IP from RAM stats");
                                false
                            }
                        }
                    }
                });
            }
        });
    }

    pub fn spawn_ban_flush_task(self: &Arc<Self>) {
        let tracker = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                let to_ban = {
                    let mut queue = tracker.ban_queue.lock().unwrap();
                    if queue.is_empty() {
                        Vec::new()
                    } else {
                        std::mem::take(&mut *queue)
                    }
                };
                if !to_ban.is_empty() {
                    let _ = tracker.kernel_fw.ban_bulk(to_ban);
                }
                let to_persist = {
                    let mut queue = tracker.db_ban_queue.lock().unwrap();
                    if queue.is_empty() {
                        Vec::new()
                    } else {
                        std::mem::take(&mut *queue)
                    }
                };
                for (ip, strikes, country, asn, reason) in to_persist {
                    let _ = tracker.db.ban_ip(&ip, strikes, &country, &asn, &reason);
                }
            }
        });
    }
}
