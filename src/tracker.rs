use crate::config::AppConfig;
use crate::kernel::KernelFirewall;
use dashmap::{DashMap, DashSet};
use std::fs;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tracing::info;

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

pub enum CheckResult {
    Allowed,
    Rejected(&'static str),
    BannedPermanently(&'static str),
}
pub struct ConnectionTracker {
    stats: Arc<DashMap<String, IpStats>>,
    permanent_bans: Arc<DashSet<String>>,
    whitelist: Arc<DashSet<String>>,
    kernel_fw: Arc<KernelFirewall>,
    config: Arc<AppConfig>,
}

impl ConnectionTracker {
    pub fn new(config: Arc<AppConfig>, kernel_fw: Arc<KernelFirewall>) -> Self {
        let tracker = Self {
            stats: Arc::new(DashMap::new()),
            permanent_bans: Arc::new(DashSet::new()),
            whitelist: Arc::new(DashSet::new()),
            kernel_fw,
            config,
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

    pub fn is_permanently_banned(&self, ip: &str) -> bool {
        self.permanent_bans.contains(ip)
    }

    pub fn is_whitelisted(&self, ip: &str) -> bool {
        self.whitelist.contains(ip)
    }

    pub fn check_and_track(&self, ip: &str) -> CheckResult {
        // check whitelist thi cho phep luon
        if self.is_whitelisted(ip) {
            return CheckResult::Allowed;
        }

        let mut stats = self.stats.entry(ip.to_string()).or_default();
        let now = Instant::now();
        let cfg = &self.config;

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
                self.permanent_bans.insert(ip.to_string());
                if let Ok(ipv4) = ip.parse::<Ipv4Addr>() {
                    let _ = self.kernel_fw.ban(ipv4);
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

    pub fn release_connection(&self, ip: &str) {
        if let Some(mut stats) = self.stats.get_mut(ip) {
            stats.active_connections = stats.active_connections.saturating_sub(1);
        }
    }
    pub async fn mark_as_good(&self, ip: &str) {
        if self.is_whitelisted(ip) {
            return;
        }

        info!(ip, "[*] IP verified as GOOD player -> Adding to Whitelist");
        self.whitelist.insert(ip.to_string());

        if let Ok(ipv4) = ip.parse::<Ipv4Addr>() {
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
