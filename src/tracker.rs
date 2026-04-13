use crate::config::AppConfig;
use crate::kernel_fw::KernelFirewall;
use dashmap::{DashMap, DashSet};
use std::fs;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

const BANNED_FILE: &str = "banned_ips.txt";
const CLEANUP_INTERVAL_SECS: u64 = 900;

// ── IP Stats ────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct IpStats {
    /// Số connection đang active
    active_connections: usize,
    /// Số lần connect trong window hiện tại
    connects_in_window: u32,
    /// Bắt đầu window
    window_start: Instant,
    /// Blacklist tạm đến thời điểm nào
    blacklisted_until: Option<Instant>,
    /// Số lần vi phạm rate limit (strike)
    /// Reset khi IP không vi phạm trong 1 thời gian dài (cleanup)
    strikes: u32,
}

impl Default for IpStats {
    fn default() -> Self {
        Self {
            active_connections: 0,
            connects_in_window: 0,
            window_start: Instant::now(),
            blacklisted_until: None,
            strikes: 0,
        }
    }
}

// ── Kết quả kiểm tra IP ────────────────────────────────────

pub enum CheckResult {
    /// Cho phép kết nối
    Allowed,
    /// Từ chối kết nối (lý do)
    Rejected(&'static str),
    /// Từ chối + vừa ban vĩnh viễn (cần ghi file)
    BannedPermanently(&'static str),
}

// ── Connection Tracker ──────────────────────────────────────

pub struct ConnectionTracker {
    stats: Arc<DashMap<String, IpStats>>,
    permanent_bans: Arc<DashSet<String>>,
    kernel_fw: Arc<KernelFirewall>,
    config: Arc<AppConfig>,
}

impl ConnectionTracker {
    pub fn new(config: Arc<AppConfig>, kernel_fw: Arc<KernelFirewall>) -> Self {
        let tracker = Self {
            stats: Arc::new(DashMap::new()),
            permanent_bans: Arc::new(DashSet::new()),
            kernel_fw,
            config,
        };
        tracker.load_banned_ips();
        tracker
    }

    /// Load danh sách IP bị ban từ file → thêm vào kernel firewall
    fn load_banned_ips(&self) {
        let Ok(data) = fs::read_to_string(BANNED_FILE) else {
            return;
        };

        for line in data.lines() {
            let ip = line.split("] ").nth(1).unwrap_or(line).trim();
            if ip.is_empty() {
                continue;
            }

            self.permanent_bans.insert(ip.to_string());
            if let Ok(ipv4) = ip.parse::<Ipv4Addr>() {
                let _ = self.kernel_fw.ban(ipv4);
            }
        }

        if !self.permanent_bans.is_empty() {
            info!(count = self.permanent_bans.len(), "Loaded banned IPs from {BANNED_FILE}");
        }
    }

    /// Check nhanh ban vĩnh viễn (trước khi spawn task)
    pub fn is_permanently_banned(&self, ip: &str) -> bool {
        self.permanent_bans.contains(ip)
    }

    /// Kiểm tra rate limit + strike system
    ///
    /// Flow:
    ///   1. Đang blacklist tạm? → reject
    ///   2. Quá rate limit? → strike +1
    ///      - strike < threshold → blacklist tạm (thời gian tăng dần)
    ///      - strike >= threshold → BAN VĨNH VIỄN
    ///   3. Quá max concurrent? → reject (không tính strike)
    ///   4. OK → allowed
    pub fn check_and_track(&self, ip: &str) -> CheckResult {
        let mut stats = self.stats.entry(ip.to_string()).or_default();
        let now = Instant::now();
        let cfg = &self.config;

        // 1. Đang blacklist tạm
        if let Some(until) = stats.blacklisted_until {
            if now < until {
                return CheckResult::Rejected("TEMP BLACKLISTED");
            }
            // Hết hạn blacklist → cho thử lại
            stats.blacklisted_until = None;
        }

        // 2. Rate limit check
        if now.duration_since(stats.window_start) > Duration::from_secs(cfg.rate_limit_window_secs)
        {
            stats.window_start = now;
            stats.connects_in_window = 0;
        }
        stats.connects_in_window += 1;

        if stats.connects_in_window > cfg.max_connects_per_window {
            stats.strikes += 1;

            // Đủ số strike → ban vĩnh viễn
            if cfg.strikes_before_ban > 0 && stats.strikes >= cfg.strikes_before_ban {
                self.permanent_bans.insert(ip.to_string());
                if let Ok(ipv4) = ip.parse::<Ipv4Addr>() {
                    if let Err(e) = self.kernel_fw.ban(ipv4) {
                        warn!(ip, error = %e, "Kernel ban failed");
                    }
                }
                warn!(
                    ip,
                    strikes = stats.strikes,
                    "🚨 Strike limit reached → PERMANENT BAN"
                );
                return CheckResult::BannedPermanently("STRIKE LIMIT → PERMANENT BAN");
            }

            // Chưa đủ strike → blacklist tạm, thời gian tăng dần
            let duration = cfg.blacklist_duration_secs * stats.strikes as u64;
            stats.blacklisted_until = Some(now + Duration::from_secs(duration));

            warn!(
                ip,
                strike = stats.strikes,
                max_strikes = cfg.strikes_before_ban,
                blacklist_secs = duration,
                "⚡ Rate limit vi phạm → temp blacklist"
            );
            return CheckResult::Rejected("RATE LIMIT → TEMP BLACKLIST");
        }

        // 3. Concurrent connection limit (không tính strike — user mở nhiều clone là bình thường)
        if stats.active_connections >= cfg.max_connections_per_ip {
            return CheckResult::Rejected("MAX CONCURRENCY");
        }

        // OK
        stats.active_connections += 1;
        CheckResult::Allowed
    }

    /// Giảm active connection khi client ngắt
    pub fn release_connection(&self, ip: &str) {
        if let Some(mut stats) = self.stats.get_mut(ip) {
            stats.active_connections = stats.active_connections.saturating_sub(1);
        }
    }

    /// Ghi IP ban vào file (async)
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

    /// Spawn background task dọn dẹp bộ nhớ tracker
    pub fn spawn_cleanup_task(&self) {
        let stats = self.stats.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(CLEANUP_INTERVAL_SECS)).await;
                let now = Instant::now();
                stats.retain(|_, s| {
                    // Giữ lại nếu đang blacklist hoặc còn connection active
                    s.blacklisted_until.is_some_and(|until| now < until)
                        || s.active_connections > 0
                });
                info!(entries = stats.len(), "🧹 Tracker cleanup done");
            }
        });
    }
}
