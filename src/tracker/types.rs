use std::net::IpAddr;
use std::time::Instant;

#[derive(Clone, Debug, PartialEq)]
pub enum IpStatus {
    Normal,
    Whitelisted,
    Banned,
    TempBlacklisted(Instant),
}

#[derive(Clone, Debug)]
pub struct IpStats {
    pub active_connections: usize,
    pub connects_in_window: u32,
    pub window_start: Instant,
    pub minute_start: Instant,
    pub connects_in_minute: u32,
    pub status: IpStatus,
    pub strikes: u32,
    pub behavior_score: f32,
    pub total_bytes_sent: u64,
    pub total_bytes_recv: u64,
    pub country: String,
    pub asn_org: String,
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
            behavior_score: 0.0,
            total_bytes_sent: 0,
            total_bytes_recv: 0,
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

pub struct TrackedIpSnapshot {
    pub ip: IpAddr,
    pub active_connections: usize,
    pub connects_per_min: u32,
    pub strikes: u32,
    pub behavior_score: f32,
    pub total_bytes_sent: u64,
    pub total_bytes_recv: u64,
    pub status: String,
    pub country: String,
    pub asn_org: String,
}
