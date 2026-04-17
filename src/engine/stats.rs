use crate::tracker::*;
use super::ConnectionTracker;
use std::net::IpAddr;

impl ConnectionTracker {
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
                    last_port: s.last_port,
                }
            })
            .collect();
        result.sort_by(|a, b| b.active_connections.cmp(&a.active_connections));
        result
    }
}
