use crate::tracker::*;
use super::ConnectionTracker;
use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr};
use tracing::{info, warn};

impl ConnectionTracker {
    pub(crate) fn load_banned_ips(&self) {
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

    pub(crate) fn load_whitelist_ips(&self) {
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

    pub(crate) fn enqueue_ban(&self, ipv4: Ipv4Addr) {
        if let Ok(mut queue) = self.ban_queue.lock() {
            queue.push(ipv4);
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
}
