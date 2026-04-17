use super::ConnectionTracker;
use crate::engine::constants::*;
use crate::tracker::*;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tracing::{debug, info};

impl ConnectionTracker {
    pub async fn check_and_track(
        &self,
        ip: IpAddr,
        port: u16,
        specific_allowed: Option<&Vec<String>>,
    ) -> CheckResult {
        if self.stats.len() >= 100_000 && !self.stats.contains_key(&ip) {
            return CheckResult::Rejected(RejectionReason::SystemOverload);
        }

        let stats_val = {
            let mut stats = self.stats.entry(ip).or_default();
            stats.last_port = port;
            let now = Instant::now();
            let cfg = self.config.load();

            if now.duration_since(stats.window_start)
                > Duration::from_secs(cfg.rate_limit.window_secs)
            {
                stats.window_start = now;
                stats.connects_in_window = 0;
            }
            stats.connects_in_window += 1;

            if now.duration_since(stats.minute_start) > MINUTE_INTERVAL {
                stats.minute_start = now;
                stats.connects_in_minute = 0;
            }
            stats.connects_in_minute += 1;

            (stats.country.clone(), stats.asn_org.clone())
        };

        let (mut country, mut asn_org) = stats_val;

        if country.is_empty() {
            let asn_r = self.asn_reader.clone();
            let country_r = self.country_reader.clone();
            let geo_info = tokio::task::spawn_blocking(move || {
                let mut country = "??".to_string();
                let mut org = "Unknown".to_string();
                if let Some(r) = country_r {
                    if let Ok(c) = r.lookup::<maxminddb::geoip2::Country>(ip) {
                        country = c
                            .country
                            .and_then(|co| co.iso_code)
                            .unwrap_or("??")
                            .to_string();
                    }
                }
                if let Some(r) = asn_r {
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
            })
            .await
            .unwrap_or(IpInfo {
                country: "??".to_string(),
                asn_org: "Unknown".to_string(),
            });

            country = geo_info.country;
            asn_org = geo_info.asn_org;

            if let Some(mut stats) = self.stats.get_mut(&ip) {
                stats.country = country.clone();
                stats.asn_org = asn_org.clone();
            }
        }

        let mut stats = match self.stats.get_mut(&ip) {
            Some(s) => s,
            None => return CheckResult::Rejected(RejectionReason::RateLimit), // Fallback if cleaned up
        };
        let now = Instant::now();
        let cfg = self.config.load();

        let ip_info = IpInfo {
            country: country.clone(),
            asn_org: asn_org.clone(),
        };

        if self.is_whitelisted(ip) {
            stats.active_connections += 1;
            stats.status = IpStatus::Whitelisted;
            return CheckResult::Allowed(ip_info);
        }

        if cfg.geo.enabled {
            if let Some(allowed_list) = specific_allowed {
                if ip_info.country != "??" && !allowed_list.contains(&ip_info.country) {
                    return CheckResult::Rejected(RejectionReason::GeoBlocked);
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
                    stats.last_violation = now;
                    return CheckResult::Rejected(RejectionReason::DatacenterRateLimit);
                }
            }
        }

        match stats.status {
            IpStatus::Banned => return CheckResult::BannedPermanently(BanReason::Manual),
            IpStatus::TempBlacklisted(until) => {
                if now < until {
                    return CheckResult::Rejected(RejectionReason::TempBlacklisted);
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
            stats.last_violation = now;
            if cfg.protection.strikes_before_ban > 0
                && stats.strikes >= cfg.protection.strikes_before_ban
            {
                stats.status = IpStatus::Banned;
                self.permanent_bans.insert(ip);
                if let IpAddr::V4(ipv4) = ip {
                    self.enqueue_ban(ipv4);

                    let octets = ipv4.octets();
                    let subnet = format!(
                        "{}.{}.{}.0{}",
                        octets[0], octets[1], octets[2], DEFAULT_IPV4_SUBNET_MASK
                    );
                    let mut s_strikes = self.subnet_strikes.entry(subnet.clone()).or_insert(0);
                    *s_strikes += 1;

                    if *s_strikes >= cfg.protection.subnet_strike_threshold {
                        let fw = self.kernel_fw.clone();
                        let subnet_clone = subnet.clone();
                        tokio::spawn(async move {
                            if let Err(e) = fw.ban_subnet(&subnet_clone) {
                                tracing::error!("Failed to ban subnet {}: {}", subnet_clone, e);
                            }
                        });
                    }
                }
                return CheckResult::BannedPermanently(BanReason::RateLimitPermanent);
            }
            let duration = cfg.protection.blacklist_duration_secs * stats.strikes as u64;
            stats.status = IpStatus::TempBlacklisted(now + Duration::from_secs(duration));
            return CheckResult::Rejected(RejectionReason::RateLimit);
        }

        if stats.active_connections >= cfg.connection.max_connections_per_ip {
            return CheckResult::Rejected(RejectionReason::MaxConcurrency);
        }

        stats.active_connections += 1;

        if cfg.behavioral.enabled {
            if !ip.is_loopback() && !self.is_whitelisted(ip) {
                if stats.behavior_score >= cfg.behavioral.scoring_threshold as f32 {
                    stats.strikes += 1;
                    stats.last_violation = now;
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
                                &BanReason::BehavioralStrikeCheck.to_string(),
                            );
                        }
                        return CheckResult::BannedPermanently(BanReason::BehavioralStrikeCheck);
                    }
                    let duration = cfg.protection.blacklist_duration_secs * stats.strikes as u64;
                    stats.status = IpStatus::TempBlacklisted(now + Duration::from_secs(duration));
                    return CheckResult::Rejected(RejectionReason::BehavioralAnomaly);
                }
            }
        }
        CheckResult::Allowed(ip_info)
    }

    pub fn is_ip_clean(&self, ip: IpAddr) -> bool {
        if let Some(entry) = self.stats.get(&ip) {
            let s = entry.value();
            s.behavior_score < CLEAN_SCORE_THRESHOLD && s.strikes == 0
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
        if !cfg.behavioral.enabled
            || ip.is_loopback()
            || self.is_whitelisted(ip)
            || stats.status == IpStatus::Banned
        {
            return;
        }
        let mut penalty = 0.0;

        // Trust Multiplier
        let trust_multiplier = if stats.total_bytes_recv > TRUST_HIGH_BYTES {
            MULTIPLIER_HIGH_TRUST
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
        // 2. Action: Tiny data
        else if bytes_recv < THRESHOLD_TINY_PAYLOAD_BYTES {
            if duration.as_secs() < THRESHOLD_SHORT_LIVED_SECS {
                penalty += PENALTY_TINY_PAYLOAD_SPAM;
            } else {
                penalty += PENALTY_LAGGY_USER;
            }
        }

        // Traffic Ratio Detection
        if bytes_sent > TRAFFIC_RATIO_SENT_MIN_BYTES
            && bytes_sent > bytes_recv * SKEWED_RATIO_THRESHOLD
        {
            penalty += PENALTY_SKEWED_RATIO;
        }

        // Frequency Multiplier
        if stats.connects_in_minute > THRESHOLD_BURST_CONNECTS_PER_MIN {
            penalty *= PENALTY_FREQUENCY_MULTIPLIER;
        }

        // Apply trust multiplier
        let applied_penalty = penalty * trust_multiplier;
        if applied_penalty > 0.0 {
            stats.last_violation = Instant::now();
        }
        stats.behavior_score += applied_penalty;

        // Enhanced Healing
        if duration.as_secs() > THRESHOLD_HEAL_MIN_DURATION && bytes_recv > THRESHOLD_HEAL_MIN_BYTES
        {
            let mut reward = REWARD_STABLE_PLAYER;
            if bytes_recv > HEAL_BONUS_RECV_BYTES {
                reward += REWARD_STABLE_BONUS;
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
                stats.behavior_score = 0.0;

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
                            &BanReason::BehavioralStrikeLimit.to_string(),
                        );
                    }
                }
            }
        }
    }
}
