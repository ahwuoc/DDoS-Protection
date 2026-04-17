use super::ConnectionTracker;
use crate::config::Mapping;
use crate::engine::constants::*;
use crate::proxy;
use crate::tracker::*;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

impl ConnectionTracker {
    pub fn spawn_cleanup_task(&self) {
        let stats = self.stats.clone();
        let config_swap = self.config.clone();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(CLEANUP_INTERVAL_SECS)).await;
                let now = Instant::now();
                let _cfg = config_swap.load();

                stats.retain(|ip, s| {
                    if s.strikes > 0
                        && now.duration_since(s.last_violation).as_secs()
                            >= _cfg.protection.strike_forgiveness_interval_secs
                    {
                        s.strikes -= 1;
                        s.last_violation = now;
                        info!(ip = %ip, strikes = s.strikes, "Forgave 1 strike due to clean behavior");
                    }

                    if s.behavior_score > 0.0 {
                        s.behavior_score = (s.behavior_score - CLEANUP_DECAY_AMOUNT).max(0.0);
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
            let mut interval = tokio::time::interval(BAN_FLUSH_INTERVAL);
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

    pub fn refresh_proxy_listeners(self: &Arc<Self>) {
        let db_servers = match self.db.load_servers() {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to load servers from DB for refresh: {e}");
                return;
            }
        };

        let config = self.config.load();

        for server in db_servers {
            let target_ip: Arc<str> = server.target_ip.clone().into();
            let allowed: Option<Arc<Vec<String>>> = server.allowed_countries.clone().map(Arc::new);

            for mapping in server.mappings {
                let listen_addr = mapping.listen_addr.clone();

                if self.active_listeners.contains(&listen_addr) {
                    continue;
                }

                // Mark as active before spawning to avoid race conditions
                self.active_listeners.insert(listen_addr.clone());

                let tracker = Arc::clone(self);
                let config_arc = Arc::clone(&*config);
                let target_ip = target_ip.clone();
                let allowed = allowed.clone();

                info!(
                    mapping = %mapping.name,
                    listen = %mapping.listen_addr,
                    target = %format!("{}:{}", target_ip, mapping.target_port),
                    "Spawning new dynamic proxy task"
                );

                tokio::spawn(async move {
                    tracker
                        .run_listener_task(mapping, config_arc, target_ip, allowed)
                        .await;
                });
            }
        }
    }

    async fn run_listener_task(
        self: Arc<Self>,
        mapping: Mapping,
        config: Arc<crate::config::AppConfig>,
        target_ip: Arc<str>,
        allowed: Option<Arc<Vec<String>>>,
    ) {
        let listen_addr = mapping.listen_addr.clone();
        let listener = match tokio::net::TcpListener::bind(&listen_addr).await {
            Ok(l) => l,
            Err(e) => {
                error!(name = %mapping.name, addr = %listen_addr, error = %e, "Failed to bind dynamic listener");
                self.active_listeners.remove(&listen_addr);
                return;
            }
        };

        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    let ip = addr.ip();
                    if self.is_permanently_banned(ip) {
                        drop(socket);
                        continue;
                    }

                    let mapping = mapping.clone();
                    let tracker = self.clone();
                    let config = config.clone();
                    let target_ip = target_ip.clone();
                    let allowed = allowed.clone();

                    tokio::spawn(async move {
                        if let Err(e) = proxy::handle_connection(
                            socket,
                            ip,
                            tracker,
                            config,
                            target_ip.to_string(),
                            mapping,
                            allowed.as_deref().cloned(),
                        )
                        .await
                        {
                            error!(error = %e, "Connection error");
                        }
                    });
                }
                Err(e) => {
                    error!(name = %mapping.name, error = %e, "Accept error");
                }
            }
        }
    }

    pub fn spawn_dynamic_refresh_task(self: &Arc<Self>) {
        let tracker = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                tracker.refresh_proxy_listeners();
            }
        });
    }
}
