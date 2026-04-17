use crate::config::{AppConfig, Mapping};
use crate::tracker::CheckResult;
use crate::engine::ConnectionTracker;
use std::sync::Arc;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tokio::time::Duration;
use tracing::{debug, error, info, instrument, warn};

use anyhow::Result;
use std::net::IpAddr;

#[instrument(skip_all, fields(ip = %ip))]
pub async fn handle_connection(
    mut client: TcpStream,
    ip: IpAddr,
    tracker: Arc<ConnectionTracker>,
    _config: Arc<AppConfig>,
    target_ip: String,
    mapping: Mapping,
    server_allowed: Option<Vec<String>>,
) -> Result<()> {
    let _ = client.set_nodelay(true);

    let ip_info = match tracker.check_and_track(ip, mapping.target_port, server_allowed.as_ref()).await {
        CheckResult::BannedPermanently(reason) => {
            let ban_info = tracker.get_ip_info(ip);
            let reason_str = reason.to_string();
            tracker.persist_ban(
                &ip.to_string(),
                0,
                &ban_info.country,
                &ban_info.asn_org,
                &reason_str,
            );
            info!(reason = %reason_str, "[-] Dropped (banned)");
            return Ok(());
        }
        CheckResult::Rejected(reason) => {
            let reason_str = reason.to_string();
            debug!(reason = %reason_str, "[-] Dropped");
            return Ok(());
        }
        CheckResult::Allowed(info) => info,
    };

    let target_addr = format!("{}:{}", target_ip, mapping.target_port);
    let start_time = std::time::Instant::now();
    let mut up = 0;
    let mut down = 0;

    let timeout_secs = _config.connection.backend_connect_timeout_secs;
    match tokio::time::timeout(Duration::from_secs(timeout_secs), TcpStream::connect(&target_addr)).await {
        Ok(Ok(mut backend)) => {
            let _ = backend.set_nodelay(true);
            info!(
                "Accepted connection from {ip} [{} | {}] -> Connected to {target_addr}",
                ip_info.country, ip_info.asn_org
            );

            let tracker_clone = tracker.clone();
            let ip_clone = ip;
            let wait_secs = _config.protection.whitelist_after_secs;
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(wait_secs)).await;
                if tracker_clone.is_ip_clean(ip_clone) {
                    tracker_clone.mark_as_good(ip_clone).await;
                } else {
                    debug!(ip = %ip_clone, "IP not clean enough for auto-whitelist - remains in untrusted state");
                }
            });

            match copy_bidirectional(&mut client, &mut backend).await {
                Ok((u, d)) => {
                    up = u;
                    down = d;
                }
                Err(e) => {
                    let msg = e.to_string();
                    if !msg.contains("Connection reset") && !msg.contains("Broken pipe") {
                        warn!(error = %e, "Relay error");
                    }
                }
            }
        }
        Ok(Err(e)) => {
            error!(target = %target_addr, error = %e, "[ERR] Backend connection failed");
        }
        Err(_) => {
            error!(target = %target_addr, timeout = %timeout_secs, "[ERR] Backend connection timed out");
        }
    }

    let duration = start_time.elapsed();
    tracker.record_connection_report(ip, duration, up, down);
    tracker.release_connection(ip);
    Ok(())
}
