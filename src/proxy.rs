use crate::config::{AppConfig, Mapping};
use crate::tracker::{CheckResult, ConnectionTracker};
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
    let ip_str = ip.to_string();
    let _ = client.set_nodelay(true);

    match tracker.check_and_track(ip, server_allowed.as_ref()) {
        CheckResult::BannedPermanently(reason) => {
            ConnectionTracker::persist_ban(&ip_str).await;
            info!(reason, "[-] Dropped (banned)");
            return Ok(());
        }
        CheckResult::Rejected(reason) => {
            debug!(reason, "[-] Dropped");
            return Ok(());
        }
        CheckResult::Allowed => {}
    }

    let target_addr = format!("{}:{}", target_ip, mapping.target_port);
    match TcpStream::connect(&target_addr).await {
        Ok(mut backend) => {
            let _ = backend.set_nodelay(true);
            let info = tracker.get_ip_info(ip);
            info!(
                "Accepted connection from {ip} [{} | {}] -> Connected to {target_addr}",
                info.country, info.asn_org
            );

            let tracker_clone = tracker.clone();
            let ip_clone = ip;
            let wait_secs = _config.protection.whitelist_after_secs;
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(wait_secs)).await;
                tracker_clone.mark_as_good(ip_clone).await;
            });

            match copy_bidirectional(&mut client, &mut backend).await {
                Ok((up, down)) => {
                    debug!(up_bytes = up, down_bytes = down, "Disconnected");
                }
                Err(e) => {
                    let msg = e.to_string();
                    if !msg.contains("Connection reset") && !msg.contains("Broken pipe") {
                        warn!(error = %e, "Relay error");
                    }
                }
            }
        }
        Err(e) => {
            error!(
                target = %target_addr,
                error = %e,
                "[ERR] Backend connection failed"
            );
        }
    }
    tracker.release_connection(ip);
    Ok(())
}
