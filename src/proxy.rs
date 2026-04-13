use crate::config::AppConfig;
use crate::tracker::{CheckResult, ConnectionTracker};
use std::sync::Arc;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};
use tracing::{debug, error, info, instrument, warn};

#[instrument(skip_all, fields(%ip))]
pub async fn handle_connection(
    mut client: TcpStream,
    ip: String,
    tracker: Arc<ConnectionTracker>,
    _config: Arc<AppConfig>,
    target_addr: String,
) {
    let _ = client.set_nodelay(true);

    match tracker.check_and_track(&ip) {
        CheckResult::BannedPermanently(reason) => {
            ConnectionTracker::persist_ban(&ip).await;
            info!(reason, "[-] Dropped (banned)");
            return;
        }
        CheckResult::Rejected(reason) => {
            debug!(reason, "[-] Dropped");
            return;
        }
        CheckResult::Allowed => {}
    }

    // connection den backend roi forward data
    match TcpStream::connect(&target_addr).await {
        Ok(mut backend) => {
            let _ = backend.set_nodelay(true);
            info!("Accepted connection from {ip} -> Connected to {target_addr}");

            let tracker_clone = tracker.clone();
            let ip_clone = ip.clone();
            let wait_secs = _config.protection.whitelist_after_secs;
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(wait_secs)).await;
                tracker_clone.mark_as_good(&ip_clone).await;
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
    tracker.release_connection(&ip);
}
