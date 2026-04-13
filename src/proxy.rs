use crate::config::AppConfig;
use crate::tracker::{CheckResult, ConnectionTracker};
use std::sync::Arc;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tracing::{error, info, instrument, warn};

#[instrument(skip_all, fields(%ip))]
pub async fn handle_connection(
    mut client: TcpStream,
    ip: String,
    tracker: Arc<ConnectionTracker>,
    config: Arc<AppConfig>,
) {
    let _ = client.set_nodelay(true);

    match tracker.check_and_track(&ip) {
        CheckResult::BannedPermanently(reason) => {
            ConnectionTracker::persist_ban(&ip).await;
            info!(reason, "🚫 Dropped (banned)");
            return;
        }
        CheckResult::Rejected(reason) => {
            info!(reason, "🚫 Dropped");
            return;
        }
        CheckResult::Allowed => {}
    }

    info!("✅ Accepted");

    // Proxy sang backend
    match TcpStream::connect(&config.target_addr).await {
        Ok(mut backend) => {
            let _ = backend.set_nodelay(true);

            match copy_bidirectional(&mut client, &mut backend).await {
                Ok((up, down)) => {
                    info!(up_bytes = up, down_bytes = down, "Disconnected");
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
                target = %config.target_addr,
                error = %e,
                "❌ Backend connection failed"
            );
        }
    }

    // Giải phóng connection counter
    tracker.release_connection(&ip);
}
