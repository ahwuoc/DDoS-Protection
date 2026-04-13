use std::sync::Arc;
use tracing::{error, info, warn};

use proxy_forward::config::AppConfig;
use proxy_forward::kernel_fw::KernelFirewall;
use proxy_forward::proxy;
use proxy_forward::tracker::ConnectionTracker;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("info".parse().unwrap()),
        )
        .with_target(false)
        .init();

    info!("🚀 Starting NRO Anti-Spam Proxy...");

    // ── Config ──────────────────────────────────────────────
    let config = Arc::new(AppConfig::load());
    let listen_port = config.listen_port();

    // ── Kernel Firewall ─────────────────────────────────────
    info!("Khởi tạo Kernel Firewall...");
    let kernel_fw = Arc::new(KernelFirewall::new());

    if let Err(e) = kernel_fw.add_invalid_drop() {
        warn!("⚠️ Rule drop invalid packet: {e}");
    }
    if let Err(e) = kernel_fw.add_syn_flood_protection(100) {
        warn!("⚠️ SYN flood protection: {e}");
    }
    if let Err(e) = kernel_fw.add_allow_only_tcp_port(listen_port) {
        warn!("⚠️ TCP-only port {listen_port}: {e}");
    }
    info!("✅ Kernel firewall rules applied (port {listen_port})");

    // ── Tracker ─────────────────────────────────────────────
    let tracker = Arc::new(ConnectionTracker::new(config.clone(), kernel_fw.clone()));
    tracker.spawn_cleanup_task();

    // ── TCP Listener ────────────────────────────────────────
    info!(
        listen = %config.listen_addr,
        target = %config.target_addr,
        "TCP proxy started"
    );
    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;

    // ── Main Loop (graceful shutdown on Ctrl+C) ─────────────
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("🛑 Shutdown signal received");
                if let Err(e) = kernel_fw.teardown() {
                    error!("❌ Teardown failed: {e}");
                } else {
                    info!("✅ Kernel firewall cleaned up");
                }
                break;
            }
            result = listener.accept() => {
                let (socket, addr) = match result {
                    Ok(conn) => conn,
                    Err(e) => {
                        error!(error = %e, "Accept error");
                        continue;
                    }
                };

                let ip = addr.ip().to_string();

                if tracker.is_permanently_banned(&ip) {
                    drop(socket);
                    continue;
                }

                let tracker = tracker.clone();
                let config = config.clone();
                tokio::spawn(proxy::handle_connection(socket, ip, tracker, config));
            }
        }
    }

    Ok(())
}
