use anyhow::Result;
use notify::{RecursiveMode, Watcher};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

use proxy_forward::config::AppConfig;
use proxy_forward::kernel::KernelFirewall;
use proxy_forward::proxy;
use proxy_forward::tracker::ConnectionTracker;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("info".parse().unwrap()),
        )
        .with_target(false)
        .init();

    info!("[*] Starting NRO Multi-Port Anti-Spam Proxy ...");
    let config = Arc::new(AppConfig::load());
    let mut listen_ports = Vec::new();
    for server in &config.servers {
        for mapping in &server.mappings {
            if let Some(port) = mapping
                .listen_addr
                .rsplit(":")
                .next()
                .and_then(|p| p.parse::<u16>().ok())
            {
                listen_ports.push(port);
            }
        }
    }

    // kernel
    info!(
        "Khởi tạo Kernel Firewall cho {} cổng...",
        listen_ports.len()
    );
    let kernel_fw = Arc::new(KernelFirewall::new(listen_ports.clone()));

    if let Err(e) = kernel_fw.add_invalid_drop() {
        warn!("[WARN] Rule drop invalid packet: {e}");
    }
    if let Err(e) =
        kernel_fw.add_syn_flood_protection(listen_ports.clone(), config.protection.max_syn_per_sec)
    {
        warn!("[WARN] SYN flood protection: {e}");
    }

    info!(
        "[OK] Kernel firewall rules applied to ports: {:?}",
        listen_ports
    );

    let tracker = Arc::new(ConnectionTracker::new(config.clone(), kernel_fw.clone()));
    tracker.spawn_cleanup_task();

    // Hot-reloading setup
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(event) = res {
            if event.kind.is_modify() {
                let _ = tx.blocking_send(());
            }
        }
    })?;

    watcher.watch(
        std::path::Path::new("config.json"),
        RecursiveMode::NonRecursive,
    )?;

    let tracker_reload = tracker.clone();
    tokio::spawn(async move {
        while let Some(_) = rx.recv().await {
            // debouncing
            tokio::time::sleep(Duration::from_millis(500)).await;
            while rx.try_recv().is_ok() {} // drain

            info!("[*] Config file change detected, reloading...");
            let new_cfg = AppConfig::load();
            tracker_reload.reload_config(Arc::new(new_cfg));
        }
    });

    let mut tasks = Vec::new();

    for server in &config.servers {
        for mapping in &server.mappings {
            let mapping = mapping.clone();
            let tracker = tracker.clone();
            let config = config.clone();
            let target_ip = server.target_ip.clone();
            let server_allowed = server.allowed_countries.clone();

            info!(
                mapping = %mapping.name,
                listen = %mapping.listen_addr,
                target = %format!("{}:{}", target_ip, mapping.target_port),
                "Starting proxy task"
            );

            let task = tokio::spawn(async move {
                let listener = match tokio::net::TcpListener::bind(&mapping.listen_addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        error!(name = %mapping.name, error = %e, "Failed to bind listener");
                        return;
                    }
                };

                loop {
                    match listener.accept().await {
                        Ok((socket, addr)) => {
                            let ip = addr.ip();
                            if tracker.is_permanently_banned(ip) {
                                drop(socket);
                                continue;
                            }

                            let mapping = mapping.clone();
                            let tracker = tracker.clone();
                            let config = config.clone();
                            let target_ip = target_ip.clone();
                            let server_allowed = server_allowed.clone();

                            tokio::spawn(async move {
                                if let Err(e) = proxy::handle_connection(
                                    socket,
                                    ip,
                                    tracker,
                                    config,
                                    target_ip,
                                    mapping,
                                    server_allowed,
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
            });
            tasks.push(task);
        }
    }

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("[*] Shutdown signal received");
        }
    }

    if let Err(e) = kernel_fw.teardown() {
        error!("[ERR] Teardown failed: {e}");
    } else {
        info!("[OK] Kernel firewall cleaned up");
    }

    Ok(())
}
