use anyhow::Result;
use clap::Parser;
use notify::{RecursiveMode, Watcher};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

use proxy_forward::config::AppConfig;
use proxy_forward::db::IpDatabase;
use proxy_forward::kernel::{KernelFirewall, SysctlTuner};
use proxy_forward::engine::ConnectionTracker;
use proxy_forward::ui;

// ── CLI ─────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "proxy-forward")]
#[command(about = "Anti-Spam Proxy & Firewall Manager")]
struct Cli {}

// ── Main ────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let _cli = Cli::parse();

    // 1. Optimization: Increase File Descriptor limits
    if let Err(e) = rlimit::increase_nofile_limit(65535) {
        eprintln!("Warning: Failed to increase FD limit: {e}");
    }

    // 2. Optimization: Non-blocking logging
    let _guard = init_logging(true);

    info!("Starting NRO Multi-Port Anti-Spam Proxy...");

    let config = Arc::new(AppConfig::load());

    let db = Arc::new(IpDatabase::open().expect("Failed to initialize SQLite database"));

    if !db.has_servers() && !config.servers.is_empty() {
        if let Err(e) = db.migrate_servers_from_config(&config.servers) {
            warn!("Failed to migrate servers from config: {e}");
        }
    }

    let db_servers = db.load_servers().unwrap_or_default();
    if db_servers.is_empty() {
        warn!("No servers configured in database! Use the menu to add servers.");
    }
    let listen_ports = collect_listen_ports_from_servers(&db_servers);

    let kernel_fw = Arc::new(init_firewall(&listen_ports, &config));

    let tracker = Arc::new(ConnectionTracker::new(
        config.clone(),
        kernel_fw.clone(),
        db.clone(),
    ));
    tracker.spawn_cleanup_task();
    tracker.spawn_ban_flush_task();

    spawn_config_watcher(tracker.clone());
    tracker.refresh_proxy_listeners();
    tracker.spawn_dynamic_refresh_task();

    // Start interactive menu (blocks until Q is pressed)
    if let Err(e) = ui::run_menu(tracker.clone()) {
        error!("Menu error: {e}");
    }

    // Cleanup
    if let Err(e) = kernel_fw.teardown() {
        error!("Teardown failed: {e}");
    } else {
        info!("Kernel firewall cleaned up");
    }

    Ok(())
}

// ── Initialization helpers ──────────────────────────────

fn init_logging(menu_mode: bool) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    let filter =
        tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse().unwrap());
    
    if menu_mode {
        let file_appender = tracing_appender::rolling::never(".", "proxy.log");
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_ansi(false)
            .with_writer(non_blocking)
            .init();
        Some(guard)
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .init();
        None
    }
}

fn collect_listen_ports_from_servers(servers: &[proxy_forward::config::ServerConfig]) -> Vec<u16> {
    servers
        .iter()
        .flat_map(|s| &s.mappings)
        .filter_map(|m| m.listen_addr.rsplit(':').next()?.parse().ok())
        .collect()
}

fn init_firewall(ports: &[u16], config: &AppConfig) -> KernelFirewall {
    info!("Initializing Kernel Firewall for {} ports...", ports.len());

    // Tune kernel parameters
    let _ = SysctlTuner::tune_all(&config.tuning);

    let fw = KernelFirewall::new(ports.to_vec());

    if let Err(e) = fw.add_syn_flood_protection(ports.to_vec(), config.protection.max_syn_per_sec) {
        warn!("SYN flood protection: {e}");
    }

    info!("Kernel firewall rules applied to ports: {:?}", ports);
    fw
}

fn spawn_config_watcher(tracker: Arc<ConnectionTracker>) {
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(event) = res {
            if event.kind.is_modify() {
                let _ = tx.blocking_send(());
            }
        }
    })
    .expect("Failed to create config watcher");

    watcher
        .watch(
            std::path::Path::new("config.json"),
            RecursiveMode::NonRecursive,
        )
        .expect("Failed to watch config.json");

    tokio::spawn(async move {
        let _watcher = watcher;

        while rx.recv().await.is_some() {
            tokio::time::sleep(Duration::from_millis(500)).await;
            while rx.try_recv().is_ok() {}
            info!("Config file changed, reloading...");
            let new_cfg = AppConfig::load();
            tracker.reload_config(Arc::new(new_cfg));
        }
    });
}
