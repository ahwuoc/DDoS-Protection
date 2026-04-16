use anyhow::Result;
use clap::Parser;
use notify::{RecursiveMode, Watcher};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

use proxy_forward::config::AppConfig;
use proxy_forward::db::IpDatabase;
use proxy_forward::kernel::KernelFirewall;
use proxy_forward::proxy;
use proxy_forward::tracker::ConnectionTracker;
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

    init_logging(true);

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
    spawn_proxy_listeners_from_db(&db_servers, &config, tracker.clone());

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

fn init_logging(menu_mode: bool) {
    let filter =
        tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse().unwrap());
    if menu_mode {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("proxy.log")
            .unwrap();

        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_ansi(false)
            .with_writer(file)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .init();
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

fn spawn_proxy_listeners_from_db(
    servers: &[proxy_forward::config::ServerConfig],
    config: &AppConfig,
    tracker: Arc<ConnectionTracker>,
) {
    for server in servers {
        let target_ip: Arc<str> = server.target_ip.clone().into();
        let allowed: Option<Arc<Vec<String>>> = server.allowed_countries.clone().map(Arc::new);

        for mapping in &server.mappings {
            let mapping = mapping.clone();
            let tracker = tracker.clone();
            let config_arc = Arc::new(config.clone());
            let target_ip = target_ip.clone();
            let allowed = allowed.clone();

            info!(
                mapping = %mapping.name,
                listen = %mapping.listen_addr,
                target = %format!("{}:{}", target_ip, mapping.target_port),
                "Starting proxy task"
            );

            tokio::spawn(async move {
                run_listener(mapping, tracker, config_arc, target_ip, allowed).await;
            });
        }
    }
}

async fn run_listener(
    mapping: proxy_forward::config::Mapping,
    tracker: Arc<ConnectionTracker>,
    config: Arc<AppConfig>,
    target_ip: Arc<str>,
    allowed: Option<Arc<Vec<String>>>,
) {
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
