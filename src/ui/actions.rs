use crate::engine::ConnectionTracker;
use crate::ui::app::App;
use inquire::Select;
use std::io;
use std::net::IpAddr;

pub fn do_unban(tracker: &ConnectionTracker, app: &mut App) {
    let banned = tracker.list_banned_ips();
    if banned.is_empty() {
        println!("\n  No IPs are currently banned.\n");
        wait_enter();
        app.status_msg = "No IPs to unban".to_string();
        return;
    }

    let choices: Vec<String> = banned
        .iter()
        .map(|ip| {
            let info = tracker.get_ip_info(*ip);
            format!("{:<18} [{}] {}", ip, info.country, info.asn_org)
        })
        .collect();

    match Select::new("Select IP to unban:", choices).prompt() {
        Ok(selected) => {
            let ip_str = selected.split_whitespace().next().unwrap_or("");
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                if let Err(e) = tracker.unban(ip) {
                    println!("\n  Error: {}\n", e);
                    app.status_msg = format!("Error: {}", e);
                } else {
                    println!("\n  Unbanned successfully: {}\n", ip);
                    app.status_msg = format!("Unbanned: {}", ip);
                }
            }
        }
        Err(_) => app.status_msg = "Cancelled".to_string(),
    }
    wait_enter();
}

pub fn wait_enter() {
    println!(" Press Enter to continue...");
    let mut buf = String::new();
    let _ = io::stdin().read_line(&mut buf);
}
