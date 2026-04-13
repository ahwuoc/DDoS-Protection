# NRO Anti-Spam TCP Proxy (DDoS Protection)

A high-performance, high-concurrency TCP proxy built in Rust, specifically designed to protect Game Servers (like NRO) from connection-based attacks, flood attacks, and spam bots.

## 🚀 Key Features

### 🛡️ 1. Dual-Layer Protection
- **Physical Kernel Level (nftables):** Uses `nftnl` and `mnl` to communicate directly with the Linux kernel. It drops malicious packets (SYN flood, invalid state) before they even reach the proxy application, saving CPU and memory.
- **Application Level (Tokio):** Asynchronous, non-blocking TCP handling capable of managing thousands of concurrent connections on low-resource VPS.

### ⚖️ 2. Intelligent Strike System
Instead of simple banning, it uses an escalating "Strike" mechanism to be friendly to real players while being lethal to bots:
- **Rate Limiting:** Monitors connection speed per IP.
- **Temporary Blacklist:** First violation = 30s lock, Second violation = 60s lock (escalating duration: `strike * base_duration`).
- **Permanent Ban:** After reaching the `strikes_before_ban` threshold, the IP is permanently banned and pushed to the **nftables kernel level** for zero-latency dropping.

### 🧬 3. Advanced Filtering
- **SYN Flood Protection:** Filters pure SYN packets with an invalid conntrack state.
- **Invalid Packet Drop:** Automatically drops packets with invalid TCP states.
- **Protocol Enforcer:** Only allows TCP traffic on the designated game port, dropping everything else (UDP, ICMP, etc. on that specific port).

### 📊 4. Modern Observability
- Integrated with `tracing` and `tracing-subscriber`.
- **Structured Logging:** All logs are tagged with the client's IP, making it easy to track individual connection life-cycles.

---

## 🛠️ Requirements
- **OS:** Linux (Kernel with `nftables` support)
- **Dependencies:** `libnftnl-dev`, `libmnl-dev`
- **Compiler:** Rust (Latest Stable)

---

## ⚙️ Configuration (`config.json`)

```json
{
  "listen_addr": "0.0.0.0:14443",
  "target_addr": "127.0.0.1:14445",
  "max_connections_per_ip": 5,
  "rate_limit_window_secs": 2,
  "max_connects_per_window": 8,
  "blacklist_duration_secs": 30,
  "strikes_before_ban": 3
}
```
- `max_connections_per_ip`: Limits "clones" per player.
- `strikes_before_ban`: Number of violations before a kernel-level permanent ban.

---

## 📦 Deployment

### 1. Build and Run
```bash
cargo build --release
sudo ./target/release/proxy_forward
```

### 2. Production (Systemd)
Use the provided `deploy.sh` script in the `deploy/` directory for a one-command production setup:
```bash
chmod +x deploy/deploy.sh
./deploy/deploy.sh
```
This will:
1. Build the release binary.
2. Strip debug symbols (reducing file size).
3. Install the application as a `systemd` service.
4. Enable auto-restart and logging.

---

## 📜 Monitor & Logs
```bash
# Watch real-time logs
sudo journalctl -u proxy_forward -f

# View permanent bans
cat banned_ips.txt
```

---

## 🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## ⚖️ License
MIT License. Created by [ahwuoc](https://github.com/ahwuoc).
