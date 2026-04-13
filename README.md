# NRO Anti-Spam TCP Proxy (Bảo vệ chống DDoS)

Một TCP proxy hiệu suất cao, xử lý đồng thời lượng kết nối lớn được viết bằng Rust. Phần mềm được thiết kế đặc biệt để bảo vệ các Game Server (như NRO) khỏi các cuộc tấn công dựa trên kết nối, flood và spam bots.

## 🚀 Các tính năng chính

### 🛡️ 1. Bảo vệ hai lớp (Dual-Layer Protection)
- **Tầng Vật lý Kernel (nftables):** Sử dụng thư viện Rust `nftables` để quản lý các rules tường lửa trực tiếp thông qua `libnftables`. Hệ thống loại bỏ các gói tin độc hại (SYN flood, trạng thái không hợp lệ) ngay ở mức màng lọc của hệ điều hành, giúp tiết kiệm tối đa CPU và RAM.
- **Tầng Ứng dụng (Tokio):** Xử lý luồng TCP bất đồng bộ (Asynchronous, non-blocking), có khả năng quản lý hàng vạn kết nối đồng thời mượt mà ngay cả trên VPS cấu hình thấp.

### ⚖️ 2. Hệ thống thẻ phạt thông minh (Intelligent Strike System)
Thay vì cấm vĩnh viễn ngay lập tức, hệ thống sử dụng cơ chế "Thẻ phạt (Strike)" tăng dần để thân thiện với người chơi thật nhưng vẫn vô cùng khắt khe với bots:
- **Rate Limiting:** Liên tục theo dõi tốc độ kết nối của từng IP theo khoảng thời gian ngắn và cửa sổ quét 1 phút.
- **Blacklist tạm thời:** Lần vi phạm đầu tiên = khóa 60s, lần 2 = khóa 120s (Thời gian khóa tăng theo cấp số nhân: `số lần vi phạm * thời gian phạt gốc`).
- **Cấm vĩnh viễn (Permanent Ban):** Khi IP vi phạm chạm tới ngưỡng thẻ đỏ `strikes_before_ban`, IP đó sẽ bị cấm vĩnh viễn và bị đẩy trực tiếp xuống **tường lửa Kernel nftables** để chặn từ dưới hệ điều hành (zero-latency).

### 🌟 3. Tự động đưa vào danh sách trắng (Automatic Whitelisting)
- **Nhận diện người chơi thật:** Các kết nối duy trì ổn định được lâu hơn ngưỡng thiết lập (VD: 30 giây) sẽ tự động được đánh dấu là người chơi hợp lệ.
- **Bỏ qua bộ lọc:** Nhóm IP trong whitelist hoàn toàn không bị ảnh hưởng bởi giới hạn kết nối hay thẻ phạt. Đảm bảo trải nghiệm không bao giờ bị gián đoạn, ngay cả khi server đang hứng chịu đợt DDoS cực nặng.
- **Tin tưởng mức Kernel:** Các IP uy tín sẽ được cấp phép (whitelist) trực tiếp dưới kernel giúp tối thiểu hóa độ trễ xử lý gói tin.

### 🧬 4. Lọc Nâng Cao & Hỗ trợ đa cổng (Advanced Filtering & Multi-Port)
- **Lưu lượng đa chiều (Multi-Port Routing):** Có khả năng lắng nghe và chuyển tiếp dữ liệu cùng lúc ở nhiều cổng thông qua danh sách `mappings` (Ví dụ mở chung thiết lập cho Game, Database).
- **Chống SYN Flood:** Mặc định từ chối các gói tin SYN rác (thuộc tính invalid state) hoặc có tần suất vượt quá ngưỡng chịu tải `max_syn_per_sec`.
- **Loại bỏ gói tin rác:** Tự động drop hủy các lệnh mang trạng thái TCP trạng thái hỏng hóc.
- **Protocol Enforcer:** Chỉ chấp nhận và xử lý dòng chảy TCP trên cổng đã mở, phớt lờ mọi giao thức không liên đới khác được gởi tới.

### 📊 5. Hệ thống theo dõi hiện đại
- Được tích hợp sẵn thư viện `tracing` và `tracing-subscriber`.
- **Structured Logging:** Tất cả log hiện tại đều được gán nhãn với IP từ phía khách hàng (client). Dễ dàng truy vết, kiểm soát toàn phần sinh mạng của từng kết nối.

---

## 🛠️ Yêu cầu hệ thống
- **Hệ điều hành:** Linux (Kernel có sẵn module `nftables`)
- **Dependencies:** `libnftables-dev`
- **Compiler:** Lõi RUST (Bản Stable mới nhất)

---

## ⚙️ Cấu hình (`config.json`)

```json
{
  "mappings": [
    {
      "name": "Game Port",
      "listen_addr": "0.0.0.0:14443",
      "target_addr": "127.0.0.1:14443"
    }
  ],
  "connection": {
    "max_connections_per_ip": 10
  },
  "rate_limit": {
    "window_secs": 2,
    "max_connects_per_window": 10,
    "max_connects_per_minute": 100
  },
  "protection": {
    "blacklist_duration_secs": 60,
    "whitelist_after_secs": 30,
    "strikes_before_ban": 3,
    "max_syn_per_sec": 10000
  }
}
```
- `mappings`: Định tuyến đầu vào cấu trúc ánh xạ proxy nhiều cổng ứng với địa chỉ backend đích.
- `connection.max_connections_per_ip`: Cản số lượng "clones" - giới hạn duy trì tab kết nối song song của mỗi IP.
- `rate_limit.*`: Cấu hình số nhịp đẩy TCP trong 1 đoạn thời gian ngắn hoặc dài rải rác (chặn bot net bạo lực mạng).
- `protection.blacklist_duration_secs`: Cấu hình nền tảng mức thời gian bị chặn (theo giây) sau lần dính strike đầu tiên.
- `protection.whitelist_after_secs`: Bao nhiêu giây sống sót thì IP vượt ải, thành người chơi thật sự.
- `protection.strikes_before_ban`: Số thẻ vi phạm tối đa trước khi án tử hình (lưu bộ nhớ Kernel permanent ban) diễn ra.
- `protection.max_syn_per_sec`: Tầng rào cản SYN - số packet khởi tạo cực đại cho phép đổ xuống mỗi giây.

---

## 📦 Triển khai (Deployment)

### 1. Dựng và Chạy thử nghiệm
```bash
cargo build --release
sudo ./target/release/proxy_forward
```

### 2. Môi trường Máy chủ Chạy thật (Systemd)
Sử dụng ngay file `deploy.sh` được đặt sẵn tại folder `deploy/` cho quy trình sản xuất auto 1 chạm:
```bash
chmod +x deploy/deploy.sh
./deploy/deploy.sh
```
Hành vi của Script này:
1. Compile và dựng phân vùng nhị phân siêu tinh giản release.
2. Tước đi bỏ (Strip) toàn bộ meta biên dịch để tốn ít storage.
3. Thiết lập proxy như một cỗ máy ngầm `systemd` system service.
4. Tự động giám sát, phục hồi và lưu lại dấu vân log.

---

## 📜 Theo dõi tài nguyên & Lọc ban
```bash
# Giám sát real-time logs tại chỗ
sudo journalctl -u proxy_forward -f

# Nhìn lại những gã bị lưu đày (Permanent bans)
cat banned_ips.txt

# Kiểm kê những thành viên trung kiên (Whitelisted - Trusted IPS)
cat whitelist_ips.txt
```

---

## 🤝 Hỗ trợ dự án
Chúng tôi luôn vinh hạnh khi bạn giúp sức mở nhánh, đóng góp PR! Đừng ngần ngại đề xuất nhé.

## ⚖️ Giấy phép
Giấy phép MIT. Tạo bởi [ahwuoc](https://github.com/ahwuoc).
