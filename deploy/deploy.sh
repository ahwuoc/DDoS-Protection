#!/bin/bash
set -e

DEPLOY_DIR="/opt/proxy_forward"
SERVICE_NAME="proxy_forward"
BINARY="target/release/proxy_forward"

echo "=== NRO Proxy Forward Deploy ==="

# 1. Build release
echo "📦 Building release..."
cargo build --release
strip "$BINARY"

# 2. Tạo thư mục deploy
echo "📁 Creating deploy directory..."
sudo mkdir -p "$DEPLOY_DIR"

# 3. Copy binary
echo "📋 Copying binary..."
sudo cp "$BINARY" "$DEPLOY_DIR/"
sudo chmod +x "$DEPLOY_DIR/proxy_forward"

# 4. Copy config nếu chưa có (không ghi đè config đang dùng)
if [ ! -f "$DEPLOY_DIR/config.json" ]; then
    echo "⚙️ Creating default config..."
    cd "$DEPLOY_DIR" && sudo ./proxy_forward &
    sleep 1
    sudo kill $! 2>/dev/null || true
    cd - > /dev/null
fi

# 5. Install systemd service
echo "🔧 Installing systemd service..."
sudo cp deploy/proxy_forward.service /etc/systemd/system/
sudo systemctl daemon-reload

# 6. Enable & restart
echo "🚀 Starting service..."
sudo systemctl enable "$SERVICE_NAME"
sudo systemctl restart "$SERVICE_NAME"

echo ""
echo "✅ Deploy hoàn tất!"
echo ""
echo "📊 Xem logs:    sudo journalctl -u $SERVICE_NAME -f"
echo "🔄 Restart:     sudo systemctl restart $SERVICE_NAME"
echo "🛑 Stop:        sudo systemctl stop $SERVICE_NAME"
echo "⚙️ Config:      sudo nano $DEPLOY_DIR/config.json"
echo "📋 Banned IPs:  cat $DEPLOY_DIR/banned_ips.txt"
