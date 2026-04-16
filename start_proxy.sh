#!/bin/bash

# Ten session tmux
SESSION_NAME="proxy"
BINARY_PATH="./target/release/proxy_forward"

# Check if binary exists, build if not
if [ ! -f "$BINARY_PATH" ]; then
    echo "[*] Binary not found. Building release..."
    cargo build --release
fi

# Kiem tra xem session da ton tai chua
tmux has-session -t $SESSION_NAME 2>/dev/null

if [ $? != 0 ]; then
    # Tao session moi (chạy ngầm -d)
    echo "[+] Dang khoi tao session tmux: $SESSION_NAME"
    tmux new-session -d -s $SESSION_NAME "sudo $BINARY_PATH"
    echo "[+] Proxy dang chay ngam trong tmux."
else
    echo "[!] Session '$SESSION_NAME' dang duoc chay."
fi

echo "-------------------------------------------------------"
echo "=> De THEO DOI (Monitor), hay go:  tmux attach -t $SESSION_NAME"
echo "=> De THOAT RA (nhung van chay), nhan: Ctrl+B sau do nhan D"
echo "-------------------------------------------------------"
