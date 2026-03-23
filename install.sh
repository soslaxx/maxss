#!/bin/bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run as root (sudo)."
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

TARGET_DIR="/var/www/maxss-core"
SERVICE_FILE="/etc/systemd/system/maxss.service"
SERVICE_NAME="maxss.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GO_REQUIRED="1.23"
GO_INSTALL_VERSION="1.23.8"

arch="$(uname -m)"
case "$arch" in
  x86_64) GO_ARCH="amd64" ;;
  aarch64|arm64) GO_ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $arch"
    exit 1
    ;;
esac

echo "[1/8] Installing base dependencies..."
apt-get update -y
apt-get install -y --no-install-recommends ca-certificates curl tar openssl sqlite3 rsync systemd

need_go_install=1
if command -v go >/dev/null 2>&1; then
  current_go="$(go version | awk '{print $3}' | sed 's/go//')"
  if dpkg --compare-versions "$current_go" ge "$GO_REQUIRED"; then
    need_go_install=0
  fi
fi

if [[ "$need_go_install" -eq 1 ]]; then
  echo "[2/8] Installing Go ${GO_INSTALL_VERSION}..."
  tmp_go_tar="/tmp/go${GO_INSTALL_VERSION}.linux-${GO_ARCH}.tar.gz"
  curl -fsSL "https://go.dev/dl/go${GO_INSTALL_VERSION}.linux-${GO_ARCH}.tar.gz" -o "$tmp_go_tar"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "$tmp_go_tar"
  rm -f "$tmp_go_tar"
else
  echo "[2/8] Go is already installed and meets version requirement."
fi

export PATH="/usr/local/go/bin:${PATH}"

echo "[3/8] Deploying source to ${TARGET_DIR}..."
mkdir -p "$TARGET_DIR"
rsync -a --delete \
  --exclude '.git' \
  --exclude 'users.db' \
  --exclude 'configs' \
  --exclude 'certs' \
  "$SCRIPT_DIR/" "$TARGET_DIR/"

mkdir -p "$TARGET_DIR/configs" "$TARGET_DIR/certs" "$TARGET_DIR/logs"

echo "[4/8] Building maxss binary..."
cd "$TARGET_DIR"
/usr/local/go/bin/go mod tidy
/usr/local/go/bin/go build -trimpath -ldflags "-s -w" -o "$TARGET_DIR/maxss" ./cmd/maxss

echo "[5/8] Initializing database/configs..."
"$TARGET_DIR/maxss" init --base-dir "$TARGET_DIR"

echo "[6/8] Installing systemd service..."
cat > "$SERVICE_FILE" <<'UNIT'
[Unit]
Description=MAXSS Core Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/var/www/maxss-core
ExecStart=/var/www/maxss-core/maxss serve --base-dir /var/www/maxss-core
Restart=always
RestartSec=2
LimitNOFILE=1048576
NoNewPrivileges=true
ReadWritePaths=/var/www/maxss-core
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
UNIT

chmod 0755 "$TARGET_DIR/maxss"

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

echo "[7/8] Optional PATH setup"
read -r -p "Add 'maxss' command to system PATH so you can run it from anywhere? (y/n) [y]: " ADD_TO_PATH
ADD_TO_PATH="${ADD_TO_PATH:-y}"
if [[ "$ADD_TO_PATH" =~ ^[Yy]$ ]]; then
  ln -sf "$TARGET_DIR/maxss" /usr/local/bin/maxss
  chmod 0755 /usr/local/bin/maxss
  echo "Added /usr/local/bin/maxss"
else
  echo "Skipped PATH symlink."
fi

echo "[8/8] Done"
echo "Installation complete."
echo "Service status: systemctl status maxss.service"
