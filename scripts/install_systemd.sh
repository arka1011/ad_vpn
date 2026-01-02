#!/bin/bash
# Installation script for AD VPN systemd service

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SERVICE_FILE="$PROJECT_ROOT/systemd/ad_vpn.service"
SYSTEMD_DIR="/etc/systemd/system"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

# Check if service file exists
if [ ! -f "$SERVICE_FILE" ]; then
    echo "Error: Service file not found: $SERVICE_FILE"
    exit 1
fi

# Create directories
echo "Creating directories..."
mkdir -p /etc/ad_vpn
mkdir -p /var/lib/ad_vpn
mkdir -p /usr/local/bin

# Copy configuration files
echo "Installing configuration files..."
if [ -f "$PROJECT_ROOT/configs/ad_vpn_config.ini" ]; then
    cp "$PROJECT_ROOT/configs/ad_vpn_config.ini" /etc/ad_vpn/
    echo "  - Installed ad_vpn_config.ini"
else
    echo "  - Warning: ad_vpn_config.ini not found, please create it manually"
fi

if [ -f "$PROJECT_ROOT/configs/ad_zlog_config.conf" ]; then
    cp "$PROJECT_ROOT/configs/ad_zlog_config.conf" /etc/ad_vpn/
    echo "  - Installed ad_zlog_config.conf"
else
    echo "  - Warning: ad_zlog_config.conf not found, please create it manually"
fi

# Copy binary (if built)
if [ -f "$PROJECT_ROOT/build/bin/ad_vpn" ]; then
    cp "$PROJECT_ROOT/build/bin/ad_vpn" /usr/local/bin/
    chmod +x /usr/local/bin/ad_vpn
    echo "  - Installed ad_vpn binary"
else
    echo "  - Warning: ad_vpn binary not found, please build and install manually"
fi

# Install systemd service
echo "Installing systemd service..."
cp "$SERVICE_FILE" "$SYSTEMD_DIR/"
systemctl daemon-reload
echo "  - Service file installed"

# Enable service (but don't start)
echo "Enabling service..."
systemctl enable ad_vpn.service
echo "  - Service enabled (use 'systemctl start ad_vpn' to start)"

echo ""
echo "Installation complete!"
echo ""
echo "To start the service:"
echo "  sudo systemctl start ad_vpn"
echo ""
echo "To check status:"
echo "  sudo systemctl status ad_vpn"
echo ""
echo "To view logs:"
echo "  sudo journalctl -u ad_vpn -f"
echo ""

