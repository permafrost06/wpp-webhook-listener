#!/bin/bash
set -e

SERVICE_NAME="wpp-deployer-webhook"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
USER_NAME="wpp-deployer"
WORKING_DIR="/opt/wpp-deployer"

# Check if we're running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (use sudo)"
    exit 1
fi

echo "Installing wpp-deployer webhook service..."

# Create user if it doesn't exist
if ! id "$USER_NAME" &>/dev/null; then
    echo "Creating user: $USER_NAME"
    useradd --system --no-create-home --shell /bin/false "$USER_NAME"
fi

# Create working directory
if [[ ! -d "$WORKING_DIR" ]]; then
    echo "Creating working directory: $WORKING_DIR"
    mkdir -p "$WORKING_DIR"
    chown "$USER_NAME:$USER_NAME" "$WORKING_DIR"
fi

# Create log directory
if [[ ! -d "/var/log/wpp-deployer" ]]; then
    echo "Creating log directory: /var/log/wpp-deployer"
    mkdir -p "/var/log/wpp-deployer"
    chown "$USER_NAME:$USER_NAME" "/var/log/wpp-deployer"
fi

# Copy service file
if [[ ! -f "wpp-deployer-webhook.service" ]]; then
    echo "Error: Service file 'wpp-deployer-webhook.service' not found"
    exit 1
fi

echo "Installing service file to $SERVICE_FILE"
cp "wpp-deployer-webhook.service" "$SERVICE_FILE"
chmod 644 "$SERVICE_FILE"

# Reload systemd
echo "Reloading systemd daemon"
systemctl daemon-reload

echo "Service installation completed!"
echo
echo "To manage the service:"
echo "  sudo systemctl enable $SERVICE_NAME"
echo "  sudo systemctl start $SERVICE_NAME"
echo "  sudo systemctl status $SERVICE_NAME"
echo "  sudo journalctl -u $SERVICE_NAME -f" 