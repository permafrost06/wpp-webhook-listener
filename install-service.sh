#!/bin/bash
set -e

SERVICE_NAME="webhook-listener"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
USER_NAME="webhook-listener"
WORKING_DIR="/home/webhook-listener"

# Check if we're running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (use sudo)"
    exit 1
fi

echo "Installing webhook listener service..."

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

# Copy service file
if [[ ! -f "webhook-listener.service" ]]; then
    echo "Error: Service file 'webhook-listener.service' not found"
    exit 1
fi

echo "Installing service file to $SERVICE_FILE"
cp "webhook-listener.service" "$SERVICE_FILE"
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