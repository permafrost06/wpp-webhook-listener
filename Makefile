BINARY_NAME=webhook-listener
BUILD_DIR=build
INSTALL_PATH=/usr/local/bin

.PHONY: all build clean install install-service uninstall

all: build

build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) *.go

install: build
	@echo "Installing $(BINARY_NAME) to $(INSTALL_PATH)..."
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_PATH)/$(BINARY_NAME)
	@echo "Installation completed."

install-service:
	@echo "Installing webhook service..."
	chmod +x install-service.sh
	sudo ./install-service.sh

install-all: install install-service
	@echo "Complete installation finished!"

uninstall:
	@echo "Removing $(BINARY_NAME) from $(INSTALL_PATH)..."
	sudo rm -f $(INSTALL_PATH)/$(BINARY_NAME)
	@echo "Uninstalled."

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)

help:
	@echo "Available targets:"
	@echo "  build              - Build the binary"
	@echo "  install            - Install the binary to $(INSTALL_PATH) (requires sudo)"
	@echo "  install-service    - Install webhook systemd service"
	@echo "  install-all        - Install binary and service"
	@echo "  uninstall          - Remove the binary from $(INSTALL_PATH) (requires sudo)"
	@echo "  clean              - Remove build artifacts"
	@echo "  help               - Show this help message" 

