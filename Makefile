BINARY_NAME=webhook-listener
BUILD_DIR=build
INSTALL_PATH=/usr/local/bin

.PHONY: all build clean install install-completions install-service uninstall uninstall-completions test

all: build

build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) main.go

install: build
	@echo "Installing $(BINARY_NAME) to $(INSTALL_PATH)..."
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_PATH)/$(BINARY_NAME)
	@echo "Installation completed. Run '$(BINARY_NAME) install' to set up the workspace."

install-completions:
	@echo "Installing shell completions..."
	chmod +x install-completions.sh
	./install-completions.sh

install-service:
	@echo "Installing webhook service..."
	chmod +x install-service.sh
	sudo ./install-service.sh

install-all: install install-completions install-service
	@echo "Complete installation finished!"

uninstall:
	@echo "Removing $(BINARY_NAME) from $(INSTALL_PATH)..."
	sudo rm -f $(INSTALL_PATH)/$(BINARY_NAME)
	@echo "Uninstalled. Note: ~/.wpp-deployer directory was not removed."

uninstall-completions:
	@echo "Removing shell completions..."
	@sudo rm -f /usr/local/share/bash-completion/completions/wpp-deployer 2>/dev/null || true
	@sudo rm -f /usr/share/bash-completion/completions/wpp-deployer 2>/dev/null || true
	@rm -f ~/.local/share/bash-completion/completions/wpp-deployer 2>/dev/null || true
	@sudo rm -f /usr/local/share/zsh/site-functions/_wpp-deployer 2>/dev/null || true
	@sudo rm -f /usr/share/zsh/site-functions/_wpp-deployer 2>/dev/null || true
	@rm -f ~/.local/share/zsh/site-functions/_wpp-deployer 2>/dev/null || true
	@echo "Shell completions removed."

uninstall-all: uninstall uninstall-completions
	@echo "Complete uninstallation finished!"

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)

test:
	go test -v ./...

help:
	@echo "Available targets:"
	@echo "  build              - Build the binary"
	@echo "  install            - Install the binary to $(INSTALL_PATH) (requires sudo)"
	@echo "  install-completions - Install shell completion scripts"
	@echo "  install-service    - Install webhook systemd service"
	@echo "  install-all        - Install binary, completions, and service"
	@echo "  uninstall          - Remove the binary from $(INSTALL_PATH) (requires sudo)"
	@echo "  uninstall-completions - Remove shell completion scripts"
	@echo "  uninstall-all      - Remove binary and completions"
	@echo "  clean              - Remove build artifacts"
	@echo "  test               - Run tests"
	@echo "  help               - Show this help message" 

