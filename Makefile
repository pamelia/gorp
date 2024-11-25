# Makefile for building the Go Reverse Proxy project

BINARY_NAME = gorp
BUILD_DIR = build

.PHONY: all clean linux windows darwin

all: clean linux windows darwin

clean:
	rm -rf $(BUILD_DIR)

linux:
	@echo "Building for Linux..."
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64

windows:
	@echo "Building for Windows..."
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe

darwin:
	@echo "Building for macOS..."
	GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64
