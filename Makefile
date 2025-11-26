# Binary name
BINARY_NAME=aspia-api

# Build directory
BUILD_DIR=build

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get

all: build

build:
	mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) -v main.go
	cp config.ini.example $(BUILD_DIR)/config.ini.example
	# Copy config.ini if it exists, otherwise ignore
	cp config.ini $(BUILD_DIR)/config.ini 2>/dev/null || :
	@echo "Build complete. Binary is in $(BUILD_DIR)/$(BINARY_NAME)"

clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)

run:
	$(GOBUILD) -o $(BINARY_NAME) -v main.go
	./$(BINARY_NAME)

deps:
	$(GOGET) -v ./...
