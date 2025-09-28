# The Sovereign Eye - Build System
SHELL := /bin/bash
.PHONY: all build test clean install-deps migrate dev prod docker-build

# Build variables
VERSION ?= $(shell git describe --tags --always --dirty)
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT := $(shell git rev-parse --short HEAD)
LDFLAGS := -X main.version=$(VERSION) -X main.buildDate=$(BUILD_DATE) -X main.gitCommit=$(GIT_COMMIT)

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Binary names
ORCHESTRATOR_BINARY=sovereign-orchestrator
API_BINARY=sovereign-api
WORKER_BINARY=sovereign-worker
SCANNER_BINARY=sovereign-scanner

# Directories
CMD_DIR=./cmd
BIN_DIR=./bin
DOCKER_DIR=./deployments/docker

all: build

install-deps:
	@echo "Installing Go dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy
	@echo "Installing Node.js dependencies..."
	cd web && npm install
	@echo "Installing Python dependencies..."
	pip install -r tools/requirements.txt
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

build: build-orchestrator build-api build-worker build-scanner

build-orchestrator:
	@echo "Building Orchestrator..."
	$(GOBUILD) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(ORCHESTRATOR_BINARY) $(CMD_DIR)/orchestrator/main.go

build-api:
	@echo "Building API Server..."
	$(GOBUILD) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(API_BINARY) $(CMD_DIR)/api/main.go

build-worker:
	@echo "Building Worker..."
	$(GOBUILD) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(WORKER_BINARY) $(CMD_DIR)/worker/main.go

build-scanner:
	@echo "Building Scanner..."
	$(GOBUILD) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(SCANNER_BINARY) $(CMD_DIR)/scanner/main.go

test:
	@echo "Running tests..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	@echo "Running security checks..."
	gosec -fmt json -out gosec-report.json ./...
	@echo "Running linter..."
	golangci-lint run

clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BIN_DIR)
	rm -f coverage.out gosec-report.json

migrate:
	@echo "Running database migrations..."
	migrate -path ./deployments/migrations -database "postgresql://localhost/sovereign_eye?sslmode=disable" up

docker-build:
	@echo "Building Docker images..."
	docker build -f $(DOCKER_DIR)/Dockerfile.orchestrator -t sovereign-eye/orchestrator:$(VERSION) .
	docker build -f $(DOCKER_DIR)/Dockerfile.api -t sovereign-eye/api:$(VERSION) .
	docker build -f $(DOCKER_DIR)/Dockerfile.worker -t sovereign-eye/worker:$(VERSION) .
	docker build -f $(DOCKER_DIR)/Dockerfile.scanner -t sovereign-eye/scanner:$(VERSION) .

docker-sign:
	@echo "Signing container images with Cosign..."
	cosign sign --key cosign.key sovereign-eye/orchestrator:$(VERSION)
	cosign sign --key cosign.key sovereign-eye/api:$(VERSION)
	cosign sign --key cosign.key sovereign-eye/worker:$(VERSION)
	cosign sign --key cosign.key sovereign-eye/scanner:$(VERSION)

sbom:
	@echo "Generating SBOMs..."
	syft sovereign-eye/orchestrator:$(VERSION) -o spdx-json > sbom-orchestrator.json
	syft sovereign-eye/api:$(VERSION) -o spdx-json > sbom-api.json
	syft sovereign-eye/worker:$(VERSION) -o spdx-json > sbom-worker.json
	syft sovereign-eye/scanner:$(VERSION) -o spdx-json > sbom-scanner.json

dev:
	@echo "Starting development environment..."
	docker-compose -f deployments/docker/docker-compose.dev.yml up -d
	@echo "Starting services in development mode..."
	air -c .air.toml

prod:
	@echo "Building for production..."
	CGO_ENABLED=0 GOOS=linux $(GOBUILD) -ldflags "$(LDFLAGS) -s -w" -o $(BIN_DIR)/$(ORCHESTRATOR_BINARY) $(CMD_DIR)/orchestrator/main.go
	CGO_ENABLED=0 GOOS=linux $(GOBUILD) -ldflags "$(LDFLAGS) -s -w" -o $(BIN_DIR)/$(API_BINARY) $(CMD_DIR)/api/main.go
	CGO_ENABLED=0 GOOS=linux $(GOBUILD) -ldflags "$(LDFLAGS) -s -w" -o $(BIN_DIR)/$(WORKER_BINARY) $(CMD_DIR)/worker/main.go
	CGO_ENABLED=0 GOOS=linux $(GOBUILD) -ldflags "$(LDFLAGS) -s -w" -o $(BIN_DIR)/$(SCANNER_BINARY) $(CMD_DIR)/scanner/main.go

helm-package:
	@echo "Packaging Helm chart..."
	helm package deployments/helm/sovereign-eye

proto:
	@echo "Generating protobuf code..."
	protoc --go_out=. --go-grpc_out=. api/proto/*.proto

.DEFAULT_GOAL := all