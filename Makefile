.PHONY: build build-cli run test lint migrate migrate-down docker-up docker-down clean

# Variables
BINARY=sshvault-server
CLI_BINARY=sshvault-cli
CMD_DIR=./cmd/server
CLI_DIR=./cmd/cli
DATABASE_URL?=postgres://sshvault:sshvault@localhost:5432/sshvault?sslmode=disable

## Build server
build:
	go build -o bin/$(BINARY) $(CMD_DIR)

## Build CLI
build-cli:
	go build -o bin/$(CLI_BINARY) $(CLI_DIR)

## Build all
build-all: build build-cli

## Run server locally
run:
	go run $(CMD_DIR)

## Run CLI
cli:
	go run $(CLI_DIR) $(ARGS)

## Run tests
test:
	go test -v -race -count=1 ./...

## Run tests with coverage
test-cover:
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

## Lint
lint:
	golangci-lint run ./...

## Run migrations up
migrate:
	migrate -path migrations -database "$(DATABASE_URL)" up

## Run migrations down
migrate-down:
	migrate -path migrations -database "$(DATABASE_URL)" down

## Docker compose up
docker-up:
	docker compose -f docker/docker-compose.yml up -d --build

## Docker compose down
docker-down:
	docker compose -f docker/docker-compose.yml down

## Create database backup
backup:
	go run $(CLI_DIR) backup create

## Start auto-backup daemon
backup-auto:
	go run $(CLI_DIR) backup auto

## Generate Ed25519 key pair
keygen:
	mkdir -p keys
	openssl genpkey -algorithm Ed25519 -out keys/ed25519.pem

## Clean build artifacts
clean:
	rm -rf bin/ coverage.out coverage.html

## Show help
help:
	@echo "Available targets:"
	@echo ""
	@echo "  Server:"
	@echo "    build        - Build the server binary"
	@echo "    run          - Run the server locally"
	@echo ""
	@echo "  CLI:"
	@echo "    build-cli    - Build the CLI binary"
	@echo "    build-all    - Build server + CLI"
	@echo "    cli ARGS=... - Run CLI with arguments"
	@echo ""
	@echo "  Database:"
	@echo "    migrate      - Run database migrations"
	@echo "    migrate-down - Rollback database migrations"
	@echo "    backup       - Create database backup"
	@echo "    backup-auto  - Start auto-backup daemon"
	@echo ""
	@echo "  Docker:"
	@echo "    docker-up    - Start Docker Compose stack"
	@echo "    docker-down  - Stop Docker Compose stack"
	@echo ""
	@echo "  Other:"
	@echo "    test         - Run all tests"
	@echo "    test-cover   - Run tests with coverage report"
	@echo "    lint         - Run linter"
	@echo "    keygen       - Generate Ed25519 key pair"
	@echo "    clean        - Clean build artifacts"
	@echo ""
	@echo "  CLI Usage Examples:"
	@echo "    make cli ARGS='user list'"
	@echo "    make cli ARGS='user info admin@example.com'"
	@echo "    make cli ARGS='backup create'"
	@echo "    make cli ARGS='backup auto'"
