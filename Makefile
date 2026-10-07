.PHONY: all build-all test-all check-rust check-go clean help

help:
	@echo "NexusEdge Polyglot Monorepo Build System"
	@echo "  make build-all    - Build all Data Plane and Control Plane binaries"
	@echo "  make test-all     - Run all unit and integration test suites"
	@echo "  make check-rust   - Verify Rust Data Plane crates"
	@echo "  make check-go     - Verify Go Control Plane services"
	@echo "  make run-gateway  - Start Edge Data Plane Gateway"
	@echo "  make run-router   - Start Go Global Router & Workload Dispatcher"
	@echo "  make run-ai       - Execute Intelligence Plane optimizer"

all: build-all

check-rust:
	cd dataplane/edge/gateway && cargo check

build-all: check-rust
	cd dataplane/edge/gateway && cargo build

test-all:
	cd dataplane/edge/gateway && cargo test
	python intelligence/scheduling/workload-scheduler/optimizer.py

run-gateway:
	cd dataplane/edge/gateway && cargo run

run-router:
	cd services/network/global-router && go run cmd/global-router/main.go

run-ai:
	python intelligence/scheduling/workload-scheduler/optimizer.py

clean:
	cd dataplane/edge/gateway && cargo clean
