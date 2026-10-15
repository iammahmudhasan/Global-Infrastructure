#!/usr/bin/env bash
# NexusEdge Pre-Push CI Parity Verification Script (Bash)
# Enforces Rule 127: Complete local parity with .github/workflows/ci.yml before pushing.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "================================================================"
echo " NexusEdge Pre-Push CI Parity Suite (Rule 127 Enforcer)"
echo "================================================================"

GO_SERVICES=(
  "services/edge/config-controller"
  "services/network/global-router"
  "apps/cli"
)

# 1. Go Format Gate
echo "[1/7] Running Go format check (gofmt -l)..."
for svc in "${GO_SERVICES[@]}"; do
  if [ -d "${REPO_ROOT}/${svc}" ]; then
    pushd "${REPO_ROOT}/${svc}" > /dev/null
    UNFORMATTED=$(gofmt -l .)
    if [ -n "$UNFORMATTED" ]; then
      echo "ERROR: Unformatted Go files detected in ${svc}:"
      echo "$UNFORMATTED"
      echo "Fix by running: cd ${svc} && gofmt -w ."
      exit 1
    fi
    popd > /dev/null
  fi
done
echo " -> Go format check passed."

# 2. Go Vet and Tests Gate
echo "[2/7] Running Go vet and unit tests..."
for svc in "${GO_SERVICES[@]}"; do
  if [ -d "${REPO_ROOT}/${svc}" ]; then
    pushd "${REPO_ROOT}/${svc}" > /dev/null
    echo "   Testing ${svc}..."
    go vet ./...
    go test -v -race ./...
    popd > /dev/null
  fi
done
echo " -> Go vet and tests passed."

# 3. Rust Format Gate
echo "[3/7] Running Rust format check (cargo fmt --check)..."
GATEWAY_CARGO="${REPO_ROOT}/dataplane/edge/gateway/Cargo.toml"
cargo fmt --manifest-path "${GATEWAY_CARGO}" --all -- --check
echo " -> Rust format check passed."

# 4. Rust Clippy Gate (-D warnings)
echo "[4/7] Running Rust Clippy linter (cargo clippy -D warnings)..."
cargo clippy --manifest-path "${GATEWAY_CARGO}" --all-targets --all-features -- -D warnings
echo " -> Rust clippy passed with zero warnings."

# 5. Rust Compiler Check
echo "[5/7] Running Rust check (cargo check)..."
cargo check --manifest-path "${GATEWAY_CARGO}"
cargo test --manifest-path "${GATEWAY_CARGO}"
echo " -> Rust check and tests passed."

# 6. Python Intelligence Optimizer Gate
echo "[6/8] Verifying Python Intelligence scheduler..."
python "${REPO_ROOT}/intelligence/scheduling/workload-scheduler/optimizer.py"
echo " -> Python optimizer passed."
python "${REPO_ROOT}/tools/ci/validate_manifests.py"
echo " -> Infrastructure manifests verified."

# 7. Dashboard Security & BFF Acceptance Gate
echo "[7/8] Running Dashboard Security & BFF test suite..."
if command -v node >/dev/null 2>&1; then
  pushd "${REPO_ROOT}/apps/dashboard" > /dev/null
  node --test test/bff.test.js
  popd > /dev/null
  echo " -> Dashboard security tests passed."
else
  echo " -> Node.js not found, skipping local dashboard check."
fi

# 8. Docker Compose Manifest Gate
echo "[8/8] Validating Docker Compose configurations..."
if command -v go >/dev/null 2>&1; then
  go run "${REPO_ROOT}/tools/release/generate_certs.go" "${REPO_ROOT}/deploy/envoy/certs" "${REPO_ROOT}/deploy/postgres/certs"
fi
if command -v docker >/dev/null 2>&1; then
  docker compose -f "${REPO_ROOT}/deploy/docker-compose.yml" config --quiet
  POSTGRES_USER="nexusedge" \
  POSTGRES_PASSWORD="prodpassword123" \
  NEXUSEDGE_DATABASE_URL="postgres://nexusedge:prodpassword123@172.30.0.5:5432/nexusedge_edge?sslmode=verify-full&sslrootcert=/etc/ssl/certs/pg_root.crt" \
  AUDIT_HMAC_KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" \
  NEXUSEDGE_SECRET_ENCRYPTION_KEY="0123456789abcdef0123456789abcdef" \
  NEXUSEDGE_CP_AUTH_TOKEN="ci-token-01" \
  NEXUSEDGE_AI_API_KEYS="ci-key:ci-tenant:proj-core:proj-core:inference:GLOBAL" \
  NEXUSEDGE_CP_POP_ID="singapore" \
  NEXUSEDGE_PUBLIC_IP="80.225.241.129" \
  docker compose -f "${REPO_ROOT}/deploy/docker-compose.prod.yml" config --quiet
  echo " -> Docker Compose validation passed."
else
  echo " -> Docker CLI not found, skipping local compose check."
fi

echo "================================================================"
echo " SUCCESS: All CI Parity Gates Passed. Safe to commit and push!"
echo "================================================================"
