#!/usr/bin/env bash
# NexusEdge Multi-PoP Failover & Chaos Verification Suite (Bash)
# Enforces Acceptance Criteria: Automated Anycast BGP withdrawal, TAT-14 subsea failover,
# Bangladesh NDMA 2026 data sovereignty fail-closed lock, and Maglev minimal disruption.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "================================================================"
echo " NexusEdge Multi-Region Failover & Chaos Verification Suite"
echo "================================================================"

# 1. Config Controller Multi-PoP Chaos & Sovereignty Suite
echo "[Chaos Gate 1/2] Executing Config Controller Multi-PoP Chaos Suite..."
cd "${REPO_ROOT}/services/edge/config-controller"
go test -v -run "TestChaos_" ./test/...

echo " -> Multi-PoP subsea cut & sovereignty chaos tests passed."

# 2. Global Router Maglev Consistent Hashing Chaos Suite
echo "[Chaos Gate 2/2] Executing Maglev Consistent Hashing Chaos Suite..."
cd "${REPO_ROOT}/services/network/global-router"
go test -v -run "TestChaos_" ./internal/policy/...

echo " -> Maglev minimal disruption chaos tests passed."

echo "================================================================"
echo " SUCCESS: All Multi-PoP Chaos Scenarios Passed Resiliency Gates!"
echo "================================================================"
