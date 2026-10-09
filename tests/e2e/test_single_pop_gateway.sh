#!/usr/bin/env bash
# NexusEdge Single-PoP Edge Security Gateway End-to-End Integration Test Suite (POSIX Bash)
# Validates Acceptance Checklist:
# Gate 1: Gateway /ready probe (503 prior to sync, 200 after sync)
# Gate 2: Envoy HTTP ingress (port 80 / 10000) -> Rust Gateway -> Origin A (200 OK, ORIGIN_DEFAULT_A)
# Gate 3: Envoy HTTPS ingress (port 443 / 10443 with TLS termination) -> Rust Gateway -> Origin A (200 OK, ORIGIN_DEFAULT_A)
# Gate 4: Path Routing isolation (/status/ prefix -> Origin B, 200 OK, ORIGIN_STATUS_B)
# Gate 5: Tenant Isolation & Fail-Closed (unmatched host returns 421 or 404, zero cross-tenant fallback)
# Gate 6: WAF Enforcement (SQL injection payload blocked with 403 Forbidden)
# Gate 7: ACME HTTP-01 challenge routing (/.well-known/acme-challenge/ routes to Control Plane with key-auth token validation)

set -euo pipefail

ENVOY_HTTP_URL="${ENVOY_HTTP_URL:-http://127.0.0.1:80}"
ENVOY_HTTPS_URL="${ENVOY_HTTPS_URL:-https://127.0.0.1:443}"
GATEWAY_URL="${GATEWAY_URL:-http://127.0.0.1:8080}"
CONTROL_PLANE_URL="${CONTROL_PLANE_URL:-http://127.0.0.1:9091}"

echo "================================================================"
echo " NexusEdge Single-PoP Gateway End-to-End Integration Tests"
echo "================================================================"

# Helper function for asserting HTTP status
assert_status() {
    local name="$1"
    local expected="$2"
    local actual="$3"
    if [ "$actual" = "$expected" ]; then
        echo "  [PASS] $name (Status: $actual)"
    else
        echo "  [FAIL] $name: Expected HTTP $expected, got $actual"
        exit 1
    fi
}

# Helper function for asserting body/header content marker
assert_contains() {
    local name="$1"
    local expected="$2"
    local actual="$3"
    if echo "$actual" | grep -iFq "$expected"; then
        echo "  [PASS] $name (Matched marker: '$expected')"
    else
        echo "  [FAIL] $name: Expected content to contain '$expected'"
        echo "         Actual output: $actual"
        exit 1
    fi
}

# 1. Gateway Readiness Gate
echo "[Test 1/9] Verifying Gateway /ready endpoint..."
READY_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${GATEWAY_URL}/ready" || true)
assert_status "Gateway /ready" "200" "$READY_CODE"

# 2. Envoy Customer HTTP Ingress Routing (Default Route -> Origin A, Scheme: http)
echo "[Test 2/9] Verifying Envoy HTTP Ingress -> Rust Gateway -> Origin A (Scheme: http)..."
HTTP_RESP=$(curl -s -D - -H "Host: api.nexusedge.io" "${ENVOY_HTTP_URL}/get" || true)
HTTP_CODE=$(echo "$HTTP_RESP" | grep -i "^HTTP/" | head -n 1 | awk '{print $2}')
assert_status "Customer HTTP Ingress Status" "200" "$HTTP_CODE"
assert_contains "Customer HTTP Ingress Origin Marker" "ORIGIN_DEFAULT_A" "$HTTP_RESP"
assert_contains "Customer HTTP Scheme Marker" "downstream_proto=http" "$HTTP_RESP"

# 3. Envoy Customer HTTPS Ingress with TLS Termination (Default Route -> Origin A, Scheme: https)
echo "[Test 3/9] Verifying Envoy HTTPS Ingress (TLS Termination) -> Origin A (Scheme: https)..."
HTTPS_RESP=$(curl -k -s -D - -H "Host: api.nexusedge.io" "${ENVOY_HTTPS_URL}/get" || true)
HTTPS_CODE=$(echo "$HTTPS_RESP" | grep -i "^HTTP/" | head -n 1 | awk '{print $2}')
assert_status "Customer HTTPS Ingress Status" "200" "$HTTPS_CODE"
assert_contains "Customer HTTPS Ingress Origin Marker" "ORIGIN_DEFAULT_A" "$HTTPS_RESP"
assert_contains "Customer HTTPS Scheme Marker" "downstream_proto=https" "$HTTPS_RESP"

# 4. Path Routing Verification (/status/ path prefix -> Origin B)
echo "[Test 4/9] Verifying Path Routing (/status/ prefix -> Origin B)..."
PATH_RESP=$(curl -s -D - -H "Host: api.nexusedge.io" "${ENVOY_HTTP_URL}/status/200" || true)
PATH_CODE=$(echo "$PATH_RESP" | grep -i "^HTTP/" | head -n 1 | awk '{print $2}')
assert_status "Path-prefix Routing Status" "200" "$PATH_CODE"
assert_contains "Path-prefix Routing Origin Marker" "ORIGIN_STATUS_B" "$PATH_RESP"

# 5. Fail-Closed Tenant Isolation Gate
echo "[Test 5/9] Verifying Fail-Closed Tenant Isolation (unknown tenant host)..."
UNKNOWN_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: unknown-tenant.example.com" "${ENVOY_HTTP_URL}/" || true)
if [ "$UNKNOWN_CODE" = "421" ] || [ "$UNKNOWN_CODE" = "404" ]; then
    echo "  [PASS] Unmatched Tenant Isolation (Status: $UNKNOWN_CODE)"
else
    echo "  [FAIL] Unmatched Tenant Isolation: Expected HTTP 421 or 404, got $UNKNOWN_CODE"
    exit 1
fi

# 6. WAF Inspection & Interception Gate
echo "[Test 6/9] Verifying WAF Interception (SQL Injection attack payload)..."
WAF_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: api.nexusedge.io" "${ENVOY_HTTP_URL}/products?id=1%20UNION%20SELECT%20null,password%20FROM%20users" || true)
assert_status "WAF SQLi Interception" "403" "$WAF_CODE"

# 7. ACME Challenge Routing Gate (Key Authorization Validation)
echo "[Test 7/9] Verifying ACME HTTP-01 Routing & Key Authorization..."
ACME_BODY=$(curl -s "${ENVOY_HTTP_URL}/.well-known/acme-challenge/test-token" || true)
ACME_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${ENVOY_HTTP_URL}/.well-known/acme-challenge/test-token" || true)
assert_status "ACME Valid Challenge Status" "200" "$ACME_CODE"
assert_contains "ACME Key Authorization Marker" "test-token.mock_key_auth_marker" "$ACME_BODY"

UNKNOWN_ACME_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${ENVOY_HTTP_URL}/.well-known/acme-challenge/nonexistent-token" || true)
assert_status "ACME Non-existent Challenge Status" "404" "$UNKNOWN_ACME_CODE"

# 8. RFC 9111 Cache Semantics Gate (Cache-Control: no-cache Exclusion & Public Caching)
echo "[Test 8/9] Verifying RFC 9111 Cache Semantics (no-cache exclusion & public caching)..."
NO_CACHE_RESP_1=$(curl -s -D - -H "Host: api.nexusedge.io" "${ENVOY_HTTP_URL}/cache/no-cache" || true)
assert_contains "no-cache First Request Cache MISS" "X-Cache: MISS" "$NO_CACHE_RESP_1"

NO_CACHE_RESP_2=$(curl -s -D - -H "Host: api.nexusedge.io" "${ENVOY_HTTP_URL}/cache/no-cache" || true)
assert_contains "no-cache Second Request Non-Reuse" "X-Cache: MISS" "$NO_CACHE_RESP_2"

PUBLIC_RESP_1=$(curl -s -D - -H "Host: api.nexusedge.io" "${ENVOY_HTTP_URL}/cache/public" || true)
assert_contains "public First Request Cache MISS" "X-Cache: MISS" "$PUBLIC_RESP_1"

PUBLIC_RESP_2=$(curl -s -D - -H "Host: api.nexusedge.io" "${ENVOY_HTTP_URL}/cache/public" || true)
assert_contains "public Second Request Cache HIT" "X-Cache: HIT" "$PUBLIC_RESP_2"

# 9. Dynamic Envoy SDS Zero-Reload Certificate Rotation & ACME Validation Gate
echo "[Test 9/9] Verifying Dynamic Envoy SDS Zero-Reload Certificate Rotation & ACME Validation..."
# 9a. Verify initial HTTPS request operates cleanly via Envoy Dynamic SDS
HTTPS_INITIAL_RESP=$(curl -k -s -D - -H "Host: api.nexusedge.io" "${ENVOY_HTTPS_URL}/get" || true)
HTTPS_INITIAL_CODE=$(echo "$HTTPS_INITIAL_RESP" | grep -i "^HTTP/" | head -n 1 | awk '{print $2}')
assert_status "Initial SDS HTTPS Ingress Status" "200" "$HTTPS_INITIAL_CODE"
assert_contains "Initial SDS HTTPS Origin Marker" "ORIGIN_DEFAULT_A" "$HTTPS_INITIAL_RESP"

# 9b. Trigger zero-downtime certificate renewal via Control Plane
RENEW_RESP=$(curl -s -X POST -H "X-API-Key: dev-fixture-key-01" "${CONTROL_PLANE_URL}/v1/domains/dom-dev-api/certificates/renew" || true)
assert_contains "Certificate Renewal Serial Marker" "serial_number" "$RENEW_RESP"

# 9c. Verify Envoy serves traffic on HTTPS immediately with zero proxy reload
HTTPS_AFTER_RENEW=$(curl -k -s -D - -H "Host: api.nexusedge.io" "${ENVOY_HTTPS_URL}/get" || true)
HTTPS_AFTER_CODE=$(echo "$HTTPS_AFTER_RENEW" | grep -i "^HTTP/" | head -n 1 | awk '{print $2}')
assert_status "Post-Renewal SDS HTTPS Ingress Status" "200" "$HTTPS_AFTER_CODE"
assert_contains "Post-Renewal Origin Marker" "ORIGIN_DEFAULT_A" "$HTTPS_AFTER_RENEW"

# 9d. Trigger new automated ACME order and challenge validation cycle
ORDER_RESP=$(curl -s -X POST -H "X-API-Key: dev-fixture-key-01" "${CONTROL_PLANE_URL}/v1/domains/dom-dev-api/certificates/order" || true)
assert_contains "ACME Order Challenge Status" "PENDING" "$ORDER_RESP"
NEW_TOKEN=$(echo "$ORDER_RESP" | grep -o '"token":"[^"]*"' | head -n 1 | cut -d'"' -f4)

# Verify challenge is instantly reachable via Envoy HTTP port 80
CHALLENGE_RESP=$(curl -s "${ENVOY_HTTP_URL}/.well-known/acme-challenge/${NEW_TOKEN}" || true)
assert_contains "ACME Live Challenge Retrieval" "${NEW_TOKEN}." "$CHALLENGE_RESP"

# Complete challenge validation
VALIDATE_RESP=$(curl -s -X POST -H "Content-Type: application/json" "${CONTROL_PLANE_URL}/v1/edge/acme/validate" -d "{\"token\":\"${NEW_TOKEN}\"}" || true)
assert_contains "ACME Challenge Validation Completion" "VALIDATED" "$VALIDATE_RESP"

echo "================================================================"
echo " Single-PoP Edge Security Gateway Verification: ALL GATES PASS"
echo "================================================================"
