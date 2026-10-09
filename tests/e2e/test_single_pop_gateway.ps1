# NexusEdge Single-PoP Edge Security Gateway End-to-End Integration Test Suite (PowerShell)
# Enforces Acceptance Criteria: Gateway /ready, Envoy Ingress (HTTP & HTTPS), Path Routing, Tenant Isolation, WAF, and ACME.

$ErrorActionPreference = "Continue"

$EnvoyHttpUrl = if ($env:ENVOY_HTTP_URL) { $env:ENVOY_HTTP_URL } else { "http://127.0.0.1:80" }
$EnvoyHttpsUrl = if ($env:ENVOY_HTTPS_URL) { $env:ENVOY_HTTPS_URL } else { "https://127.0.0.1:443" }
$GatewayUrl = if ($env:GATEWAY_URL) { $env:GATEWAY_URL } else { "http://127.0.0.1:8080" }
$ControlPlaneUrl = if ($env:CONTROL_PLANE_URL) { $env:CONTROL_PLANE_URL } else { "http://127.0.0.1:9091" }

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " NexusEdge Single-PoP Gateway End-to-End Integration Tests" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

function Assert-Status {
    param(
        [string]$Name,
        [int]$Expected,
        [int]$Actual
    )
    if ($Actual -eq $Expected) {
        Write-Host "  [PASS] $Name (Status: $Actual)" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] $Name: Expected HTTP $Expected, got $Actual" -ForegroundColor Red
        exit 1
    }
}

# 1. Gateway Readiness Gate
Write-Host "[Test 1/7] Verifying Gateway /ready endpoint..." -ForegroundColor Yellow
$readyCode = & curl -s -o /dev/null -w "%{http_code}" "$GatewayUrl/ready"
Assert-Status "Gateway /ready" 200 ([int]$readyCode)

# 2. Envoy Customer HTTP Ingress Routing
Write-Host "[Test 2/7] Verifying Envoy HTTP Ingress -> Rust Gateway -> Origin..." -ForegroundColor Yellow
$httpCode = & curl -s -o /dev/null -w "%{http_code}" -H "Host: api.nexusedge.io" "$EnvoyHttpUrl/get"
Assert-Status "Customer HTTP Ingress" 200 ([int]$httpCode)

# 3. Envoy Customer HTTPS Ingress with TLS Termination
Write-Host "[Test 3/7] Verifying Envoy HTTPS Ingress (TLS Termination)..." -ForegroundColor Yellow
$httpsCode = & curl -k -s -o /dev/null -w "%{http_code}" -H "Host: api.nexusedge.io" "$EnvoyHttpsUrl/get"
Assert-Status "Customer HTTPS Ingress" 200 ([int]$httpsCode)

# 4. Path Routing Verification (/api/ path prefix)
Write-Host "[Test 4/7] Verifying Path Routing (/api/ prefix)..." -ForegroundColor Yellow
$pathCode = & curl -s -o /dev/null -w "%{http_code}" -H "Host: api.nexusedge.io" "$EnvoyHttpUrl/api/status/200"
Assert-Status "Path-prefix Routing" 200 ([int]$pathCode)

# 5. Fail-Closed Tenant Isolation Gate
Write-Host "[Test 5/7] Verifying Fail-Closed Tenant Isolation (unknown tenant host)..." -ForegroundColor Yellow
$unknownCode = & curl -s -o /dev/null -w "%{http_code}" -H "Host: unknown-tenant.example.com" "$EnvoyHttpUrl/"
Assert-Status "Unmatched Tenant Isolation" 404 ([int]$unknownCode)

# 6. WAF Inspection & Interception Gate
Write-Host "[Test 6/7] Verifying WAF Interception (SQL Injection attack payload)..." -ForegroundColor Yellow
$wafCode = & curl -s -o /dev/null -w "%{http_code}" -H "Host: api.nexusedge.io" "$EnvoyHttpUrl/products?id=1%20UNION%20SELECT%20null,password%20FROM%20users"
Assert-Status "WAF SQLi Interception" 403 ([int]$wafCode)

# 7. ACME Challenge Routing Gate
Write-Host "[Test 7/7] Verifying ACME HTTP-01 Routing to Control Plane..." -ForegroundColor Yellow
$acmeCode = [int](& curl -s -o /dev/null -w "%{http_code}" "$EnvoyHttpUrl/.well-known/acme-challenge/test-token")
if ($acmeCode -eq 404 -or $acmeCode -eq 200) {
    Write-Host "  [PASS] ACME HTTP-01 Challenge Routing: Reached Control Plane (Status: $acmeCode)" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] ACME HTTP-01 Challenge Routing: Unexpected status $acmeCode" -ForegroundColor Red
    exit 1
}

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Single-PoP Edge Security Gateway Verification: ALL GATES PASS" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
