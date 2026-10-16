# NexusEdge Multi-PoP Failover & Chaos Verification Suite (PowerShell)
# Enforces Acceptance Criteria: Automated Anycast BGP withdrawal, TAT-14 subsea failover,
# Bangladesh NDMA 2026 data sovereignty fail-closed lock, and Maglev minimal disruption.

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $RepoRoot) {
    $RepoRoot = Get-Location
}

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " NexusEdge Multi-Region Failover & Chaos Verification Suite" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# 1. Config Controller Multi-PoP Chaos & Sovereignty Suite
Write-Host "[Chaos Gate 1/2] Executing Config Controller Multi-PoP Chaos Suite..." -ForegroundColor Yellow
$ConfigControllerDir = Join-Path $RepoRoot "services/edge/config-controller"
Push-Location $ConfigControllerDir
try {
    & go test -v -run "TestChaos_" ./test/...
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Config Controller Multi-PoP Chaos tests failed!" -ForegroundColor Red
        exit 1
    }
} finally {
    Pop-Location
}
Write-Host " -> Multi-PoP subsea cut & sovereignty chaos tests passed." -ForegroundColor Green

# 2. Global Router Maglev Consistent Hashing Chaos Suite
Write-Host "[Chaos Gate 2/2] Executing Maglev Consistent Hashing Chaos Suite..." -ForegroundColor Yellow
$GlobalRouterDir = Join-Path $RepoRoot "services/network/global-router"
Push-Location $GlobalRouterDir
try {
    & go test -v -run "TestChaos_" ./internal/policy/...
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Maglev Consistent Hashing Chaos tests failed!" -ForegroundColor Red
        exit 1
    }
} finally {
    Pop-Location
}
Write-Host " -> Maglev minimal disruption chaos tests passed." -ForegroundColor Green

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " SUCCESS: All Multi-PoP Chaos Scenarios Passed Resiliency Gates!" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Cyan
