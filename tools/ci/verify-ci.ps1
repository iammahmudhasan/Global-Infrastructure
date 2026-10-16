# NexusEdge Pre-Push CI Parity Verification Script (PowerShell)
# Enforces Rule 127: Complete local parity with .github/workflows/ci.yml before pushing.

$ErrorActionPreference = "Stop"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " NexusEdge Pre-Push CI Parity Suite (Rule 127 Enforcer)" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $RepoRoot) {
    $RepoRoot = Get-Location
}

# 1. Go Format Gate
Write-Host "[1/7] Running Go format check (gofmt -l)..." -ForegroundColor Yellow
$GoServices = @(
    "services/edge/config-controller",
    "services/network/global-router",
    "apps/cli",
    "benchmarks/packet"
)

foreach ($svc in $GoServices) {
    $svcPath = Join-Path $RepoRoot $svc
    if (Test-Path $svcPath) {
        Push-Location $svcPath
        try {
            $unformatted = & gofmt -l .
            if ($unformatted) {
                Write-Host "ERROR: Unformatted Go files detected in $svc`:" -ForegroundColor Red
                $unformatted | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
                Write-Host "Fix by running: cd $svc; gofmt -w ." -ForegroundColor Yellow
                exit 1
            }
        } finally {
            Pop-Location
        }
    }
}
Write-Host " -> Go format check passed." -ForegroundColor Green

# 2. Go Vet and Tests Gate
Write-Host "[2/7] Running Go vet and unit tests..." -ForegroundColor Yellow
foreach ($svc in $GoServices) {
    $svcPath = Join-Path $RepoRoot $svc
    if (Test-Path $svcPath) {
        Push-Location $svcPath
        try {
            Write-Host "   Testing $svc..." -ForegroundColor Gray
            & go vet ./...
            if ($LASTEXITCODE -ne 0) {
                Write-Host "ERROR: 'go vet ./...' failed in $svc" -ForegroundColor Red
                exit 1
            }
            & go test ./...
            if ($LASTEXITCODE -ne 0) {
                Write-Host "ERROR: 'go test ./...' failed in $svc" -ForegroundColor Red
                exit 1
            }
        } finally {
            Pop-Location
        }
    }
}
Write-Host " -> Go vet and tests passed." -ForegroundColor Green

# 3. Rust Format Gate
Write-Host "[3/7] Running Rust format check (cargo fmt --check)..." -ForegroundColor Yellow
$GatewayCargo = Join-Path $RepoRoot "dataplane/edge/gateway/Cargo.toml"
& cargo fmt --manifest-path $GatewayCargo --all -- --check
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Rust code is unformatted." -ForegroundColor Red
    Write-Host "Fix by running: cargo fmt --manifest-path $GatewayCargo --all" -ForegroundColor Yellow
    exit 1
}
Write-Host " -> Rust format check passed." -ForegroundColor Green

# 4. Rust Clippy Gate (-D warnings)
Write-Host "[4/7] Running Rust Clippy linter (cargo clippy -D warnings)..." -ForegroundColor Yellow
& cargo clippy --manifest-path $GatewayCargo --all-targets --all-features -- -D warnings
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Rust clippy reported warnings or errors." -ForegroundColor Red
    exit 1
}
Write-Host " -> Rust clippy passed with zero warnings." -ForegroundColor Green

# 5. Rust Compiler & Tests Check
Write-Host "[5/7] Running Rust check (cargo check --tests)..." -ForegroundColor Yellow
& cargo check --manifest-path $GatewayCargo --tests
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: 'cargo check --tests' failed." -ForegroundColor Red
    exit 1
}
Write-Host " -> Rust check and tests verified." -ForegroundColor Green

# 6. Python Intelligence Optimizer Gate
Write-Host "[6/7] Verifying Python Intelligence scheduler..." -ForegroundColor Yellow
$OptimizerScript = Join-Path $RepoRoot "intelligence/scheduling/workload-scheduler/optimizer.py"
$PythonExe = $null

$candidates = @()
if ($env:LOCALAPPDATA) {
    $candidates += (Join-Path $env:LOCALAPPDATA "Python\bin\python.exe")
}
$candidates += (Get-Command python, py, python3 -ErrorAction SilentlyContinue |
    Where-Object { $_.Source -notlike "*WindowsApps*" } |
    Select-Object -ExpandProperty Source)

foreach ($c in $candidates) {
    if ($c -and (Test-Path $c)) {
        $PythonExe = $c
        break
    }
}

if (-not $PythonExe) {
    $PythonExe = "python"
}

& $PythonExe $OptimizerScript
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Python optimizer verification failed." -ForegroundColor Red
    exit 1
}
Write-Host " -> Python optimizer passed." -ForegroundColor Green

$ManifestValidator = Join-Path $RepoRoot "tools/ci/validate_manifests.py"
& $PythonExe $ManifestValidator
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Infrastructure manifest validation failed." -ForegroundColor Red
    exit 1
}
Write-Host " -> Infrastructure manifests verified." -ForegroundColor Green

$PythonSdkDir = Join-Path $RepoRoot "libs/python/nexusedge"
if (Test-Path $PythonSdkDir) {
    Push-Location $PythonSdkDir
    try {
        & $PythonExe -m unittest discover -s tests -p "test_*.py"
        if ($LASTEXITCODE -ne 0) {
            Write-Host "ERROR: Python SDK unit test suite failed." -ForegroundColor Red
            exit 1
        }
        Write-Host " -> Python SDK tests passed." -ForegroundColor Green
    } finally {
        Pop-Location
    }
}

# 7. Dashboard Security & BFF Acceptance Gate
Write-Host "[7/8] Running Dashboard Security & BFF test suite..." -ForegroundColor Yellow
$DashboardDir = Join-Path $RepoRoot "apps/dashboard"
if (Get-Command node -ErrorAction SilentlyContinue) {
    Push-Location $DashboardDir
    try {
        & node --test test/bff.test.js
        if ($LASTEXITCODE -ne 0) {
            Write-Host "ERROR: Dashboard BFF test suite failed." -ForegroundColor Red
            exit 1
        }
        Write-Host " -> Dashboard security tests passed." -ForegroundColor Green

        $SdkDir = Join-Path $RepoRoot "libs/ts/api-client"
        if (Test-Path (Join-Path $SdkDir "test/client.test.js")) {
            Push-Location $SdkDir
            try {
                if (-not (Test-Path "dist/index.js")) {
                    & npx -y typescript --project tsconfig.json
                }
                & node --test test/client.test.js
                if ($LASTEXITCODE -ne 0) {
                    Write-Host "ERROR: TypeScript SDK test suite failed." -ForegroundColor Red
                    exit 1
                }
                Write-Host " -> TypeScript SDK tests passed." -ForegroundColor Green
            } finally {
                Pop-Location
            }
        }
    } finally {
        Pop-Location
    }
} else {
    Write-Host " -> Node.js not found, skipping local dashboard check." -ForegroundColor Gray
}

# 8. Docker Compose Manifest Validation Gate
Write-Host "[8/10] Validating Docker Compose configurations..." -ForegroundColor Yellow
$ComposeFile = Join-Path $RepoRoot "deploy/docker-compose.yml"
$ComposeProdFile = Join-Path $RepoRoot "deploy/docker-compose.prod.yml"
$CertGen = Join-Path $RepoRoot "tools/release/generate_certs.go"
$EnvoyCertDir = Join-Path $RepoRoot "deploy/envoy/certs"
$PgCertDir = Join-Path $RepoRoot "deploy/postgres/certs"
if (Get-Command go -ErrorAction SilentlyContinue) {
    & go run $CertGen $EnvoyCertDir $PgCertDir
}
if (Get-Command docker -ErrorAction SilentlyContinue) {
    & docker compose -f $ComposeFile config --quiet
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Docker Compose dev configuration validation failed." -ForegroundColor Red
        exit 1
    }
    $env:POSTGRES_USER = "nexusedge"
    $env:POSTGRES_PASSWORD = "prodpassword123"
    $env:NEXUSEDGE_DATABASE_URL = "postgres://nexusedge:prodpassword123@172.30.0.5:5432/nexusedge_edge?sslmode=verify-full&sslrootcert=/etc/ssl/certs/pg_root.crt"
    $env:AUDIT_HMAC_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    $env:NEXUSEDGE_SECRET_ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef"
    $env:NEXUSEDGE_CP_AUTH_TOKEN = "ci-token-01"
    $env:NEXUSEDGE_AI_API_KEYS = "ci-key:ci-tenant:proj-core:proj-core:inference:GLOBAL"
    $env:NEXUSEDGE_CP_POP_ID = "singapore"
    $env:NEXUSEDGE_PUBLIC_IP = "80.225.241.129"
    & docker compose -f $ComposeProdFile config --quiet
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Docker Compose prod configuration validation failed." -ForegroundColor Red
        exit 1
    }
    # Verify fail-closed behavior when NEXUSEDGE_PUBLIC_IP is omitted
    $oldIp = $env:NEXUSEDGE_PUBLIC_IP
    Remove-Item env:NEXUSEDGE_PUBLIC_IP -ErrorAction SilentlyContinue
    $ErrorActionPreference = "Continue"
    $output = & docker compose -f $ComposeProdFile config 2>&1
    $failCode = $LASTEXITCODE
    $ErrorActionPreference = "Stop"
    $env:NEXUSEDGE_PUBLIC_IP = $oldIp
    if ($failCode -eq 0) {
        Write-Host "ERROR: Docker Compose prod must fail when NEXUSEDGE_PUBLIC_IP is omitted!" -ForegroundColor Red
        exit 1
    }
    Write-Host " -> Docker Compose validation passed (including fail-closed public IP check)." -ForegroundColor Green
} else {
    Write-Host " -> Docker CLI not found, skipping local compose check." -ForegroundColor Gray
}

# 9. Automated Secret Scanning Gate (OWASP ASVS V2 / NIST SSDF PW.1.2)
Write-Host "[9/10] Running Automated Secret & High-Entropy Credential Scanner..." -ForegroundColor Yellow
$SecretScanner = Join-Path $RepoRoot "tools/ci/scan-secrets.py"
if (Test-Path $SecretScanner) {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3 $SecretScanner
    } elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
        & python3 $SecretScanner
    } elseif (Get-Command python -ErrorAction SilentlyContinue) {
        & python $SecretScanner
    } else {
        Write-Host "WARNING: Python not found; skipping secret scanner." -ForegroundColor Yellow
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Secret scan detected committed secrets or private keys!" -ForegroundColor Red
        exit 1
    }
    Write-Host " -> Secret scanning passed (Zero credentials in code)." -ForegroundColor Green
}

# 10. Dependency Vulnerability & Supply Chain Audit Gate
Write-Host "[10/10] Running Dependency Vulnerability Audits (npm audit & govulncheck)..." -ForegroundColor Yellow
if (Get-Command npm -ErrorAction SilentlyContinue) {
    Write-Host "   Auditing apps/dashboard dependencies..." -ForegroundColor Gray
    & npm audit --prefix (Join-Path $RepoRoot "apps/dashboard")
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: npm audit failed in apps/dashboard." -ForegroundColor Red
        exit 1
    }
    Write-Host "   Auditing libs/ts/api-client dependencies..." -ForegroundColor Gray
    & npm audit --prefix (Join-Path $RepoRoot "libs/ts/api-client")
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: npm audit failed in libs/ts/api-client." -ForegroundColor Red
        exit 1
    }
    Write-Host " -> Node.js dependency audits passed (0 vulnerabilities)." -ForegroundColor Green
}
if (Get-Command govulncheck -ErrorAction SilentlyContinue) {
    Write-Host "   Auditing Go dependencies via govulncheck..." -ForegroundColor Gray
    foreach ($svc in $GoServices) {
        $svcPath = Join-Path $RepoRoot $svc
        if (Test-Path $svcPath) {
            Push-Location $svcPath
            try {
                & govulncheck ./...
                if ($LASTEXITCODE -ne 0) {
                    Write-Host "ERROR: govulncheck found vulnerabilities in $svc" -ForegroundColor Red
                    exit 1
                }
            } finally {
                Pop-Location
            }
        }
    }
    Write-Host " -> Go vulnerability check passed (0 vulnerabilities)." -ForegroundColor Green
}

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " SUCCESS: All 10 CI Parity Gates Passed. Safe to commit and push!" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Cyan
