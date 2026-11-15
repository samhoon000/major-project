<#
.SYNOPSIS
    Sentinel AI Network Intrusion Detection & Secure Chat - First-Time Setup Script
.DESCRIPTION
    Automates environment verification, virtual environment creation, pinned dependency
    installation, model artifact validation, configuration initialization, and Npcap driver checks.
    This script is completely idempotent: running it multiple times will not damage an existing environment.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  Sentinel AI Network IDS & Secure Chat - Automated Setup" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# 1. Enforce Verified Python Version (Python 3.13.2)
Write-Host "`n[1/6] Verifying Python installation..." -ForegroundColor Yellow
try {
    $pythonCmd = Get-Command python -ErrorAction Stop
    $pythonPath = $pythonCmd.Source

    $versionRaw = & python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to execute Python at '$pythonPath' (exit code: $LASTEXITCODE)."
        exit 1
    }

    $versionOutput = "$versionRaw".Trim()
    Write-Host "  Detected Python $versionOutput at $pythonPath" -ForegroundColor Green

    $supportedVersion = "3.13.2"
    if ($versionOutput -ne $supportedVersion) {
        Write-Error "Unsupported Python version: '$versionOutput'. The project dependencies and model artifacts are strictly verified on Python $supportedVersion. Please install Python 3.13.2 from https://www.python.org/downloads/release/python-3132/."
        exit 1
    }
    Write-Host "  [OK] Python version $versionOutput matches verified project standard." -ForegroundColor Green
} catch {
    Write-Error "Python verification failed: $($_.Exception.Message). Please ensure Python 3.13.2 is installed."
    exit 1
}

# 2. Virtual Environment Management (Isolated, Idempotent)
Write-Host "`n[2/6] Checking virtual environment..." -ForegroundColor Yellow
$venvDir = Join-Path $PSScriptRoot "venv"
$venvPython = Join-Path $venvDir "Scripts\python.exe"

if (Test-Path $venvPython) {
    Write-Host "  [OK] Virtual environment 'venv' already exists at $venvDir." -ForegroundColor Green
} else {
    Write-Host "  Creating isolated virtual environment 'venv'..." -ForegroundColor Cyan
    & python -m venv $venvDir
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $venvPython)) {
        Write-Error "Failed to create virtual environment at $venvDir (exit code: $LASTEXITCODE)."
        exit 1
    }
    Write-Host "  [OK] Isolated virtual environment created successfully." -ForegroundColor Green
}

# 3. Comprehensive Pinned Dependency Verification & Installation
Write-Host "`n[3/6] Verifying and installing dependencies..." -ForegroundColor Yellow
$reqFile = Join-Path $PSScriptRoot "requirements.txt"
if (-not (Test-Path $reqFile)) {
    Write-Error "requirements.txt not found at $reqFile."
    exit 1
}

$verifyScript = @"
import sys, importlib.metadata

req_file = 'requirements.txt'
mismatches = []
total = 0
with open(req_file, 'r', encoding='utf-8') as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith('#') or '==' not in line:
            continue
        total += 1
        pkg, pinned_ver = line.split('==', 1)
        pkg, pinned_ver = pkg.strip(), pinned_ver.strip()
        try:
            installed = importlib.metadata.version(pkg)
            if installed != pinned_ver:
                mismatches.append(f'{pkg}: expected {pinned_ver}, installed {installed}')
        except importlib.metadata.PackageNotFoundError:
            mismatches.append(f'{pkg}: missing (expected {pinned_ver})')

if mismatches:
    print('MISMATCH_COUNT:' + str(len(mismatches)))
    for m in mismatches:
        print('  [MISMATCH] ' + m)
    sys.exit(1)
else:
    print(f'ALL_VERIFIED_COUNT:{total}')
    sys.exit(0)
"@

Write-Host "  Verifying every pinned dependency against requirements.txt..." -ForegroundColor Cyan
$verifyOutput = & $venvPython -c $verifyScript 2>$null
$verifyExit = $LASTEXITCODE

if ($verifyExit -eq 0 -and ($verifyOutput -like "*ALL_VERIFIED_COUNT:*")) {
    Write-Host "  [OK] All pinned dependencies match exact versions in the environment." -ForegroundColor Green
} else {
    Write-Host "  Missing or mismatched dependencies detected:" -ForegroundColor Yellow
    $verifyOutput | ForEach-Object { if ($_ -match "\[MISMATCH\]") { Write-Host "  $_" -ForegroundColor Yellow } }
    
    Write-Host "  Installing pinned packages from requirements.txt..." -ForegroundColor Cyan
    & $venvPython -m pip install -r $reqFile --no-warn-script-location
    if ($LASTEXITCODE -ne 0) {
        Write-Error "pip installation failed with exit code $LASTEXITCODE. Cannot continue setup."
        exit 1
    }

    # Re-verify every pinned version again after installation
    Write-Host "  Re-verifying dependencies after installation..." -ForegroundColor Cyan
    $postVerifyOutput = & $venvPython -c $verifyScript 2>$null
    if ($LASTEXITCODE -ne 0 -or -not ($postVerifyOutput -like "*ALL_VERIFIED_COUNT:*")) {
        Write-Error "Dependency verification failed after installation. Mismatched packages remaining."
        exit 1
    }
    Write-Host "  [OK] All dependencies successfully verified after installation." -ForegroundColor Green
}

# 4. Model Artifacts Validation
Write-Host "`n[4/6] Validating GATv2 model artifacts..." -ForegroundColor Yellow
$modelsDir = Join-Path $PSScriptRoot "models"
$requiredArtifacts = @(
    "gatv2_model.pth",
    "node_scaler.pkl",
    "edge_scaler.pkl",
    "model_config.json",
    "feature_config.json"
)

$missingArtifacts = @()
foreach ($artifact in $requiredArtifacts) {
    $artPath = Join-Path $modelsDir $artifact
    if (Test-Path $artPath) {
        $fileSize = (Get-Item $artPath).Length
        Write-Host "  - $artifact ($fileSize bytes): Valid" -ForegroundColor Gray
    } else {
        $missingArtifacts += $artifact
    }
}

if ($missingArtifacts.Count -gt 0) {
    Write-Error "Missing required model artifacts in '$modelsDir': $($missingArtifacts -join ', ')"
    exit 1
}
Write-Host "  [OK] All 5 required GATv2 model artifacts validated." -ForegroundColor Green

# 5. Configuration Initialization (.env)
Write-Host "`n[5/6] Checking configuration (.env)..." -ForegroundColor Yellow
$envFile = Join-Path $PSScriptRoot ".env"
$envExample = Join-Path $PSScriptRoot ".env.example"

if (Test-Path $envFile) {
    Write-Host "  [OK] Existing configuration '.env' detected. Preserving existing settings." -ForegroundColor Green
} else {
    if (-not (Test-Path $envExample)) {
        Write-Error ".env.example not found at $envExample."
        exit 1
    }
    Write-Host "  Creating '.env' from '.env.example'..." -ForegroundColor Cyan
    $envContent = Get-Content $envExample -Raw

    # Generate cryptographically secure random token (32 bytes / 64 hex chars)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] 32
    $rng.GetBytes($bytes)
    $secureAdminToken = -join ($bytes | ForEach-Object { "{0:x2}" -f $_ })

    $envContent = $envContent -replace "ADMIN_TOKEN=", "ADMIN_TOKEN=$secureAdminToken"
    Set-Content -Path $envFile -Value $envContent -Encoding UTF8
    Write-Host "  [OK] Created '.env' with a newly generated secure ADMIN_TOKEN." -ForegroundColor Green
}

# 6. Npcap Driver Validation
Write-Host "`n[6/6] Checking packet capture prerequisites (Npcap)..." -ForegroundColor Yellow
$npcapInstalled = (Test-Path "C:\Windows\System32\Npcap\wpcap.dll") -or (Test-Path "C:\Windows\System32\wpcap.dll")

if ($npcapInstalled) {
    Write-Host "  [OK] Npcap packet capture driver detected." -ForegroundColor Green
} else {
    Write-Host "  ------------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host "  [NOTICE] Npcap was not found on this Windows system." -ForegroundColor Yellow
    Write-Host "  The Secure Chat and Threat Engine will run completely without Npcap." -ForegroundColor Yellow
    Write-Host "  However, live raw network packet capture requires Npcap." -ForegroundColor Yellow
    Write-Host "  To enable live network capture:" -ForegroundColor Yellow
    Write-Host "    1. Download Npcap from: https://npcap.com/#download" -ForegroundColor Yellow
    Write-Host "    2. During installation, ensure you check:" -ForegroundColor Yellow
    Write-Host "       [x] 'Install Npcap in WinPcap API-compatible Mode'" -ForegroundColor Yellow
    Write-Host "       [x] 'Support raw 802.11 traffic'" -ForegroundColor Yellow
    Write-Host "       [ ] Uncheck 'Restrict Npcap driver's access to Administrators only' (or run terminal as Admin)" -ForegroundColor Yellow
    Write-Host "  ------------------------------------------------------------------" -ForegroundColor Yellow
}

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "  [SUCCESS] Sentinel setup complete and verified!" -ForegroundColor Green
Write-Host "  Run .\start.ps1 to launch the integrated application." -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
