<#
.SYNOPSIS
    Sentinel AI Network Intrusion Detection & Secure Chat - Application Launcher
.DESCRIPTION
    Verifies environment readiness, displays runtime configuration (LAN URL, Cloudflare Tunnel state),
    and starts the unified FastAPI application via Uvicorn.
#>

[CmdletBinding()]
param(
    [string]$HostBinding = "0.0.0.0",
    [int]$Port = 0
)

$ErrorActionPreference = "Continue"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  Sentinel AI Network IDS & Secure Chat - Application Launcher" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# 1. Check Virtual Environment
$venvPython = Join-Path $PSScriptRoot "venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Error "Virtual environment not found at '$venvPython'. Please run .\setup.ps1 first."
    exit 1
}

# 2. Check Configuration (.env)
$envFile = Join-Path $PSScriptRoot ".env"
if (-not (Test-Path $envFile)) {
    Write-Warning "No '.env' configuration found. Creating default from '.env.example'..."
    Copy-Item (Join-Path $PSScriptRoot ".env.example") $envFile
}

# 3. Read configured port if not explicitly passed
if ($Port -eq 0) {
    $Port = 8001
    if (Test-Path $envFile) {
        Get-Content $envFile | ForEach-Object {
            if ($_ -match "^\s*PORT\s*=\s*(\d+)") {
                $Port = [int]$matches[1]
            }
        }
    }
}
$env:PORT = "$Port"

# 4. Display Network & Connectivity Summary
Write-Host "`nDetecting active network configuration..." -ForegroundColor Yellow
$detectScript = @"
import os
from backend.network.adapter_detector import select_network_adapter
from backend.network.tunnel import tunnel_manager

adapter = select_network_adapter()
if adapter:
    print(f'ADAPTER_NAME:{adapter.adapter.name}')
    print(f'ADAPTER_IP:{adapter.local_ip}')
    print(f'ADAPTER_TYPE:{adapter.adapter_type}')
else:
    print('ADAPTER_NAME:None')
    print('ADAPTER_IP:127.0.0.1')
    print('ADAPTER_TYPE:Loopback')

print(f'TUNNEL_STATUS:{tunnel_manager.status}')
print(f'PUBLIC_HOSTNAME:{tunnel_manager.public_hostname or \"None\"}')
print(f'PUBLIC_READY:{tunnel_manager.is_public_ready}')
"@

$info = & $venvPython -c $detectScript 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Adapter detection returned non-zero exit code ($LASTEXITCODE)."
    Write-Warning ($info -join "`n")
}

$adapterName = "Automatic"
$adapterIp = "127.0.0.1"
$adapterType = "Network"
$tunnelStatus = "disabled"
$publicHost = "None"

if ($info) {
    $info | ForEach-Object {
        $line = $_.ToString()
        if ($line -match "^ADAPTER_NAME:(.*)") { $adapterName = $matches[1] }
        if ($line -match "^ADAPTER_IP:(.*)") { $adapterIp = $matches[1] }
        if ($line -match "^ADAPTER_TYPE:(.*)") { $adapterType = $matches[1] }
        if ($line -match "^TUNNEL_STATUS:(.*)") { $tunnelStatus = $matches[1] }
        if ($line -match "^PUBLIC_HOSTNAME:(.*)") { $publicHost = $matches[1] }
    }
}

Write-Host "  Active Adapter  : $adapterName [$adapterType]" -ForegroundColor Green
Write-Host "  Local LAN IP    : $adapterIp" -ForegroundColor Green
Write-Host "  Local LAN URL   : http://${adapterIp}:${Port}/chat" -ForegroundColor Cyan
Write-Host "  SOC Dashboard   : http://${adapterIp}:${Port}/dashboard" -ForegroundColor Cyan
if ($publicHost -ne "None" -and $publicHost) {
    Write-Host "  Cloudflare Host : https://${publicHost}/chat ($tunnelStatus)" -ForegroundColor Magenta
} else {
    Write-Host "  Cloudflare Host : Disabled (LAN mode active)" -ForegroundColor Gray
}
Write-Host "  Firewall Notice : If other LAN devices cannot connect, allow port ${Port} in Admin PowerShell:" -ForegroundColor DarkYellow
Write-Host "                    New-NetFirewallRule -DisplayName 'Sentinel AI LAN Server (TCP ${Port})' -Direction Inbound -LocalPort ${Port} -Protocol TCP -Action Allow -Profile Public,Private -RemoteAddress LocalSubnet" -ForegroundColor Gray

Write-Host "`nStarting Sentinel server on ${HostBinding}:${Port}..." -ForegroundColor Yellow
Write-Host "Press Ctrl+C to stop.`n" -ForegroundColor Gray

& $venvPython -m uvicorn app:app --host $HostBinding --port $Port --no-proxy-headers
if ($LASTEXITCODE -ne 0) {
    Write-Error "Sentinel server stopped with exit code $LASTEXITCODE."
    exit $LASTEXITCODE
}

