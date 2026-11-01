<#
.SYNOPSIS
    Autonomous NIDS — Native PowerShell Launcher (run.ps1)
.DESCRIPTION
    Verifies Windows Administrator privileges (required by Npcap/Scapy Layer-2/3 capture)
    and launches the unified NIDS process supervisor (run.py) inside the project .venv.
#>

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

$VenvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$OrchestratorScript = Join-Path $PSScriptRoot "run.py"

if (-not (Test-Path $VenvPython)) {
    Write-Host "[!] Virtual environment Python not found at: $VenvPython" -ForegroundColor Red
    exit 1
}

# Verify Administrator elevation required for raw packet sniffing
$CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$IsAdmin = $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host "[!] Administrator privileges are required for Npcap packet capture." -ForegroundColor Yellow
    Write-Host "[*] Requesting UAC Administrator elevation..." -ForegroundColor Cyan
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit 0
}

Write-Host "[*] Starting Autonomous NIDS Unified Orchestrator..." -ForegroundColor Cyan
& $VenvPython $OrchestratorScript
