param(
    [string]$BaseDir = (Get-Location).Path
)

$ErrorActionPreference = "Stop"

$required = @(
    "messenger.db",
    "uploads",
    ".secret_key",
    ".security_salt",
    ".master_key",
    "config.py"
)

$missing = @()
foreach ($item in $required) {
    $path = Join-Path $BaseDir $item
    if (-not (Test-Path $path)) {
        $missing += $item
    }
}

if ($missing.Count -gt 0) {
    Write-Host "Backup requirement check failed."
    Write-Host "Missing:"
    $missing | ForEach-Object { Write-Host " - $_" }
    exit 1
}

Write-Host "Backup requirement check passed."
exit 0

