param(
    [string]$BaseDir = (Get-Location).Path,
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $OutputPath = Join-Path $BaseDir "DR_REHEARSAL_$stamp.md"
}

$verifyScript = Join-Path $BaseDir "scripts\verify_backup_requirements.ps1"
if (-not (Test-Path $verifyScript)) {
    Write-Host "verify_backup_requirements.ps1 not found."
    exit 1
}

$verifyOk = $true
try {
    & $verifyScript -BaseDir $BaseDir
    if ($LASTEXITCODE -ne 0) { $verifyOk = $false }
} catch {
    $verifyOk = $false
}

$now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$status = if ($verifyOk) { "PASS" } else { "FAIL" }

$content = @"
# DR Rehearsal Report

- Executed at: $now
- Base directory: $BaseDir
- Backup requirement check: $status

## Checklist

1. Backup files existence verified (`scripts/verify_backup_requirements.ps1`)
2. `.master_key` presence checked
3. Restore runbook review required before production recovery

"@

Set-Content -Path $OutputPath -Value $content -Encoding UTF8

if (-not $verifyOk) {
    Write-Host "DR rehearsal failed. See: $OutputPath"
    exit 1
}

Write-Host "DR rehearsal passed. Report: $OutputPath"
exit 0

