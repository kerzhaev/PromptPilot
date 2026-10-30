# Start PromptPilot services (worker + server + optional bot and flows)
# Usage:
#   .\start.ps1           - worker + server
#   .\start.ps1 -Bot      - worker + server + bot (requires PP_TG_TOKEN)
# The flows runner (pp flows run) starts by itself when flow files exist
# (~\.promptpilot\flows\*.json or PP_FLOWS_DIR, see docs\FLOWS.md).

param(
    [switch]$Bot
)

$ErrorActionPreference = "Stop"
$pidFile = "$PSScriptRoot\.pp-pids.json"
$logDir  = "$PSScriptRoot\logs"

# P2-9: PP_DATA_DIR проверяется ДО старта процессов. Раньше молчаливый
# пропуск/кривой путь включал сервер с пустой базой — миссии «исчезали»
# (404) уже после успешного старта.
if ($env:PP_DATA_DIR) {
    if (-not (Test-Path -LiteralPath $env:PP_DATA_DIR -PathType Container)) {
        Write-Host "PP_DATA_DIR='$env:PP_DATA_DIR' does not exist." -ForegroundColor Red
        Write-Host "Create the directory or fix the variable before start; an empty DB turns missions into 404." -ForegroundColor Red
        exit 1
    }
    Write-Host "PP_DATA_DIR: $env:PP_DATA_DIR" -ForegroundColor DarkGray
}

# Load .env if present (same logic as config.py)
$envFile = "$PSScriptRoot\.env"
if (Test-Path -LiteralPath $envFile -PathType Leaf) {
    Get-Content -LiteralPath $envFile -Encoding UTF8 | ForEach-Object {
        if ($_ -match '^\s*([^#][^=]*?)\s*=\s*"?([^"]*)"?\s*$') {
            $k = $Matches[1].Trim(); $v = $Matches[2].Trim()
            if ($k -and -not (Test-Path "env:$k")) {
                Set-Item -Path "env:$k" -Value $v
            }
        }
    }
    Write-Host "Loaded .env" -ForegroundColor DarkGray
}

# Check if already running
if (Test-Path $pidFile) {
    $old = Get-Content $pidFile | ConvertFrom-Json
    $alive = $old.PSObject.Properties | Where-Object {
        # A watcher may survive a crashed core process.  It is discovered by
        # command line in stop.ps1, but must not make a fresh core start look
        # healthy or block recovery from a stale PID file.
        if ($_.Name -eq 'verdict_watcher') { return $false }
        # pid=0 means "not launched" (long-dead Telegram bot); Get-Process -Id 0
        # succeeds on the System Idle process and made a fully dead stack look
        # "already running" (incident 07.10: start-all refused to revive it).
        if (-not $_.Value -or [int]$_.Value -le 0) { return $false }
        try { Get-Process -Id $_.Value -ErrorAction Stop; $true } catch { $false }
    }
    if ($alive) {
        Write-Host "PromptPilot is already running. Use .\stop.ps1 first." -ForegroundColor Yellow
        exit 1
    }
    Remove-Item $pidFile
}

# Pick executable: prefer built dist, then the repository venv, then PATH.
if (Test-Path "$PSScriptRoot\dist\pp.exe") {
    $exe = "$PSScriptRoot\dist\pp.exe"
    Write-Host "Using: dist\pp.exe" -ForegroundColor DarkGray
} elseif (Test-Path "$PSScriptRoot\.venv\Scripts\pp.exe") {
    $exe = "$PSScriptRoot\.venv\Scripts\pp.exe"
    Write-Host "Using: .venv\Scripts\pp.exe" -ForegroundColor DarkGray
} else {
    $exe = "pp"
    Write-Host "Using: pp (from PATH)" -ForegroundColor DarkGray
}

New-Item -ItemType Directory -Force -Path $logDir | Out-Null

Write-Host "Starting PromptPilot..." -ForegroundColor Cyan

$w = Start-Process $exe -ArgumentList "worker" `
    -RedirectStandardOutput "$logDir\worker.log" `
    -RedirectStandardError  "$logDir\worker.err" `
    -WindowStyle Hidden -PassThru

$s = Start-Process $exe -ArgumentList "server" `
    -RedirectStandardOutput "$logDir\server.log" `
    -RedirectStandardError  "$logDir\server.err" `
    -WindowStyle Hidden -PassThru

$pids = [ordered]@{ worker = $w.Id; server = $s.Id }

Write-Host "  Worker  PID $($w.Id)   logs\worker.log" -ForegroundColor Green
Write-Host "  Server  PID $($s.Id)   http://127.0.0.1:8420" -ForegroundColor Green

if ($Bot -or $env:PP_TG_TOKEN) {
    if (-not $env:PP_TG_TOKEN) {
        Write-Host "PP_TG_TOKEN is not set, skipping bot." -ForegroundColor Yellow
    } else {
        $b = Start-Process $exe -ArgumentList "bot" `
        -RedirectStandardOutput "$logDir\bot.log" `
        -RedirectStandardError  "$logDir\bot.err" `
        -WindowStyle Hidden -PassThru
        $pids.bot = $b.Id
        Write-Host "  Bot     PID $($b.Id)   logs\bot.log" -ForegroundColor Green
    }
}


# Локальные надстройки развёртывания (не из upstream): контроллер ревью-цепочки
# и наблюдатель вердиктов. Тот же venv, что и основной стек, — зависимости
# promptpilot резолвятся из этого checkout.
function Test-PromptPilotCommandLine([string]$Pattern) {
    [bool](Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" |
        Where-Object { $_.CommandLine -match $Pattern })
}

$addonPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $addonPython)) { $addonPython = "python" }

$cascade = Start-Process $addonPython -ArgumentList @('-X', 'utf8', "$PSScriptRoot\cascade-review.py") `
    -WorkingDirectory $PSScriptRoot -RedirectStandardOutput "$logDir\cascade-review.log" `
    -RedirectStandardError "$logDir\cascade-review.err" -WindowStyle Hidden -PassThru
$pids.cascade = $cascade.Id
Write-Host "  Cascade PID $($cascade.Id)   logs\cascade-review.log" -ForegroundColor Green

if (Test-PromptPilotCommandLine 'verdict-repair-watcher\.py') {
    Write-Host "  Verdict watcher already running" -ForegroundColor DarkGray
} else {
    $watcher = Start-Process $addonPython.replace('python.exe','pythonw.exe') -ArgumentList @('-X', 'utf8', "$PSScriptRooterdict-repair-watcher.py") `
        -WorkingDirectory $PSScriptRoot -RedirectStandardOutput "$logDirerdict-repair-watcher.stdout.log" `
        -RedirectStandardError "$logDirerdict-repair-watcher.stderr.log" -WindowStyle Hidden -PassThru
    $pids.verdict_watcher = $watcher.Id
    Write-Host "  Verdict watcher PID $($watcher.Id)   logserdict-repair-watcher.stdout.log" -ForegroundColor Green
}

# Flows runner: only when there are flows to run.
if ($env:PP_FLOWS_DIR) {
    $flowsDir = $env:PP_FLOWS_DIR
} elseif ($env:PP_DATA_DIR) {
    $flowsDir = Join-Path $env:PP_DATA_DIR "flows"
} else {
    $flowsDir = Join-Path $HOME ".promptpilot\flows"
}
if (Test-Path -Path (Join-Path $flowsDir "*.json")) {
    $f = Start-Process $exe -ArgumentList "flows", "run" `
        -RedirectStandardOutput "$logDir\flows.log" `
        -RedirectStandardError  "$logDir\flows.err" `
        -WindowStyle Hidden -PassThru
    $pids.flows = $f.Id
    Write-Host "  Flows   PID $($f.Id)   logs\flows.log" -ForegroundColor Green
}

# ASCII: без BOM — PowerShell-UTF8 пишет BOM и ломает json-читателей
$pids | ConvertTo-Json | Set-Content -LiteralPath $pidFile -Encoding Ascii

Write-Host "`nAll logs in .\logs\   Stop with: .\stop.ps1" -ForegroundColor DarkGray
