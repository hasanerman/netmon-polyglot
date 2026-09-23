param(
    [string] $Demo = '',
    [int] $Port = 50051,
    [string] $Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$python = "$root\analytics-py\.venv\Scripts\python.exe"
$app = "$root\ui-cs\src\NetMonitor.App\bin\$Configuration\net10.0\NetMonitor.exe"

if (-not (Test-Path $app)) { throw "ui not built, run scripts\build_all.ps1 first ($app)" }

$env:PYTHONPATH = "$root\analytics-py\src"
$service = Start-Process -FilePath $python -ArgumentList '-m', 'analytics.server', '--port', $Port -PassThru -WindowStyle Hidden
Write-Output "analytics service started (pid $($service.Id), port $Port)"

try {
    $uiArgs = @('--analytics', "http://127.0.0.1:$Port")
    if ($Demo) { $uiArgs += @('--demo', $Demo) }
    Start-Process -FilePath $app -ArgumentList $uiArgs -Wait
}
finally {
    if (-not $service.HasExited) { Stop-Process -Id $service.Id -Force }
    Write-Output 'analytics service stopped'
}
