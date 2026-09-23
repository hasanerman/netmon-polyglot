param([switch] $SkipTests)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

function Step([string] $name, [scriptblock] $action) {
    Write-Output "== $name"
    # powershell 5.1 stderr satirlarini hata sayiyor, basariyi exit code belirliyor
    $ErrorActionPreference = 'Continue'
    & $action 2>&1 | ForEach-Object { "$_" }
    $ErrorActionPreference = 'Stop'
    if ($LASTEXITCODE -ne 0) { throw "$name failed with exit code $LASTEXITCODE" }
}

Step 'c sniffer' { cmd /c "`"$root\sniffer-c\build.bat`"" }
Step 'rust core' { cargo build --release --manifest-path "$root\core-rs\Cargo.toml" }

$venv = "$root\analytics-py\.venv"
if (-not (Test-Path "$venv\Scripts\python.exe")) {
    Step 'python venv' { python -m venv $venv }
}
Step 'python deps' { & "$venv\Scripts\python.exe" -m pip install -q -e "$root\analytics-py[dev]" }
Step 'python stubs' { & "$venv\Scripts\python.exe" "$root\analytics-py\scripts\gen_proto.py" }
Step 'c# ui' { dotnet build "$root\ui-cs\NetMonitor.slnx" -c Release }

if ($SkipTests) { return }

Push-Location "$root\sniffer-c"
try {
    Step 'c tests' { .\build\test_replay.exe; if ($LASTEXITCODE -eq 0) { .\build\test_device.exe } }
}
finally { Pop-Location }
Step 'rust clippy' { cargo clippy --manifest-path "$root\core-rs\Cargo.toml" --all-targets -- -D warnings }
Step 'rust tests' { cargo test --manifest-path "$root\core-rs\Cargo.toml" }
Step 'c# tests' { dotnet test "$root\ui-cs\NetMonitor.slnx" -c Release --no-build }
Push-Location "$root\analytics-py"
try {
    Step 'python lint' { & "$venv\Scripts\python.exe" -m ruff check src tests scripts }
    Step 'python types' { & "$venv\Scripts\python.exe" -m mypy src }
    Step 'python tests' { & "$venv\Scripts\python.exe" -m pytest -q }
}
finally { Pop-Location }
Write-Output 'all components built and tested'
