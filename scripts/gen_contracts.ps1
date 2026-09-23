$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

Write-Output 'regenerating contracts/core_ffi.h (cbindgen via build.rs)'
cargo build --manifest-path "$root\core-rs\Cargo.toml" -p netcore-ffi
if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }

Write-Output 'regenerating python grpc stubs from contracts/analytics.proto'
& "$root\analytics-py\.venv\Scripts\python.exe" "$root\analytics-py\scripts\gen_proto.py"
if ($LASTEXITCODE -ne 0) { throw 'gen_proto failed' }

git -C $root diff --stat -- contracts
