param([int] $Packets = 1000000)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$netmon = "$root\core-rs\target\release\netmon.exe"
$sniff = "$root\sniffer-c\build\sniff.exe"
$python = "$root\analytics-py\.venv\Scripts\python.exe"
$app = "$root\ui-cs\src\NetMonitor.App\bin\Release\net10.0\NetMonitor.exe"
$work = Join-Path $env:TEMP 'netmon-bench'
$mb = 1MB

New-Item -ItemType Directory -Force $work | Out-Null

function Invoke-Measured([string] $exe, [string[]] $arguments) {
    $out = Join-Path $work 'stdout.txt'
    $p = Start-Process -FilePath $exe -ArgumentList $arguments -PassThru -NoNewWindow -RedirectStandardOutput $out
    $peak = 0
    while (-not $p.HasExited) {
        try { $p.Refresh(); $peak = [Math]::Max($peak, $p.PeakWorkingSet64) } catch { }
        Start-Sleep -Milliseconds 20
    }
    [pscustomobject]@{ Output = (Get-Content $out -Raw); PeakMB = $peak / $mb; Exit = $p.ExitCode }
}

function Rate([string] $text) {
    if ($text -match '\((\d+) pkt/s') { [int64]$Matches[1] } else { 0 }
}

try {
    Write-Output "machine : $((Get-CimInstance Win32_Processor).Name.Trim()), $([Environment]::ProcessorCount) logical cpus"
    foreach ($s in 'mixed', 'portscan', 'flood') {
        & $netmon gen $s "$work\$s.pcap" --packets $Packets | Out-Null
    }

    $plain = Invoke-Measured $netmon @('replay', "$work\mixed.pcap", '--no-rules', '--top', '0')
    $rules = Invoke-Measured $netmon @('replay', "$work\mixed.pcap", '--top', '0')
    $scan = Invoke-Measured $netmon @('replay', "$work\portscan.pcap", '--top', '0')
    $flood = Invoke-Measured $netmon @('replay', "$work\flood.pcap", '--no-rules', '--top', '0')
    Write-Output ("rust parse, no rules   : {0:N0} pkt/s, peak {1:N1} MB" -f (Rate $plain.Output), $plain.PeakMB)
    Write-Output ("rust parse, 4 rules    : {0:N0} pkt/s, peak {1:N1} MB" -f (Rate $rules.Output), $rules.PeakMB)
    Write-Output ("rust portscan + rules  : {0:N0} pkt/s, alerts: {1}" -f (Rate $scan.Output), ([regex]::Match($scan.Output, '(\d+) alert').Groups[1].Value))
    Write-Output ("rust 100k flow table   : {0:N0} pkt/s, peak {1:N1} MB, {2}" -f (Rate $flood.Output), $flood.PeakMB, ([regex]::Match($flood.Output, 'flows\s+: .*').Value))

    $sw = [Diagnostics.Stopwatch]::StartNew()
    $c = Invoke-Measured $sniff @('replay', "$work\mixed.pcap")
    $sw.Stop()
    Write-Output ("c sniffer replay       : {0:N0} pkt/s, peak {1:N1} MB (process start included)" -f ($Packets / $sw.Elapsed.TotalSeconds), $c.PeakMB)

    Push-Location "$root\analytics-py"
    try { & $python scripts\bench_model.py } finally { Pop-Location }

    if (Test-Path $app) {
        $ui = Start-Process -FilePath $app -ArgumentList '--demo', 'portscan', '--no-analytics' -PassThru
        Start-Sleep -Seconds 15
        $ui.Refresh(); $early = $ui.WorkingSet64 / $mb
        Start-Sleep -Seconds 40
        $ui.Refresh(); $late = $ui.WorkingSet64 / $mb; $peak = $ui.PeakWorkingSet64 / $mb
        $ui.CloseMainWindow() | Out-Null
        if (-not $ui.WaitForExit(5000)) { $ui.Kill() }
        Write-Output ("c# ui demo             : working set {0:N0} MB at 15 s, {1:N0} MB at 55 s, peak {2:N0} MB" -f $early, $late, $peak)
    }

    $sizes = @{
        'netmon.exe' = "$root\core-rs\target\release\netmon.exe"
        'netcore.dll' = "$root\core-rs\target\release\netcore.dll"
        'sniff.exe' = $sniff
    }
    foreach ($k in $sizes.Keys | Sort-Object) {
        Write-Output ("size {0,-18}: {1:N0} KB" -f $k, ((Get-Item $sizes[$k]).Length / 1KB))
    }
}
finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
