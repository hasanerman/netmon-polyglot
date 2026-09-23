param(
    [Parameter(Mandatory)] [string] $Exe,
    [Parameter(Mandatory)] [string] $Out,
    [string[]] $AppArgs = @(),
    [int] $WaitSeconds = 8
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class Win {
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
}
'@
$PW_RENDERFULLCONTENT = 2
[Win]::SetProcessDPIAware() | Out-Null

$proc = Start-Process -FilePath $Exe -ArgumentList $AppArgs -PassThru
try {
    Start-Sleep -Seconds $WaitSeconds
    $proc.Refresh()
    $handle = $proc.MainWindowHandle
    if ($handle -eq [IntPtr]::Zero) { throw 'window not found' }

    $r = New-Object Win+RECT
    [Win]::GetWindowRect($handle, [ref]$r) | Out-Null
    $bmp = New-Object System.Drawing.Bitmap ($r.Right - $r.Left), ($r.Bottom - $r.Top)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $hdc = $g.GetHdc()
    $ok = [Win]::PrintWindow($handle, $hdc, $PW_RENDERFULLCONTENT)
    $g.ReleaseHdc($hdc)
    $g.Dispose()
    if (-not $ok) { throw 'PrintWindow failed' }
    $bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    "saved $Out"
}
finally {
    if (-not $proc.HasExited) { $proc.CloseMainWindow() | Out-Null; Start-Sleep 1 }
    if (-not $proc.HasExited) { $proc.Kill() }
}
