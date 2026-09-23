@echo off
setlocal enabledelayedexpansion

set "ROOT=%~dp0"
set "OUT=%ROOT%build"
set "CFLAGS=/nologo /std:c17 /W4 /WX /O2 /MD /D_CRT_SECURE_NO_WARNINGS /I"%ROOT%include""
set "SOURCES="%ROOT%src\sniffer.c" "%ROOT%src\capture_loop.c" "%ROOT%src\pcap_replay.c" "%ROOT%src\device.c" "%ROOT%src\win_npcap.c""

if /i "%~1"=="asan" (
  set "CFLAGS=/nologo /std:c17 /W4 /WX /Od /Zi /MD /fsanitize=address /D_CRT_SECURE_NO_WARNINGS /I"%ROOT%include""
  set "OUT=%ROOT%build\asan"
)

set "VSWHERE=C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"

where cl >nul 2>nul
if errorlevel 1 (
  if not exist "!VSWHERE!" (
    echo MSVC bulunamadi. Developer Command Prompt icinden calistir.
    exit /b 1
  )
  for /f "usebackq tokens=*" %%i in (`"!VSWHERE!" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
  if not defined VSPATH (
    echo MSVC araclari kurulu degil.
    exit /b 1
  )
  call "!VSPATH!\VC\Auxiliary\Build\vcvars64.bat" >nul
)

if not exist "%OUT%\obj" mkdir "%OUT%\obj"
set "CFLAGS=%CFLAGS% /Fd:"%OUT%\\""

cl %CFLAGS% /c /Fo:"%OUT%\obj\\" %SOURCES%
if errorlevel 1 exit /b 1

lib /nologo /OUT:"%OUT%\sniffer.lib" "%OUT%\obj\*.obj"
if errorlevel 1 exit /b 1

cl %CFLAGS% /Fe:"%OUT%\sniff.exe" /Fo:"%OUT%\\" "%ROOT%tools\sniff.c" "%OUT%\sniffer.lib"
if errorlevel 1 exit /b 1

cl %CFLAGS% /Fe:"%OUT%\test_replay.exe" /Fo:"%OUT%\\" "%ROOT%tests\test_replay.c" "%OUT%\sniffer.lib"
if errorlevel 1 exit /b 1

cl %CFLAGS% /Fe:"%OUT%\test_device.exe" /Fo:"%OUT%\\" "%ROOT%tests\test_device.c" "%OUT%\sniffer.lib"
if errorlevel 1 exit /b 1

echo build ok: %OUT%
