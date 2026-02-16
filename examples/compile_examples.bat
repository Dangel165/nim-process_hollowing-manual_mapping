@echo off
chcp 65001 >nul
echo ========================================
echo   Compiling Example Payloads
echo ========================================
echo.

REM Check if GCC is installed
where gcc >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: GCC is not installed or not in PATH
    echo.
    echo Please install MinGW-w64 from:
    echo https://www.mingw-w64.org/downloads/
    echo.
    echo Or install via MSYS2:
    echo https://www.msys2.org/
    echo.
    pause
    exit /b 1
)

echo GCC found:
gcc --version | findstr "gcc"
echo.

REM Compile test payload (EXE)
echo ========================================
echo Compiling test_payload.exe...
echo ========================================
gcc test_payload.c -o test_payload.exe -mwindows -s -O2

if %ERRORLEVEL% EQU 0 (
    echo ✓ test_payload.exe compiled successfully!
    echo   Size: 
    dir test_payload.exe | findstr "test_payload.exe"
) else (
    echo ✗ test_payload.exe compilation failed!
)
echo.

REM Compile test DLL
echo ========================================
echo Compiling test_dll.dll...
echo ========================================
gcc test_dll.c -shared -o test_dll.dll -mwindows -s -O2

if %ERRORLEVEL% EQU 0 (
    echo ✓ test_dll.dll compiled successfully!
    echo   Size:
    dir test_dll.dll | findstr "test_dll.dll"
) else (
    echo ✗ test_dll.dll compilation failed!
)
echo.

echo ========================================
echo Compilation Complete!
echo ========================================
echo.
echo Files created:
if exist test_payload.exe (
    echo   ✓ test_payload.exe - Use with Process Hollowing
)
if exist test_dll.dll (
    echo   ✓ test_dll.dll - Use with Manual Mapping
)
echo.
echo Usage:
echo   1. Process Hollowing: Use test_payload.exe as payload
echo   2. Manual Mapping: Use test_dll.dll as DLL to inject
echo.

pause
