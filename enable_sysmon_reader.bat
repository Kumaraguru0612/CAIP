@echo off
echo ======================================================================
echo Granting Read Permission on Sysmon Event Log for Local Users...
echo ======================================================================
wevtutil sl "Microsoft-Windows-Sysmon/Operational" "/ca:O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;BO)(A;;0x1;;;SO)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;AU)"
if %errorlevel% equ 0 (
    echo.
    echo [SUCCESS] Permission granted! Standard processes can now read Sysmon directly.
) else (
    echo.
    echo [ERROR] Access denied. Please right-click this file and choose "Run as administrator".
)
echo.
pause

