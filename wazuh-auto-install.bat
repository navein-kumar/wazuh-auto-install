@echo off
REM =============================================================================
REM Windows Threat Hunting Enhancement Script - Batch Version
REM Works on ANY Windows system without PowerShell version issues
REM =============================================================================

echo.
echo ========================================
echo Windows Threat Hunting Setup v5.0
echo ========================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Error: Administrator privileges required!
    echo Please run this script as Administrator.
    echo.
    pause
    exit /b 1
)

echo [OK] Running with administrator privileges
echo.

REM Set variables
set TEMP_DIR=C:\Windows\Temp\ThreatHuntingSetup
set SCRIPTS_DIR=C:\Scripts
set LOGS_DIR=C:\logs\netstat
set TRANSCRIPTS_DIR=C:\Windows\Temp\PSTranscripts

REM URLs for downloads
set SYSMON_URL=https://download.sysinternals.com/files/Sysmon.zip
set SYSMON_CONFIG_URL=https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml
set NSSM_URL=https://raw.githubusercontent.com/navein-kumar/wazuh-Netstat-Powershell/main/nssm.exe
set NETSTAT_SCRIPT_URL=https://raw.githubusercontent.com/navein-kumar/wazuh-Netstat-Powershell/main/netstat-service.ps1

echo Creating directories...
if not exist "%TEMP_DIR%" mkdir "%TEMP_DIR%"
if not exist "%SCRIPTS_DIR%" mkdir "%SCRIPTS_DIR%"
if not exist "%LOGS_DIR%" mkdir "%LOGS_DIR%"
if not exist "%TRANSCRIPTS_DIR%" mkdir "%TRANSCRIPTS_DIR%"
echo [OK] Directories created

echo.
echo ========================================
echo Installing Sysmon
echo ========================================

REM Check if Sysmon is already installed and remove it
sc query Sysmon64 >nul 2>&1
if %errorLevel% equ 0 (
    echo Removing existing Sysmon64...
    sysmon64 -u >nul 2>&1
    timeout /t 3 /nobreak >nul
)

sc query Sysmon >nul 2>&1
if %errorLevel% equ 0 (
    echo Removing existing Sysmon...
    sysmon -u >nul 2>&1
    timeout /t 3 /nobreak >nul
)

echo Downloading Sysmon...
powershell -Command "try { Invoke-WebRequest -Uri '%SYSMON_URL%' -OutFile '%TEMP_DIR%\Sysmon.zip' -UseBasicParsing; echo '[OK] Sysmon downloaded' } catch { echo '[ERROR] Failed to download Sysmon'; exit 1 }"
if %errorLevel% neq 0 goto :sysmon_error

echo Downloading Sysmon configuration...
powershell -Command "try { Invoke-WebRequest -Uri '%SYSMON_CONFIG_URL%' -OutFile '%TEMP_DIR%\sysmonconfig.xml' -UseBasicParsing; echo '[OK] Configuration downloaded' } catch { echo '[ERROR] Failed to download config'; exit 1 }"
if %errorLevel% neq 0 goto :sysmon_error

echo Extracting Sysmon...
powershell -Command "try { Expand-Archive -Path '%TEMP_DIR%\Sysmon.zip' -DestinationPath '%TEMP_DIR%\Sysmon' -Force; echo '[OK] Sysmon extracted' } catch { echo '[ERROR] Failed to extract'; exit 1 }"
if %errorLevel% neq 0 goto :sysmon_error

REM Find and install Sysmon
if exist "%TEMP_DIR%\Sysmon\Sysmon64.exe" (
    echo Installing Sysmon64...
    "%TEMP_DIR%\Sysmon\Sysmon64.exe" -accepteula -i "%TEMP_DIR%\sysmonconfig.xml"
    if %errorLevel% equ 0 (
        echo [OK] Sysmon64 installed successfully
        timeout /t 5 /nobreak >nul
        sc query Sysmon64 | find "RUNNING" >nul
        if %errorLevel% equ 0 (
            echo [OK] Sysmon64 service is running
        ) else (
            echo [WARNING] Sysmon64 service not running
        )
    ) else (
        echo [ERROR] Sysmon64 installation failed
    )
) else if exist "%TEMP_DIR%\Sysmon\Sysmon.exe" (
    echo Installing Sysmon...
    "%TEMP_DIR%\Sysmon\Sysmon.exe" -accepteula -i "%TEMP_DIR%\sysmonconfig.xml"
    if %errorLevel% equ 0 (
        echo [OK] Sysmon installed successfully
        timeout /t 5 /nobreak >nul
        sc query Sysmon | find "RUNNING" >nul
        if %errorLevel% equ 0 (
            echo [OK] Sysmon service is running
        ) else (
            echo [WARNING] Sysmon service not running
        )
    ) else (
        echo [ERROR] Sysmon installation failed
    )
) else (
    echo [ERROR] Sysmon executable not found
    goto :sysmon_error
)
goto :powershell_logging

:sysmon_error
echo [ERROR] Sysmon installation failed - continuing with other components

:powershell_logging
echo.
echo ========================================
echo Configuring PowerShell Logging
echo ========================================

REM Enable PowerShell Script Block Logging
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f >nul 2>&1
if %errorLevel% equ 0 (
    echo [OK] PowerShell Script Block Logging enabled
) else (
    echo [ERROR] Failed to enable Script Block Logging
)

REM Enable PowerShell Module Logging
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v * /t REG_SZ /d * /f >nul 2>&1
if %errorLevel% equ 0 (
    echo [OK] PowerShell Module Logging enabled
) else (
    echo [ERROR] Failed to enable Module Logging
)

REM Enable PowerShell Transcription
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableInvocationHeader /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d "%TRANSCRIPTS_DIR%" /f >nul 2>&1
if %errorLevel% equ 0 (
    echo [OK] PowerShell Transcription enabled
) else (
    echo [ERROR] Failed to enable Transcription
)

echo.
echo ========================================
echo Configuring Windows Audit Policies
echo ========================================

auditpol /set /category:"Account Logon" /success:enable /failure:enable >nul 2>&1
auditpol /set /category:"Account Management" /success:enable /failure:enable >nul 2>&1
auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable >nul 2>&1
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable >nul 2>&1
auditpol /set /category:"Object Access" /success:enable /failure:enable >nul 2>&1
auditpol /set /category:"Policy Change" /success:enable /failure:enable >nul 2>&1
auditpol /set /category:"Privilege Use" /success:enable /failure:enable >nul 2>&1
auditpol /set /category:"System" /success:enable /failure:enable >nul 2>&1

REM Enable command line auditing
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f >nul 2>&1

echo [OK] Windows audit policies configured

echo.
echo ========================================
echo Installing Netstat Service
echo ========================================

REM Stop and remove existing service
sc query NetstatService >nul 2>&1
if %errorLevel% equ 0 (
    echo Removing existing NetstatService...
    sc stop NetstatService >nul 2>&1
    timeout /t 3 /nobreak >nul
    if exist "%SCRIPTS_DIR%\nssm.exe" (
        "%SCRIPTS_DIR%\nssm.exe" remove NetstatService confirm >nul 2>&1
    )
    timeout /t 3 /nobreak >nul
)

echo Downloading NSSM...
powershell -Command "try { Invoke-WebRequest -Uri '%NSSM_URL%' -OutFile '%SCRIPTS_DIR%\nssm.exe' -UseBasicParsing; echo '[OK] NSSM downloaded' } catch { echo '[ERROR] Failed to download NSSM'; exit 1 }"
if %errorLevel% neq 0 goto :netstat_error

echo Downloading Netstat script...
powershell -Command "try { Invoke-WebRequest -Uri '%NETSTAT_SCRIPT_URL%' -OutFile '%SCRIPTS_DIR%\netstat-service.ps1' -UseBasicParsing; echo '[OK] Script downloaded' } catch { echo '[ERROR] Failed to download script'; exit 1 }"
if %errorLevel% neq 0 goto :netstat_error

echo Installing NetstatService...
"%SCRIPTS_DIR%\nssm.exe" install NetstatService powershell.exe "-ExecutionPolicy Bypass -File \"%SCRIPTS_DIR%\netstat-service.ps1\"" >nul 2>&1
if %errorLevel% neq 0 goto :netstat_error

"%SCRIPTS_DIR%\nssm.exe" set NetstatService DisplayName "Network Monitor Service" >nul 2>&1
"%SCRIPTS_DIR%\nssm.exe" set NetstatService Description "Monitors network connections for Wazuh" >nul 2>&1
"%SCRIPTS_DIR%\nssm.exe" set NetstatService Start SERVICE_AUTO_START >nul 2>&1

echo Starting NetstatService...
"%SCRIPTS_DIR%\nssm.exe" start NetstatService >nul 2>&1
timeout /t 5 /nobreak >nul

sc query NetstatService | find "RUNNING" >nul
if %errorLevel% equ 0 (
    echo [OK] NetstatService installed and running
) else (
    echo [WARNING] NetstatService installed but may not be running
)
goto :cleanup

:netstat_error
echo [ERROR] Netstat service installation failed

:cleanup
echo.
echo ========================================
echo Cleaning up temporary files
echo ========================================
rmdir /s /q "%TEMP_DIR%" >nul 2>&1
echo [OK] Cleanup completed

echo.
echo ========================================
echo INSTALLATION SUMMARY
echo ========================================
echo.
echo Components configured:
echo  - Sysmon (with SwiftOnSecurity config)
echo  - PowerShell Logging (Script Block, Module, Transcription)
echo  - Windows Audit Policies (all categories)
echo  - Netstat Monitoring Service
echo.
echo NEXT STEPS:
echo 1. Add to Wazuh agent.conf:
echo    ^<localfile^>
echo      ^<location^>C:\logs\netstat\netstat*.json^</location^>
echo      ^<log_format^>json^</log_format^>
echo    ^</localfile^>
echo.
echo 2. Verify installations:
echo    - Check Event Viewer for Sysmon events
echo    - Check PowerShell logging in Event Viewer
echo    - Check that NetstatService is running: sc query NetstatService
echo    - Check netstat logs in: %LOGS_DIR%
echo.
echo Setup completed!
echo.
pause
