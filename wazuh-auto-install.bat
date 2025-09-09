@echo off
setlocal enabledelayedexpansion
REM =============================================================================
REM Windows Threat Hunting Enhancement Script v3 - Updated Version
REM Direct Sysmon exe download + Unified directory structure
REM =============================================================================

REM Set log file path (same directory as script)
set SCRIPT_DIR=%~dp0
set LOG_FILE=%SCRIPT_DIR%wazuh-auto-install.log
set TIMESTAMP=%date:~-4,4%-%date:~-10,2%-%date:~-7,2%_%time:~0,2%-%time:~3,2%-%time:~6,2%
set TIMESTAMP=%TIMESTAMP: =0%

REM Start logging
echo ============================================================================= >> "%LOG_FILE%"
echo Windows Threat Hunting Setup v3.0 - Started at %TIMESTAMP% >> "%LOG_FILE%"
echo Log file: %LOG_FILE% >> "%LOG_FILE%"
echo ============================================================================= >> "%LOG_FILE%"

REM Function to log both to console and file
call :log "Starting Windows Threat Hunting Setup v3.0"
call :log "Log file: %LOG_FILE%"
call :log ""

REM Initialize counters
set SUCCESS_COUNT=0
set ERROR_COUNT=0
set WARNING_COUNT=0

REM Check if running as administrator
call :log "Checking administrator privileges..."
net session >nul 2>&1
if %errorLevel% neq 0 (
    call :log "[ERROR] Administrator privileges required!"
    call :log "Please run this script as Administrator."
    call :log "Script will exit in 10 seconds..."
    timeout /t 10
    exit /b 1
)

call :log "[SUCCESS] Running with administrator privileges"
set /a SUCCESS_COUNT+=1

REM Set variables - Updated directory structure
set TEMP_DIR=C:\Windows\Temp\ThreatHuntingSetup
set SCRIPTS_DIR=C:\netstat
set LOGS_DIR=C:\netstat\logs
set TRANSCRIPTS_DIR=C:\Windows\Temp\PSTranscripts

REM URLs for downloads - Direct Sysmon exe links
set SYSMON64_URL=https://github.com/navein-kumar/wazuh_sysmon/raw/refs/heads/main/Sysmon64.exe
set SYSMON32_URL=https://github.com/navein-kumar/wazuh_sysmon/raw/refs/heads/main/Sysmon.exe
set SYSMON_CONFIG_URL=https://raw.githubusercontent.com/navein-kumar/wazuh_sysmon/refs/heads/main/windows_sysmon_config.xml
set NSSM_URL=https://raw.githubusercontent.com/navein-kumar/wazuh-Netstat-Powershell/main/nssm.exe
set NETSTAT_SCRIPT_URL=https://raw.githubusercontent.com/navein-kumar/wazuh-Netstat-Powershell/main/netstat-service.ps1

call :log "========================================="
call :log "CREATING DIRECTORIES"
call :log "========================================="

call :log "Creating required directories..."

if not exist "%TEMP_DIR%" (
    mkdir "%TEMP_DIR%" 2>>"%LOG_FILE%"
    if !errorLevel! equ 0 (
        call :log "[SUCCESS] Created: %TEMP_DIR%"
        set /a SUCCESS_COUNT+=1
    ) else (
        call :log "[ERROR] Failed to create: %TEMP_DIR%"
        set /a ERROR_COUNT+=1
    )
) else (
    call :log "[INFO] Already exists: %TEMP_DIR%"
)

if not exist "%SCRIPTS_DIR%" (
    mkdir "%SCRIPTS_DIR%" 2>>"%LOG_FILE%"
    if !errorLevel! equ 0 (
        call :log "[SUCCESS] Created: %SCRIPTS_DIR%"
        set /a SUCCESS_COUNT+=1
    ) else (
        call :log "[ERROR] Failed to create: %SCRIPTS_DIR%"
        set /a ERROR_COUNT+=1
    )
) else (
    call :log "[INFO] Already exists: %SCRIPTS_DIR%"
)

if not exist "%LOGS_DIR%" (
    mkdir "%LOGS_DIR%" 2>>"%LOG_FILE%"
    if !errorLevel! equ 0 (
        call :log "[SUCCESS] Created: %LOGS_DIR%"
        set /a SUCCESS_COUNT+=1
    ) else (
        call :log "[ERROR] Failed to create: %LOGS_DIR%"
        set /a ERROR_COUNT+=1
    )
) else (
    call :log "[INFO] Already exists: %LOGS_DIR%"
)

if not exist "%TRANSCRIPTS_DIR%" (
    mkdir "%TRANSCRIPTS_DIR%" 2>>"%LOG_FILE%"
    if !errorLevel! equ 0 (
        call :log "[SUCCESS] Created: %TRANSCRIPTS_DIR%"
        set /a SUCCESS_COUNT+=1
    ) else (
        call :log "[ERROR] Failed to create: %TRANSCRIPTS_DIR%"
        set /a ERROR_COUNT+=1
    )
) else (
    call :log "[INFO] Already exists: %TRANSCRIPTS_DIR%"
)

call :log ""
call :log "========================================="
call :log "SYSMON INSTALLATION"
call :log "========================================="

call :log "Checking current Sysmon status..."

call :log "--- Checking for existing Sysmon64 service ---"
sc query Sysmon64 >nul 2>&1
if %errorLevel% equ 0 (
    call :log "[FOUND] Sysmon64 service exists"
    sc query Sysmon64 >> "%LOG_FILE%" 2>&1
    
    call :log "Removing existing Sysmon64..."
    if exist "C:\Windows\Sysmon64.exe" (
        call :log "[INFO] Using: C:\Windows\Sysmon64.exe -u force"
        "C:\Windows\Sysmon64.exe" -u force >>"%LOG_FILE%" 2>&1
        if !errorLevel! equ 0 (
            call :log "[SUCCESS] Sysmon64 uninstalled successfully"
            set /a SUCCESS_COUNT+=1
        ) else (
            call :log "[ERROR] Failed to uninstall Sysmon64"
            set /a ERROR_COUNT+=1
        )
    ) else if exist "C:\Windows\System32\Sysmon64.exe" (
        call :log "[INFO] Using: C:\Windows\System32\Sysmon64.exe -u force"
        "C:\Windows\System32\Sysmon64.exe" -u force >>"%LOG_FILE%" 2>&1
        if !errorLevel! equ 0 (
            call :log "[SUCCESS] Sysmon64 uninstalled successfully"
            set /a SUCCESS_COUNT+=1
        ) else (
            call :log "[ERROR] Failed to uninstall Sysmon64"
            set /a ERROR_COUNT+=1
        )
    ) else (
        call :log "[WARNING] Sysmon64.exe not found in standard locations"
        call :log "[INFO] Attempting generic uninstall command"
        sysmon64.exe -u force >>"%LOG_FILE%" 2>&1
        if !errorLevel! equ 0 (
            call :log "[SUCCESS] Sysmon64 uninstalled via generic command"
            set /a SUCCESS_COUNT+=1
        ) else (
            call :log "[ERROR] Generic uninstall also failed"
            set /a ERROR_COUNT+=1
        )
    )
    
    call :log "[INFO] Waiting 5 seconds for service removal..."
    timeout /t 5 /nobreak >nul
) else (
    call :log "[INFO] No existing Sysmon64 service found"
)

call :log "--- Checking for existing Sysmon service ---"
sc query Sysmon >nul 2>&1
if %errorLevel% equ 0 (
    call :log "[FOUND] Sysmon service exists"
    sc query Sysmon >> "%LOG_FILE%" 2>&1
    
    call :log "Removing existing Sysmon..."
    if exist "C:\Windows\Sysmon.exe" (
        call :log "[INFO] Using: C:\Windows\Sysmon.exe -u force"
        "C:\Windows\Sysmon.exe" -u force >>"%LOG_FILE%" 2>&1
        if !errorLevel! equ 0 (
            call :log "[SUCCESS] Sysmon uninstalled successfully"
            set /a SUCCESS_COUNT+=1
        ) else (
            call :log "[ERROR] Failed to uninstall Sysmon"
            set /a ERROR_COUNT+=1
        )
    ) else if exist "C:\Windows\System32\Sysmon.exe" (
        call :log "[INFO] Using: C:\Windows\System32\Sysmon.exe -u force"
        "C:\Windows\System32\Sysmon.exe" -u force >>"%LOG_FILE%" 2>&1
        if !errorLevel! equ 0 (
            call :log "[SUCCESS] Sysmon uninstalled successfully"
            set /a SUCCESS_COUNT+=1
        ) else (
            call :log "[ERROR] Failed to uninstall Sysmon"
            set /a ERROR_COUNT+=1
        )
    ) else (
        call :log "[WARNING] Sysmon.exe not found in standard locations"
        sysmon.exe -u force >>"%LOG_FILE%" 2>&1
        if !errorLevel! equ 0 (
            call :log "[SUCCESS] Sysmon uninstalled via generic command"
            set /a SUCCESS_COUNT+=1
        ) else (
            call :log "[ERROR] Generic uninstall also failed"
            set /a ERROR_COUNT+=1
        )
    )
    
    call :log "[INFO] Waiting 5 seconds for service removal..."
    timeout /t 5 /nobreak >nul
) else (
    call :log "[INFO] No existing Sysmon service found"
)

call :log "--- Checking for SysmonDrv driver ---"
sc query SysmonDrv >nul 2>&1
if %errorLevel% equ 0 (
    call :log "[FOUND] SysmonDrv driver exists"
    sc query SysmonDrv >> "%LOG_FILE%" 2>&1
    call :log "[INFO] Driver will be replaced during new installation"
) else (
    call :log "[INFO] No existing SysmonDrv driver found"
)

call :log "--- Verifying cleanup ---"
call :log "Checking if services were properly removed..."

sc query Sysmon64 >nul 2>&1
if %errorLevel% equ 0 (
    call :log "[WARNING] Sysmon64 service still exists - attempting forced removal"
    sc delete Sysmon64 >>"%LOG_FILE%" 2>&1
    if !errorLevel! equ 0 (
        call :log "[SUCCESS] Sysmon64 service deleted"
        set /a SUCCESS_COUNT+=1
    ) else (
        call :log "[ERROR] Failed to delete Sysmon64 service"
        set /a ERROR_COUNT+=1
    )
    timeout /t 3 /nobreak >nul
) else (
    call :log "[SUCCESS] Sysmon64 service properly removed"
    set /a SUCCESS_COUNT+=1
)

sc query Sysmon >nul 2>&1
if %errorLevel% equ 0 (
    call :log "[WARNING] Sysmon service still exists - attempting forced removal"
    sc delete Sysmon >>"%LOG_FILE%" 2>&1
    if !errorLevel! equ 0 (
        call :log "[SUCCESS] Sysmon service deleted"
        set /a SUCCESS_COUNT+=1
    ) else (
        call :log "[ERROR] Failed to delete Sysmon service"
        set /a ERROR_COUNT+=1
    )
    timeout /t 3 /nobreak >nul
) else (
    call :log "[SUCCESS] Sysmon service properly removed"
    set /a SUCCESS_COUNT+=1
)

call :log "--- Downloading Sysmon files ---"
call :log "Downloading Sysmon64.exe from: %SYSMON64_URL%"
powershell -Command "try { Invoke-WebRequest -Uri '%SYSMON64_URL%' -OutFile '%TEMP_DIR%\Sysmon64.exe' -UseBasicParsing; Write-Host 'Sysmon64.exe download completed' } catch { Write-Host 'Sysmon64.exe download failed:' $_.Exception.Message; exit 1 }" >>"%LOG_FILE%" 2>&1
if %errorLevel% neq 0 (
    call :log "[WARNING] Sysmon64.exe download failed, trying 32-bit version..."
    call :log "Downloading Sysmon.exe from: %SYSMON32_URL%"
    powershell -Command "try { Invoke-WebRequest -Uri '%SYSMON32_URL%' -OutFile '%TEMP_DIR%\Sysmon.exe' -UseBasicParsing; Write-Host 'Sysmon.exe download completed' } catch { Write-Host 'Sysmon.exe download failed:' $_.Exception.Message; exit 1 }" >>"%LOG_FILE%" 2>&1
    if !errorLevel! neq 0 (
        call :log "[ERROR] Both Sysmon downloads failed"
        set /a ERROR_COUNT+=1
        goto :sysmon_error
    ) else (
        call :log "[SUCCESS] Sysmon.exe (32-bit) download completed"
        set /a SUCCESS_COUNT+=1
        set SYSMON_DOWNLOADED=32
    )
) else (
    call :log "[SUCCESS] Sysmon64.exe download completed"
    set /a SUCCESS_COUNT+=1
    set SYSMON_DOWNLOADED=64
)

call :log "Downloading Sysmon configuration from: %SYSMON_CONFIG_URL%"
powershell -Command "try { Invoke-WebRequest -Uri '%SYSMON_CONFIG_URL%' -OutFile '%TEMP_DIR%\sysmonconfig.xml' -UseBasicParsing; Write-Host 'Config download completed' } catch { Write-Host 'Config download failed:' $_.Exception.Message; exit 1 }" >>"%LOG_FILE%" 2>&1
if %errorLevel% neq 0 (
    call :log "[ERROR] Sysmon config download failed"
    set /a ERROR_COUNT+=1
    goto :sysmon_error
) else (
    call :log "[SUCCESS] Sysmon config download completed"
    set /a SUCCESS_COUNT+=1
)

call :log "--- Checking downloaded files ---"
if "%SYSMON_DOWNLOADED%"=="64" (
    if exist "%TEMP_DIR%\Sysmon64.exe" (
        call :log "[FOUND] Sysmon64.exe (64-bit version)"
        dir "%TEMP_DIR%\Sysmon64.exe" >> "%LOG_FILE%" 2>&1
    ) else (
        call :log "[ERROR] Sysmon64.exe not found after download"
        set /a ERROR_COUNT+=1
        goto :sysmon_error
    )
) else (
    if exist "%TEMP_DIR%\Sysmon.exe" (
        call :log "[FOUND] Sysmon.exe (32-bit version)"
        dir "%TEMP_DIR%\Sysmon.exe" >> "%LOG_FILE%" 2>&1
    ) else (
        call :log "[ERROR] Sysmon.exe not found after download"
        set /a ERROR_COUNT+=1
        goto :sysmon_error
    )
)

if exist "%TEMP_DIR%\sysmonconfig.xml" (
    call :log "[FOUND] Configuration file"
    dir "%TEMP_DIR%\sysmonconfig.xml" >> "%LOG_FILE%" 2>&1
) else (
    call :log "[ERROR] Configuration file missing"
    set /a ERROR_COUNT+=1
    goto :sysmon_error
)

call :log "--- Installing Sysmon ---"
if "%SYSMON_DOWNLOADED%"=="64" (
    call :log "[INFO] Installing Sysmon64 (64-bit version)..."
    call :log "[COMMAND] %TEMP_DIR%\Sysmon64.exe -accepteula -i %TEMP_DIR%\sysmonconfig.xml"
    "%TEMP_DIR%\Sysmon64.exe" -accepteula -i "%TEMP_DIR%\sysmonconfig.xml" >>"%LOG_FILE%" 2>&1
    set INSTALL_RESULT=!errorLevel!
    set SYSMON_INSTALLED=64
    
    if !INSTALL_RESULT! equ 0 (
        call :log "[SUCCESS] Sysmon64 installation command completed"
        set /a SUCCESS_COUNT+=1
    ) else (
        call :log "[ERROR] Sysmon64 installation command failed with exit code: !INSTALL_RESULT!"
        set /a ERROR_COUNT+=1
    )
    
) else (
    call :log "[INFO] Installing Sysmon (32-bit version)..."
    call :log "[COMMAND] %TEMP_DIR%\Sysmon.exe -accepteula -i %TEMP_DIR%\sysmonconfig.xml"
    "%TEMP_DIR%\Sysmon.exe" -accepteula -i "%TEMP_DIR%\sysmonconfig.xml" >>"%LOG_FILE%" 2>&1
    set INSTALL_RESULT=!errorLevel!
    set SYSMON_INSTALLED=32
    
    if !INSTALL_RESULT! equ 0 (
        call :log "[SUCCESS] Sysmon installation command completed"
        set /a SUCCESS_COUNT+=1
    ) else (
        call :log "[ERROR] Sysmon installation command failed with exit code: !INSTALL_RESULT!"
        set /a ERROR_COUNT+=1
    )
)

call :log "--- Verifying Sysmon Installation ---"
call :log "[INFO] Waiting 5 seconds for services to initialize..."
timeout /t 5 /nobreak >nul

if "%SYSMON_INSTALLED%"=="64" (
    call :log "Checking Sysmon64 service status..."
    sc query Sysmon64 >nul 2>&1
    if !errorLevel! equ 0 (
        call :log "[SUCCESS] Sysmon64 service found"
        sc query Sysmon64 >> "%LOG_FILE%" 2>&1
        
        sc query Sysmon64 | find "RUNNING" >nul
        if !errorLevel! equ 0 (
            call :log "[SUCCESS] Sysmon64 service is RUNNING"
            set /a SUCCESS_COUNT+=1
        ) else (
            call :log "[WARNING] Sysmon64 service exists but not running - attempting start"
            sc start Sysmon64 >>"%LOG_FILE%" 2>&1
            timeout /t 3 /nobreak >nul
            sc query Sysmon64 | find "RUNNING" >nul
            if !errorLevel! equ 0 (
                call :log "[SUCCESS] Sysmon64 service started successfully"
                set /a SUCCESS_COUNT+=1
            ) else (
                call :log "[ERROR] Sysmon64 service failed to start"
                sc query Sysmon64 >> "%LOG_FILE%" 2>&1
                set /a ERROR_COUNT+=1
            )
        )
    ) else (
        call :log "[ERROR] Sysmon64 service not found after installation"
        set /a ERROR_COUNT+=1
    )
) else if "%SYSMON_INSTALLED%"=="32" (
    call :log "Checking Sysmon service status..."
    sc query Sysmon >nul 2>&1
    if !errorLevel! equ 0 (
        call :log "[SUCCESS] Sysmon service found"
        sc query Sysmon >> "%LOG_FILE%" 2>&1
        
        sc query Sysmon | find "RUNNING" >nul
        if !errorLevel! equ 0 (
            call :log "[SUCCESS] Sysmon service is RUNNING"
            set /a SUCCESS_COUNT+=1
        ) else (
            call :log "[WARNING] Sysmon service exists but not running - attempting start"
            sc start Sysmon >>"%LOG_FILE%" 2>&1
            timeout /t 3 /nobreak >nul
            sc query Sysmon | find "RUNNING" >nul
            if !errorLevel! equ 0 (
                call :log "[SUCCESS] Sysmon service started successfully"
                set /a SUCCESS_COUNT+=1
            ) else (
                call :log "[ERROR] Sysmon service failed to start"
                sc query Sysmon >> "%LOG_FILE%" 2>&1
                set /a ERROR_COUNT+=1
            )
        )
    ) else (
        call :log "[ERROR] Sysmon service not found after installation"
        set /a ERROR_COUNT+=1
    )
)

call :log "--- Checking SysmonDrv Driver ---"
sc query SysmonDrv >nul 2>&1
if %errorLevel% equ 0 (
    call :log "[SUCCESS] SysmonDrv driver found"
    sc query SysmonDrv >> "%LOG_FILE%" 2>&1
    
    sc query SysmonDrv | find "RUNNING" >nul
    if !errorLevel! equ 0 (
        call :log "[SUCCESS] SysmonDrv driver is RUNNING"
        set /a SUCCESS_COUNT+=1
    ) else (
        call :log "[WARNING] SysmonDrv driver exists but not running"
        set /a WARNING_COUNT+=1
    )
) else (
    call :log "[ERROR] SysmonDrv driver not found"
    set /a ERROR_COUNT+=1
)

call :log "[SUCCESS] Sysmon installation section completed"
goto :powershell_logging

:sysmon_error
call :log ""
call :log "[ERROR] Sysmon installation failed"
call :log ""
call :log "TROUBLESHOOTING TIPS:"
call :log "- Check if antivirus is blocking the installation"
call :log "- Verify you have administrator privileges"
call :log "- Check Windows Event Log for Sysmon-related errors"
call :log "- Ensure no other security tools are conflicting"
call :log "- Check the log file for detailed error messages: %LOG_FILE%"
call :log ""
set /a ERROR_COUNT+=1

:powershell_logging
call :log ""
call :log "========================================="
call :log "POWERSHELL LOGGING CONFIGURATION"
call :log "========================================="

call :log "Configuring PowerShell Script Block Logging..."
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f >>"%LOG_FILE%" 2>&1
if %errorLevel% equ 0 (
    call :log "[SUCCESS] PowerShell Script Block Logging enabled"
    set /a SUCCESS_COUNT+=1
) else (
    call :log "[ERROR] Failed to enable Script Block Logging"
    set /a ERROR_COUNT+=1
)

call :log "Configuring PowerShell Module Logging..."
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f >>"%LOG_FILE%" 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v * /t REG_SZ /d * /f >>"%LOG_FILE%" 2>&1
if %errorLevel% equ 0 (
    call :log "[SUCCESS] PowerShell Module Logging enabled"
    set /a SUCCESS_COUNT+=1
) else (
    call :log "[ERROR] Failed to enable Module Logging"
    set /a ERROR_COUNT+=1
)

call :log "Configuring PowerShell Transcription..."
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f >>"%LOG_FILE%" 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableInvocationHeader /t REG_DWORD /d 1 /f >>"%LOG_FILE%" 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d "%TRANSCRIPTS_DIR%" /f >>"%LOG_FILE%" 2>&1
if %errorLevel% equ 0 (
    call :log "[SUCCESS] PowerShell Transcription enabled (Output: %TRANSCRIPTS_DIR%)"
    set /a SUCCESS_COUNT+=1
) else (
    call :log "[ERROR] Failed to enable Transcription"
    set /a ERROR_COUNT+=1
)

call :log ""
call :log "========================================="
call :log "WINDOWS AUDIT POLICIES"
call :log "========================================="

call :log "Configuring Windows audit policies..."
auditpol /set /category:"Account Logon" /success:enable /failure:enable >>"%LOG_FILE%" 2>&1
auditpol /set /category:"Account Management" /success:enable /failure:enable >>"%LOG_FILE%" 2>&1
auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable >>"%LOG_FILE%" 2>&1
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable >>"%LOG_FILE%" 2>&1
auditpol /set /category:"Object Access" /success:enable /failure:enable >>"%LOG_FILE%" 2>&1
auditpol /set /category:"Policy Change" /success:enable /failure:enable >>"%LOG_FILE%" 2>&1
auditpol /set /category:"Privilege Use" /success:enable /failure:enable >>"%LOG_FILE%" 2>&1
auditpol /set /category:"System" /success:enable /failure:enable >>"%LOG_FILE%" 2>&1

call :log "Enabling command line auditing..."
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f >>"%LOG_FILE%" 2>&1
if %errorLevel% equ 0 (
    call :log "[SUCCESS] Windows audit policies configured"
    set /a SUCCESS_COUNT+=1
) else (
    call :log "[ERROR] Some audit policies may have failed"
    set /a ERROR_COUNT+=1
)

call :log ""
call :log "========================================="
call :log "NETSTAT SERVICE INSTALLATION"
call :log "========================================="

call :log "Checking for existing NetstatService..."
sc query NetstatService >nul 2>&1
if %errorLevel% equ 0 (
    call :log "[FOUND] Existing NetstatService - removing..."
    sc stop NetstatService >>"%LOG_FILE%" 2>&1
    call :log "[INFO] Waiting for service to stop..."
    timeout /t 3 /nobreak >nul
    
    if exist "%SCRIPTS_DIR%\nssm.exe" (
        call :log "[INFO] Using NSSM to remove service"
        "%SCRIPTS_DIR%\nssm.exe" remove NetstatService confirm >>"%LOG_FILE%" 2>&1
        if !errorLevel! equ 0 (
            call :log "[SUCCESS] NetstatService removed successfully"
            set /a SUCCESS_COUNT+=1
        ) else (
            call :log "[ERROR] Failed to remove NetstatService with NSSM"
            set /a ERROR_COUNT+=1
        )
    ) else (
        call :log "[WARNING] NSSM not found, attempting manual removal"
        sc delete NetstatService >>"%LOG_FILE%" 2>&1
        if !errorLevel! equ 0 (
            call :log "[SUCCESS] NetstatService deleted manually"
            set /a SUCCESS_COUNT+=1
        ) else (
            call :log "[ERROR] Failed to delete NetstatService manually"
            set /a ERROR_COUNT+=1
        )
    )
    timeout /t 3 /nobreak >nul
) else (
    call :log "[INFO] No existing NetstatService found"
)

call :log "Downloading NSSM from: %NSSM_URL%"
powershell -Command "try { Invoke-WebRequest -Uri '%NSSM_URL%' -OutFile '%SCRIPTS_DIR%\nssm.exe' -UseBasicParsing; Write-Host 'NSSM download completed' } catch { Write-Host 'NSSM download failed:' $_.Exception.Message; exit 1 }" >>"%LOG_FILE%" 2>&1
if %errorLevel% neq 0 (
    call :log "[ERROR] NSSM download failed"
    set /a ERROR_COUNT+=1
    goto :netstat_error
) else (
    call :log "[SUCCESS] NSSM download completed"
    set /a SUCCESS_COUNT+=1
)

call :log "Downloading Netstat script from: %NETSTAT_SCRIPT_URL%"
powershell -Command "try { Invoke-WebRequest -Uri '%NETSTAT_SCRIPT_URL%' -OutFile '%SCRIPTS_DIR%\netstat-service.ps1' -UseBasicParsing; Write-Host 'Script download completed' } catch { Write-Host 'Script download failed:' $_.Exception.Message; exit 1 }" >>"%LOG_FILE%" 2>&1
if %errorLevel% neq 0 (
    call :log "[ERROR] Netstat script download failed"
    set /a ERROR_COUNT+=1
    goto :netstat_error
) else (
    call :log "[SUCCESS] Netstat script download completed"
    set /a SUCCESS_COUNT+=1
)

call :log "Installing NetstatService..."
call :log "[COMMAND] %SCRIPTS_DIR%\nssm.exe install NetstatService powershell.exe"
"%SCRIPTS_DIR%\nssm.exe" install NetstatService powershell.exe "-ExecutionPolicy Bypass -File \"%SCRIPTS_DIR%\netstat-service.ps1\"" >>"%LOG_FILE%" 2>&1
if %errorLevel% neq 0 (
    call :log "[ERROR] NetstatService installation failed"
    set /a ERROR_COUNT+=1
    goto :netstat_error
) else (
    call :log "[SUCCESS] NetstatService installed"
    set /a SUCCESS_COUNT+=1
)

call :log "Configuring NetstatService properties..."
"%SCRIPTS_DIR%\nssm.exe" set NetstatService DisplayName "Network Monitor Service" >>"%LOG_FILE%" 2>&1
"%SCRIPTS_DIR%\nssm.exe" set NetstatService Description "Monitors network connections for Wazuh" >>"%LOG_FILE%" 2>&1
"%SCRIPTS_DIR%\nssm.exe" set NetstatService Start SERVICE_AUTO_START >>"%LOG_FILE%" 2>&1

call :log "Starting NetstatService..."
"%SCRIPTS_DIR%\nssm.exe" start NetstatService >>"%LOG_FILE%" 2>&1
call :log "[INFO] Waiting for service to start..."
timeout /t 5 /nobreak >nul

sc query NetstatService | find "RUNNING" >nul
if %errorLevel% equ 0 (
    call :log "[SUCCESS] NetstatService is running"
    sc query NetstatService >> "%LOG_FILE%" 2>&1
    set /a SUCCESS_COUNT+=1
) else (
    call :log "[WARNING] NetstatService installed but may not be running"
    call :log "[INFO] Current service status:"
    sc query NetstatService >> "%LOG_FILE%" 2>&1
    set /a WARNING_COUNT+=1
)
goto :cleanup

:netstat_error
call :log "[ERROR] Netstat service installation failed"
set /a ERROR_COUNT+=1

:cleanup
call :log ""
call :log "========================================="
call :log "CLEANUP"
call :log "========================================="
call :log "Cleaning up temporary files..."
if exist "%TEMP_DIR%" (
    rmdir /s /q "%TEMP_DIR%" >>"%LOG_FILE%" 2>&1
    if !errorLevel! equ 0 (
        call :log "[SUCCESS] Temporary files cleaned up"
        set /a SUCCESS_COUNT+=1
    ) else (
        call :log "[WARNING] Some temporary files may remain in: %TEMP_DIR%"
        set /a WARNING_COUNT+=1
    )
) else (
    call :log "[INFO] No temporary files to clean up"
)

call :log ""
call :log "========================================="
call :log "WAZUH AGENT RESTART"
call :log "========================================="

call :log "Checking Wazuh agent status..."
sc query WazuhSvc >nul 2>&1
if %errorLevel% equ 0 (
    call :log "[FOUND] Wazuh agent service detected"
    sc query WazuhSvc >> "%LOG_FILE%" 2>&1
    
    call :log "Restarting Wazuh agent to apply new log configurations..."
    sc stop WazuhSvc >>"%LOG_FILE%" 2>&1
    if !errorLevel! equ 0 (
        call :log "[SUCCESS] Wazuh agent stopped"
        call :log "[INFO] Waiting 5 seconds before restart..."
        timeout /t 5 /nobreak >nul
        
        sc start WazuhSvc >>"%LOG_FILE%" 2>&1
        if !errorLevel! equ 0 (
            call :log "[SUCCESS] Wazuh agent started"
            set /a SUCCESS_COUNT+=1
            
            call :log "[INFO] Waiting 5 seconds for agent to initialize..."
            timeout /t 5 /nobreak >nul
            
            sc query WazuhSvc | find "RUNNING" >nul
            if !errorLevel! equ 0 (
                call :log "[SUCCESS] Wazuh agent is running and ready"
                set /a SUCCESS_COUNT+=1
            ) else (
                call :log "[WARNING] Wazuh agent may still be starting up"
                set /a WARNING_COUNT+=1
            )
        ) else (
            call :log "[ERROR] Failed to start Wazuh agent"
            set /a ERROR_COUNT+=1
        )
    ) else (
        call :log "[ERROR] Failed to stop Wazuh agent"
        set /a ERROR_COUNT+=1
    )
) else (
    call :log "[WARNING] Wazuh agent service not found - please install Wazuh agent first"
    call :log "[INFO] Service name checked: WazuhSvc"
    set /a WARNING_COUNT+=1
)

call :log ""
call :log "========================================="
call :log "FINAL VERIFICATION"
call :log "========================================="
call :log ""
call :log "Running final verification checks..."

call :log "--- Verifying Sysmon Service ---"
sc query Sysmon64 >nul 2>&1
if %errorLevel% equ 0 (
    sc query Sysmon64 | find "RUNNING" >nul
    if !errorLevel! equ 0 (
        call :log "[VERIFIED] Sysmon64 service is RUNNING"
        set SYSMON_STATUS=RUNNING
    ) else (
        call :log "[ISSUE] Sysmon64 service exists but not running"
        set SYSMON_STATUS=NOT_RUNNING
    )
) else (
    sc query Sysmon >nul 2>&1
    if !errorLevel! equ 0 (
        sc query Sysmon | find "RUNNING" >nul
        if !errorLevel! equ 0 (
            call :log "[VERIFIED] Sysmon service is RUNNING"
            set SYSMON_STATUS=RUNNING
        ) else (
            call :log "[ISSUE] Sysmon service exists but not running"
            set SYSMON_STATUS=NOT_RUNNING
        )
    ) else (
        call :log "[ISSUE] No Sysmon service found"
        set SYSMON_STATUS=NOT_FOUND
    )
)

call :log "--- Verifying SysmonDrv Driver ---"
sc query SysmonDrv >nul 2>&1
if %errorLevel% equ 0 (
    sc query SysmonDrv | find "RUNNING" >nul
    if !errorLevel! equ 0 (
        call :log "[VERIFIED] SysmonDrv driver is RUNNING"
        set SYSMONDRV_STATUS=RUNNING
    ) else (
        call :log "[ISSUE] SysmonDrv driver exists but not running"
        set SYSMONDRV_STATUS=NOT_RUNNING
    )
) else (
    call :log "[ISSUE] SysmonDrv driver not found"
    set SYSMONDRV_STATUS=NOT_FOUND
)

call :log "--- Verifying NetstatService ---"
sc query NetstatService >nul 2>&1
if %errorLevel% equ 0 (
    sc query NetstatService | find "RUNNING" >nul
    if !errorLevel! equ 0 (
        call :log "[VERIFIED] NetstatService is RUNNING"
        set NETSTAT_STATUS=RUNNING
    ) else (
        call :log "[ISSUE] NetstatService exists but not running"
        set NETSTAT_STATUS=NOT_RUNNING
    )
) else (
    call :log "[ISSUE] NetstatService not found"
    set NETSTAT_STATUS=NOT_FOUND
)

call :log "--- Verifying Wazuh Agent ---"
sc query WazuhSvc >nul 2>&1
if %errorLevel% equ 0 (
    sc query WazuhSvc | find "RUNNING" >nul
    if !errorLevel! equ 0 (
        call :log "[VERIFIED] Wazuh agent is RUNNING"
        set WAZUH_STATUS=RUNNING
    ) else (
        call :log "[ISSUE] Wazuh agent exists but not running"
        set WAZUH_STATUS=NOT_RUNNING
    )
) else (
    call :log "[ISSUE] Wazuh agent service not found"
    set WAZUH_STATUS=NOT_FOUND
)

call :log ""
call :log "========================================="
call :log "INSTALLATION COMPLETED"
call :log "========================================="
call :log "Full log available at: %LOG_FILE%"
call :log "You can review the complete installation details in the log file."
call :log ""

REM Display final summary to console
echo.
echo ==========================================
echo INSTALLATION COMPLETED v3.0
echo ==========================================
echo.
echo Updated Directory Structure:
echo  Scripts: %SCRIPTS_DIR%
echo  Logs:    %LOGS_DIR%
echo.
echo Results Summary:
echo  SUCCESS: %SUCCESS_COUNT% operations
echo  WARNING: %WARNING_COUNT% operations  
echo  ERROR:   %ERROR_COUNT% operations
echo.

echo Service Status Verification:
echo  Sysmon:       %SYSMON_STATUS%
echo  SysmonDrv:    %SYSMONDRV_STATUS%
echo  NetstatSvc:   %NETSTAT_STATUS%
echo  WazuhAgent:   %WAZUH_STATUS%
echo.

echo Live Verification Commands:
echo ==========================================
echo sc query Sysmon64
sc query Sysmon64
echo.
echo sc query SysmonDrv
sc query SysmonDrv
echo.
echo sc query NetstatService
sc query NetstatService
echo.
echo sc query WazuhSvc
sc query WazuhSvc
echo.

if %ERROR_COUNT% equ 0 (
    echo [STATUS] Installation completed successfully!
) else (
    echo [STATUS] Installation completed with %ERROR_COUNT% errors
)
echo.
echo Full detailed log saved to: %LOG_FILE%
echo.
echo NEXT STEPS:
echo 1. Check Event Viewer: eventvwr.msc
echo    Navigate to: Applications and Services Logs ^> Microsoft ^> Windows ^> Sysmon ^> Operational
echo 2. Test Sysmon: powershell.exe -Command "Get-Process"
echo 3. Check netstat logs: dir %LOGS_DIR%\
echo 4. Verify Wazuh agent is receiving logs in Wazuh dashboard
echo.
echo WAZUH CONFIGURATION:
echo Add to ossec.conf:
echo   ^<localfile^>
echo     ^<location^>Microsoft-Windows-Sysmon/Operational^</location^>
echo     ^<log_format^>eventchannel^</log_format^>
echo   ^</localfile^>
echo.
echo   ^<localfile^>
echo     ^<location^>%LOGS_DIR%\netstat*.json^</location^>
echo     ^<log_format^>json^</log_format^>
echo   ^</localfile^>
echo.
echo Press any key to open the log file...
pause >nul
notepad.exe "%LOG_FILE%"
goto :end

REM Function to log both to console and file
:log
echo %~1
echo %date% %time% - %~1 >> "%LOG_FILE%"
goto :eof

:end
exit /b 0
