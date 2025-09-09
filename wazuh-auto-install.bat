@echo off
REM =============================================================================
REM Windows Threat Hunting Enhancement Script - With Log File Output
REM Creates detailed log file in same directory as script
REM =============================================================================

REM Set log file path (same directory as script)
set SCRIPT_DIR=%~dp0
set LOG_FILE=%SCRIPT_DIR%wazuh-auto-install.log
set TIMESTAMP=%date:~-4,4%-%date:~-10,2%-%date:~-7,2%_%time:~0,2%-%time:~3,2%-%time:~6,2%
set TIMESTAMP=%TIMESTAMP: =0%

REM Start logging
echo ============================================================================= >> "%LOG_FILE%"
echo Windows Threat Hunting Setup v5.2 - Started at %TIMESTAMP% >> "%LOG_FILE%"
echo Log file: %LOG_FILE% >> "%LOG_FILE%"
echo ============================================================================= >> "%LOG_FILE%"

REM Function to log both to console and file
call :log "Starting Windows Threat Hunting Setup v5.2"
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
call :log "Downloading Sysmon from: %SYSMON_URL%"
powershell -Command "try { Invoke-WebRequest -Uri '%SYSMON_URL%' -OutFile '%TEMP_DIR%\Sysmon.zip' -UseBasicParsing; Write-Host 'Download completed' } catch { Write-Host 'Download failed:' $_.Exception.Message; exit 1 }" >>"%LOG_FILE%" 2>&1
if %errorLevel% neq 0 (
    call :log "[ERROR] Sysmon download failed"
    set /a ERROR_COUNT+=1
    goto :sysmon_error
) else (
    call :log "[SUCCESS] Sysmon download completed"
    set /a SUCCESS_COUNT+=1
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

call :log "--- Extracting Sysmon ---"
call :log "Extracting Sysmon archive to: %TEMP_DIR%\Sysmon"
powershell -Command "try { Expand-Archive -Path '%TEMP_DIR%\Sysmon.zip' -DestinationPath '%TEMP_DIR%\Sysmon' -Force; Write-Host 'Extraction completed' } catch { Write-Host 'Extraction failed:' $_.Exception.Message; exit 1 }" >>"%LOG_FILE%" 2>&1
if %errorLevel% neq 0 (
    call :log "[ERROR] Sysmon extraction failed"
    set /a ERROR_COUNT+=1
    goto :sysmon_error
) else (
    call :log "[SUCCESS] Sysmon extraction completed"
    set /a SUCCESS_COUNT+=1
)

call :log "--- Checking extracted files ---"
if exist "%TEMP_DIR%\Sysmon\Sysmon64.exe" (
    call :log "[FOUND] Sysmon64.exe (64-bit version)"
    dir "%TEMP_DIR%\Sysmon\Sysmon64.exe" >> "%LOG_FILE%" 2>&1
) else (
    call :log "[INFO] Sysmon64.exe not found"
)

if exist "%TEMP_DIR%\Sysmon\Sysmon.exe" (
    call :log "[FOUND] Sysmon.exe (32-bit version)"
    dir "%TEMP_DIR%\Sysmon\Sysmon.exe" >> "%LOG_FILE%" 2>&1
) else (
    call :log "[INFO] Sysmon.exe not found"
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
if exist "%TEMP_DIR%\Sysmon\Sysmon64.exe" (
    call :log "[INFO] Installing Sysmon64 (64-bit version)..."
    call :log "[COMMAND] %TEMP_DIR%\Sysmon\Sysmon64.exe -accepteula -i %TEMP_DIR%\sysmonconfig.xml"
    "%TEMP_DIR%\Sysmon\Sysmon64.exe" -accepteula -i "%TEMP_DIR%\sysmonconfig.xml" >>"%LOG_FILE%" 2>&1
    set INSTALL_RESULT=!errorLevel!
    set SYSMON_INSTALLED=64
    
    if !INSTALL_RESULT! equ 0 (
        call :log "[SUCCESS] Sysmon64 installation command completed"
        set /a SUCCESS_COUNT+=1
    ) else (
        call :log "[ERROR] Sysmon64 installation command failed with exit code: !INSTALL_RESULT!"
        set /a ERROR_COUNT+=1
    )
    
) else if exist "%TEMP_DIR%\Sysmon\Sysmon.exe" (
    call :log "[INFO] Installing Sysmon (32-bit version)..."
    call :log "[COMMAND] %TEMP_DIR%\Sysmon\Sysmon.exe -accepteula -i %TEMP_DIR%\sysmonconfig.xml"
    "%TEMP_DIR%\Sysmon\Sysmon.exe" -accepteula -i "%TEMP_DIR%\sysmonconfig.xml" >>"%LOG_FILE%" 2>&1
    set INSTALL_RESULT=!errorLevel!
    set SYSMON_INSTALLED=32
    
    if !INSTALL_RESULT! equ 0 (
        call :log "[SUCCESS] Sysmon installation command completed"
        set /a SUCCESS_COUNT+=1
    ) else (
        call :log "[ERROR] Sysmon installation command failed with exit code: !INSTALL_RESULT!"
        set /a ERROR_COUNT+=1
    )
    
) else (
    call :log "[ERROR] No Sysmon executable found in extracted files"
    call :log "[INFO] Contents of extraction directory:"
    dir "%TEMP_DIR%\Sysmon\" >> "%LOG_FILE%" 2>&1
    set /a ERROR_COUNT+=1
    goto :sysmon_error
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
call :log "INSTALLATION SUMMARY"
call :log "========================================="
call :log ""
call :log "RESULTS:"
call :log " [SUCCESS] Operations: %SUCCESS_COUNT%"
call :log " [WARNING] Operations: %WARNING_COUNT%"
call :log " [ERROR]   Operations: %ERROR_COUNT%"
call :log ""

if %ERROR_COUNT% equ 0 (
    call :log "[OVERALL STATUS] INSTALLATION COMPLETED SUCCESSFULLY"
) else if %ERROR_COUNT% lss 3 (
    call :log "[OVERALL STATUS] INSTALLATION COMPLETED WITH MINOR ISSUES"
) else (
    call :log "[OVERALL STATUS] INSTALLATION COMPLETED WITH SIGNIFICANT ISSUES"
)

call :log ""
call :log "COMPONENTS CONFIGURED:"
call :log " - Sysmon (with SwiftOnSecurity config)"
call :log " - PowerShell Logging (Script Block, Module, Transcription)"
call :log " - Windows Audit Policies (all categories)"
call :log " - Netstat Monitoring Service"
call :log ""

call :log "VERIFICATION COMMANDS:"
call :log " Check Sysmon: sc query Sysmon64  (or sc query Sysmon)"
call :log " Check Driver: sc query SysmonDrv"
call :log " Check Netstat: sc query NetstatService"
call :log " Check Logs: Check Event Viewer -> Sysmon/Operational"
call :log " Check Files: dir %LOGS_DIR%"
call :log ""

call :log "NEXT STEPS:"
call :log "1. Add to Wazuh agent ossec.conf:"
call :log "   <localfile>"
call :log "     <location>Microsoft-Windows-Sysmon/Operational</location>"
call :log "     <log_format>eventchannel</log_format>"
call :log "   </localfile>"
call :log ""
call :log "   <localfile>"
call :log "     <location>C:\logs\netstat\netstat*.json</location>"
call :log "     <log_format>json</log_format>"
call :log "   </localfile>"
call :log ""
call :log "2. Restart Wazuh agent service"
call :log "3. Test by running: powershell.exe -Command Get-Process"
call :log ""

call :log "========================================="
call :log "DETAILED SERVICE STATUS"
call :log "========================================="
call :log ""

call :log "--- Sysmon Status ---"
sc query Sysmon64 >nul 2>&1
if %errorLevel% equ 0 (
    sc query Sysmon64 >> "%LOG_FILE%" 2>&1
    call :log "Sysmon64 service details logged"
) else (
    sc query Sysmon >nul 2>&1
    if !errorLevel! equ 0 (
        sc query Sysmon >> "%LOG_FILE%" 2>&1
        call :log "Sysmon service details logged"
    ) else (
        call :log "[ERROR] No Sysmon service found"
    )
)

call :log ""
call :log "--- SysmonDrv Status ---"
sc query SysmonDrv >nul 2>&1
if %errorLevel% equ 0 (
    sc query SysmonDrv >> "%LOG_FILE%" 2>&1
    call :log "SysmonDrv driver details logged"
) else (
    call :log "[ERROR] No SysmonDrv driver found"
)

call :log ""
call :log "--- NetstatService Status ---"
sc query NetstatService >nul 2>&1
if %errorLevel% equ 0 (
    sc query NetstatService >> "%LOG_FILE%" 2>&1
    call :log "NetstatService details logged"
) else (
    call :log "[ERROR] No NetstatService found"
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
echo INSTALLATION COMPLETED
echo ==========================================
echo.
echo Results Summary:
echo  SUCCESS: %SUCCESS_COUNT% operations
echo  WARNING: %WARNING_COUNT% operations  
echo  ERROR:   %ERROR_COUNT% operations
echo.
if %ERROR_COUNT% equ 0 (
    echo [STATUS] Installation completed successfully!
) else (
    echo [STATUS] Installation completed with %ERROR_COUNT% errors
)
echo.
echo Full detailed log saved to: %LOG_FILE%
echo.
echo Key verification commands:
echo  sc query Sysmon64
echo  sc query SysmonDrv  
echo  sc query NetstatService
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
