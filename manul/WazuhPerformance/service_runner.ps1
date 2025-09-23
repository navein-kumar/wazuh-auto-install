# Service wrapper for Windows Performance Monitor
$ErrorActionPreference = "Continue"

while ($true) {
    try {
        & "C:\WazuhPerformance\performance_monitor.ps1"
    } catch {
        # Log service runner errors
        $errorMsg = "Service runner error: $^($_.Exception.Message^)"
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "$timestamp`: $errorMsg" | Out-File "C:\WazuhPerformance\logs\service_errors.log" -Append
    }
ECHO is off.
    # Wait 60 seconds before next collection
    Start-Sleep -Seconds 60
}
