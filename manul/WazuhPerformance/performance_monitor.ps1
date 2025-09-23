# Windows Performance Monitor for Wazuh - Complete Version
$logDir = "C:\WazuhPerformance\logs"
$today = Get-Date -Format "yyyy-MM-dd"
$logFile = "$logDir\performance_$today.json"

try {
    # Ensure log directory exists
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    # Get CPU utilization
    $cpuPercent = 0
    try {
        $cpu = Get-WmiObject -Class Win32_Processor | Select-Object -First 1
        if ($cpu.LoadPercentage) {
            $cpuPercent = $cpu.LoadPercentage
        } else {
            # Fallback to performance counter
            $perfCounter = Get-Counter "\Processor^(_Total^)\% Processor Time" -SampleInterval 1 -MaxSamples 1
            $cpuPercent = [math]::Round($perfCounter.CounterSamples[0].CookedValue, 2)
        }
    } catch {
        $cpuPercent = 0
    }

    # Get Memory information
    $memory = Get-WmiObject -Class Win32_OperatingSystem
    $memTotalKB = $memory.TotalVisibleMemorySize
    $memFreeKB = $memory.FreePhysicalMemory
    $memUsedKB = $memTotalKB - $memFreeKB
    $memUsedPercent = [math]::Round(($memUsedKB / $memTotalKB) * 100, 2)

    # Get Disk information for C: drive
    $disk = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'"
    $diskTotalGB = [math]::Round($disk.Size / 1GB, 2)
    $diskFreeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
    $diskUsedGB = $diskTotalGB - $diskFreeGB
    $diskUsedPercent = [math]::Round(($diskUsedGB / $diskTotalGB) * 100, 2)

    # Get Network adapters
    $networkAdapters = Get-WmiObject -Class Win32_NetworkAdapter -Filter "NetConnectionStatus=2"
    $activeNetworkCount = ($networkAdapters | Measure-Object).Count

    # Get System uptime
    $bootTime = (Get-WmiObject Win32_OperatingSystem).LastBootUpTime
    $bootTimeFormatted = [Management.ManagementDateTimeConverter]::ToDateTime($bootTime)
    $uptime = (Get-Date) - $bootTimeFormatted
    $uptimeHours = [math]::Round($uptime.TotalHours, 2)

    # Create comprehensive performance object
    $perfData = @{
        timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        hostname = $env:COMPUTERNAME
        domain = $env:USERDOMAIN
        os_version = $memory.Caption
        cpu_percent = $cpuPercent
        memory_total_gb = [math]::Round($memTotalKB / 1MB, 2)
        memory_used_gb = [math]::Round($memUsedKB / 1MB, 2)
        memory_free_gb = [math]::Round($memFreeKB / 1MB, 2)
        memory_used_percent = $memUsedPercent
        disk_total_gb = $diskTotalGB
        disk_used_gb = $diskUsedGB
        disk_free_gb = $diskFreeGB
        disk_used_percent = $diskUsedPercent
        network_adapters_active = $activeNetworkCount
        uptime_hours = $uptimeHours
    }

    # Convert to JSON and write to file
    $json = $perfData | ConvertTo-Json -Compress
    $json | Out-File -FilePath $logFile -Append -Encoding UTF8

    # Log rotation - Clean old logs (older than 7 days) every hour at minute 0
    if ((Get-Date).Minute -eq 0) {
        try {
            $cutoffDate = (Get-Date).AddDays(-7)
            $oldLogs = Get-ChildItem -Path $logDir -Filter "performance_*.json" | Where-Object { $_.LastWriteTime -lt $cutoffDate }
            if ($oldLogs) {
                $oldLogs | Remove-Item -Force
                Write-Host "Cleaned $^($oldLogs.Count^) old log files"
            }
        } catch {
            # Silent cleanup failure
        }
    }

} catch {
    # Error handling - log errors to separate file
    try {
        $errorData = @{
            timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            hostname = $env:COMPUTERNAME
            error = $_.Exception.Message
            error_type = "performance_collection_failed"
        }
        $errorJson = $errorData | ConvertTo-Json -Compress
        $errorJson | Out-File -FilePath "$logDir\performance_errors_$today.json" -Append -Encoding UTF8
    } catch {
        # Silent error logging failure
    }
}
