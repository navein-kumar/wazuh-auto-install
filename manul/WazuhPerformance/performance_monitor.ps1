# Windows Performance Monitor for Wazuh - v2 Multi-Drive Support
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
    $cpuCores = 0
    try {
        $cpu = Get-WmiObject -Class Win32_Processor | Select-Object -First 1
        $cpuCores = $cpu.NumberOfLogicalProcessors
        if ($cpu.LoadPercentage) {
            $cpuPercent = $cpu.LoadPercentage
        } else {
            # Fallback to performance counter
            $perfCounter = Get-Counter "\Processor^(_Total^)\% Processor Time" -SampleInterval 1 -MaxSamples 1
            $cpuPercent = [math]::Round($perfCounter.CounterSamples[0].CookedValue, 0)
        }
    } catch {
        $cpuPercent = 0
    }
    $cpuFreePercent = 100 - $cpuPercent
    $cpuUsedCore = [math]::Round(($cpuPercent / 100) * $cpuCores, 0)
    $cpuFreeCore = $cpuCores - $cpuUsedCore

    # Get Memory information
    $memory = Get-WmiObject -Class Win32_OperatingSystem
    $memTotalKB = $memory.TotalVisibleMemorySize
    $memFreeKB = $memory.FreePhysicalMemory
    $memUsedKB = $memTotalKB - $memFreeKB
    $memUsedPercent = [math]::Round(($memUsedKB / $memTotalKB) * 100, 0)

    # Get ALL Disk information (Fixed drives only)
    $allDisks = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3"
    $diskHighest = 0
    $diskAlertDrive = ""
    $diskDetails = @()

    foreach ($disk in $allDisks) {
        $driveLetter = $disk.DeviceID -replace ":",""
        $diskTotalGB = [math]::Round($disk.Size / 1GB, 0)
        $diskFreeGB = [math]::Round($disk.FreeSpace / 1GB, 0)
        $diskUsedGB = $diskTotalGB - $diskFreeGB
        $diskUsedPercent = [math]::Round(($diskUsedGB / $diskTotalGB) * 100, 0)

        # Track highest disk usage for alert
        if ($diskUsedPercent -gt $diskHighest) {
            $diskHighest = $diskUsedPercent
            $diskAlertDrive = $driveLetter
        }

        $diskDetails += @{
            "drive" = $driveLetter
            "total_gb" = [string]$diskTotalGB
            "used_gb" = [string]$diskUsedGB
            "free_gb" = [string]$diskFreeGB
            "used_percent" = [string]$diskUsedPercent
        }
    }

    # Get Network adapters
    $networkAdapters = Get-WmiObject -Class Win32_NetworkAdapter -Filter "NetConnectionStatus=2"
    $activeNetworkCount = ($networkAdapters | Measure-Object).Count

    # Get System uptime
    $bootTime = (Get-WmiObject Win32_OperatingSystem).LastBootUpTime
    $bootTimeFormatted = [Management.ManagementDateTimeConverter]::ToDateTime($bootTime)
    $uptime = (Get-Date) - $bootTimeFormatted
    $uptimeHours = [math]::Round($uptime.TotalHours, 0)

    # Create comprehensive performance object with ordered output
    $perfData = [ordered]@{
        "wazuhlogtype" = "wazuhperformance"
        "log_timestamp" = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        "hostname" = $env:COMPUTERNAME
        "domain" = $env:USERDOMAIN
        "os_version" = $memory.Caption
        "cpu_total_core" = [string]$cpuCores
        "cpu_used_core" = [string]$cpuUsedCore
        "cpu_free_core" = [string]$cpuFreeCore
        "cpu_used_percent" = [string]$cpuPercent
        "memory_total_gb" = [string][math]::Round($memTotalKB / 1MB, 0)
        "memory_used_gb" = [string][math]::Round($memUsedKB / 1MB, 0)
        "memory_free_gb" = [string][math]::Round($memFreeKB / 1MB, 0)
        "memory_used_percent" = [string]$memUsedPercent
        "disk_highest_percent" = [string]$diskHighest
        "disk_alert_drive" = $diskAlertDrive
        "disk_count" = [string]$diskDetails.Count
        "network_adapters_active" = [string]$activeNetworkCount
        "uptime_hours" = [string]$uptimeHours
    }

    # Add individual disk details
    foreach ($d in $diskDetails) {
        $prefix = "disk_" + $d.drive.ToLower()
        $perfData["$prefix`_total_gb"] = $d.total_gb
        $perfData["$prefix`_used_gb"] = $d.used_gb
        $perfData["$prefix`_free_gb"] = $d.free_gb
        $perfData["$prefix`_used_percent"] = $d.used_percent
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
            "log_timestamp" = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            "hostname" = $env:COMPUTERNAME
            "error" = $_.Exception.Message
            "error_type" = "performance_collection_failed"
        }
        $errorJson = $errorData | ConvertTo-Json -Compress
        $errorJson | Out-File -FilePath "$logDir\performance_errors_$today.json" -Append -Encoding UTF8
    } catch {
        # Silent error logging failure
    }
}
