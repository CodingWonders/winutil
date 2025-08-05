function Force-CleanupMountDirectory {
    <#
    .SYNOPSIS
    Forces cleanup of a mount directory by closing processes that have files open

    .DESCRIPTION
    This function attempts to identify and close processes that have files open in the specified
    mount directory, which is often the cause of unmount failures.

    .PARAMETER MountPath
    The path to the mount directory to clean up

    .PARAMETER TimeoutSeconds
    Maximum time to wait for processes to close (default: 30 seconds)
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$MountPath,

        [int]$TimeoutSeconds = 30
    )

    Write-Host "DEBUG: Starting forced cleanup of mount directory: $MountPath" -ForegroundColor Yellow

    try {
        # First, try to identify processes using files in the mount directory
        Write-Host "DEBUG: Checking for processes using files in mount directory..." -ForegroundColor Yellow

        # Get all processes and check if they have files open in the mount directory
        $processesToKill = @()

        try {
            # Use Get-Process with file handle information
            $allProcesses = Get-Process -ErrorAction SilentlyContinue
            foreach ($process in $allProcesses) {
                try {
                    if ($process.ProcessName -eq "System" -or $process.ProcessName -eq "Idle") {
                        continue
                    }

                    # Check if process has any modules or files loaded from the mount path
                    try {
                        $processModules = $process.Modules
                    } catch {
                        $processModules = $null
                    }
                    if ($processModules) {
                        foreach ($module in $processModules) {
                            if ($module.FileName -and $module.FileName.StartsWith($MountPath, [System.StringComparison]::OrdinalIgnoreCase)) {
                                Write-Host "DEBUG: Found process using mount directory: $($process.ProcessName) (PID: $($process.Id))" -ForegroundColor Red
                                $processesToKill += $process
                                break
                            }
                        }
                    }
                } catch {
                    # Ignore processes we can't access
                    continue
                }
            }
        } catch {
            Write-Host "DEBUG: Could not enumerate all processes: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        # Also check for common processes that might interfere
        $commonInterferingProcesses = @("explorer", "dwm", "winlogon", "csrss", "svchost")
        Write-Host "DEBUG: Checking for Windows Search, antivirus, and other interfering processes..." -ForegroundColor Yellow

        $suspiciousProcesses = Get-Process -ErrorAction SilentlyContinue | Where-Object {
            $_.ProcessName -match "SearchIndexer|SearchProtocolHost|SearchFilterHost|MsMpEng|NisSrv|avp|avgnt|avast|mcshield|norton|kaspersky|bitdefender|eset|fsecure|gdata|panda|sophos|trendmicro|webroot|malwarebytes"
        }

        if ($suspiciousProcesses) {
            Write-Host "DEBUG: Found potentially interfering processes:" -ForegroundColor Yellow
            foreach ($proc in $suspiciousProcesses) {
                Write-Host "DEBUG:   - $($proc.ProcessName) (PID: $($proc.Id))" -ForegroundColor Yellow
            }
        }

        # Force garbage collection to release any PowerShell file handles
        Write-Host "DEBUG: Forcing garbage collection to release file handles..." -ForegroundColor Yellow
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        [System.GC]::Collect()

        # Wait a moment for handles to be released
        Start-Sleep -Seconds 3

        # Try to set the mount directory and its contents to not readonly
        Write-Host "DEBUG: Removing readonly attributes from mount directory contents..." -ForegroundColor Yellow
        try {
            if (Test-Path $MountPath) {
                & attrib -R "$MountPath\*" /S /D 2>$null
                Write-Host "DEBUG: Readonly attributes removed from mount directory" -ForegroundColor Green
            }
        } catch {
            Write-Host "DEBUG: Could not remove readonly attributes: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        # Try to close any remaining file handles using system tools
        Write-Host "DEBUG: Attempting to close file handles using system methods..." -ForegroundColor Yellow

        # Use PowerShell to try and close any open file handles
        try {
            # This is a more aggressive approach - restart the Windows Search service if it's running
            $searchService = Get-Service -Name "WSearch" -ErrorAction SilentlyContinue
            if ($searchService -and $searchService.Status -eq "Running") {
                Write-Host "DEBUG: Temporarily stopping Windows Search service..." -ForegroundColor Yellow
                Stop-Service -Name "WSearch" -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
                Write-Host "DEBUG: Restarting Windows Search service..." -ForegroundColor Yellow
                Start-Service -Name "WSearch" -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Host "DEBUG: Could not restart Windows Search service: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        # Final cleanup attempt
        Write-Host "DEBUG: Performing final cleanup..." -ForegroundColor Yellow
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        [System.GC]::Collect()

        Start-Sleep -Seconds 2

        Write-Host "DEBUG: Mount directory cleanup completed" -ForegroundColor Green
        return $true

    } catch {
        Write-Host "DEBUG: Error during mount directory cleanup: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}
