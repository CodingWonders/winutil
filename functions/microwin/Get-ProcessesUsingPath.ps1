function Get-ProcessesUsingPath {
    <#
    .SYNOPSIS
    Identifies processes that may be using files in a specific path

    .DESCRIPTION
    This function attempts to identify processes that have files open in the specified path,
    which can help diagnose unmount issues.

    .PARAMETER Path
    The path to check for process usage

    .EXAMPLE
    Get-ProcessesUsingPath -Path "F:\Scratch"
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    Write-Host "Checking for processes using path: $Path" -ForegroundColor Cyan

    $foundProcesses = @()

    try {
        # Method 1: Check process modules and loaded files
        $allProcesses = Get-Process -ErrorAction SilentlyContinue
        foreach ($process in $allProcesses) {
            try {
                if ($process.ProcessName -match "^(System|Idle)$") {
                    continue
                }

                # Check process modules
                try {
                    $modules = $process.Modules
                } catch {
                    $modules = $null
                }
                if ($modules) {
                    foreach ($module in $modules) {
                        if ($module.FileName -and $module.FileName.StartsWith($Path, [System.StringComparison]::OrdinalIgnoreCase)) {
                            $foundProcesses += @{
                                ProcessName = $process.ProcessName
                                PID = $process.Id
                                File = $module.FileName
                                Method = "Module"
                            }
                            break
                        }
                    }
                }

                # Check working directory
                try {
                    $startInfo = $process.StartInfo
                    if ($startInfo -and $startInfo.WorkingDirectory -and $startInfo.WorkingDirectory.StartsWith($Path, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $foundProcesses += @{
                            ProcessName = $process.ProcessName
                            PID = $process.Id
                            File = $startInfo.WorkingDirectory
                            Method = "WorkingDirectory"
                        }
                    }
                } catch {
                    # Ignore access denied
                }

            } catch {
                # Ignore processes we can't access
                continue
            }
        }

        # Method 2: Check common interfering processes
        $suspiciousProcesses = Get-Process -ErrorAction SilentlyContinue | Where-Object {
            $_.ProcessName -match "SearchIndexer|SearchProtocolHost|SearchFilterHost|MsMpEng|NisSrv|avp|avgnt|avast|mcshield|explorer"
        }

        if ($suspiciousProcesses) {
            Write-Host "`nPotentially interfering processes (may not be directly using the path):" -ForegroundColor Yellow
            foreach ($proc in $suspiciousProcesses) {
                Write-Host "  - $($proc.ProcessName) (PID: $($proc.Id))" -ForegroundColor Yellow
            }
        }

        # Display results
        if ($foundProcesses.Count -gt 0) {
            Write-Host "`nProcesses found using path:" -ForegroundColor Red
            foreach ($proc in $foundProcesses) {
                Write-Host "  - $($proc.ProcessName) (PID: $($proc.PID)) - $($proc.File) [$($proc.Method)]" -ForegroundColor Red
            }
        } else {
            Write-Host "No processes found directly using the specified path." -ForegroundColor Green
        }

        return $foundProcesses

    } catch {
        Write-Host "Error checking processes: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}
