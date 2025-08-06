function Force-CleanupMountDirectory {
    <#
    .SYNOPSIS
    Forces cleanup of a mount directory by closing processes that have files open

    .DESCRIPTION
    This function attempts to clean up a mount directory by unloading registry hives,
    releasing file handles, and removing readonly attributes.

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

    try {
        # Attempt to unload any registry hives that might still be loaded
        $hiveNames = @("HKLM\zCOMPONENTS", "HKLM\zDEFAULT", "HKLM\zNTUSER", "HKLM\zSOFTWARE", "HKLM\zSYSTEM")
        foreach ($hiveName in $hiveNames) {
            try {
                $null = reg query $hiveName 2>$null
                if ($LASTEXITCODE -eq 0) {
                    # Registry hive is loaded, try to unload it with retries
                    $attempts = 0
                    $maxAttempts = 10
                    do {
                        $attempts++
                        reg unload $hiveName 2>$null
                        if ($LASTEXITCODE -eq 0) {
                            break
                        }
                        Start-Sleep -Milliseconds 100
                    } until ($attempts -ge $maxAttempts)
                }
            } catch {
                # Hive not loaded or error checking - continue
            }
        }

        # Force garbage collection to release any PowerShell file handles
        Invoke-GarbageCollection -WaitSeconds 2

        # Try to set the mount directory and its contents to not readonly
        try {
            if (Test-Path "$MountPath") {
                & attrib -R "$MountPath\*" /S /D 2>$null
            }
        } catch {
            # Ignore attrib errors
        }

        # Restart Windows Search service if it's running (helps release file handles)
        try {
            $searchService = Get-Service -Name "WSearch" -ErrorAction SilentlyContinue
            if ($searchService -and $searchService.Status -eq "Running") {
                Stop-Service -Name "WSearch" -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 1
                Start-Service -Name "WSearch" -ErrorAction SilentlyContinue
            }
        } catch {
            # Ignore service restart errors
        }

        # Final cleanup
        Invoke-GarbageCollection

        return $true

    } catch {
        return $false
    }
}
