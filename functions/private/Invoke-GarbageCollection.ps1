function Invoke-GarbageCollection {
    <#
    .SYNOPSIS
    Forces garbage collection to release file handles and free memory

    .DESCRIPTION
    This function performs a complete garbage collection cycle to help release
    file handles that might be keeping files or directories locked.

    .PARAMETER WaitSeconds
    Optional wait time after garbage collection (default: 0)

    .EXAMPLE
    Invoke-GarbageCollection

    .EXAMPLE
    Invoke-GarbageCollection -WaitSeconds 2
    #>
    param(
        [int]$WaitSeconds = 0
    )

    try {
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        [System.GC]::Collect()

        if ($WaitSeconds -gt 0) {
            Start-Sleep -Seconds $WaitSeconds
        }
    } catch {
        # Ignore GC errors - not critical
    }
}
