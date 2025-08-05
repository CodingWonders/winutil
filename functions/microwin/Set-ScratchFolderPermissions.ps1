function Set-ScratchFolderPermissions {
    <#
    .SYNOPSIS
    Creates a scratch directory for DISM operations

    .DESCRIPTION
    This function simply creates a directory and removes read-only attributes.
    DISM handles its own permissions when running as Administrator.

    .PARAMETER Path
    The path to the directory to prepare
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        # Create directory if it doesn't exist
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
        }

        # Remove read-only attributes (this is the only thing that actually matters)
        & attrib -R "$Path" /S /D 2>$null

        return $true
    } catch {
        Write-Host "Failed to prepare directory $Path`: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}
