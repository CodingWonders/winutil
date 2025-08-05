function Set-ScratchFolderPermissions {
    <#
    .SYNOPSIS
    Sets DISM-compatible permissions on any directory

    .DESCRIPTION
    This function sets proper permissions on a directory to make it compatible with DISM operations

    .PARAMETER Path
    The path to the directory to set permissions on

    .PARAMETER ShowPermissions
    Switch to display the current permissions after setting them
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [switch]$ShowPermissions
    )

function Set-DismCompatiblePermissions {
    param([string]$Path)

    # Log which user is setting permissions and which folder
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    Write-Host "Current user setting permissions: $currentUser for folder: $Path" -ForegroundColor Magenta

    # Remove ReadOnly attribute from install.wim and boot.wim in the scratch folder
    $wimFiles = @('install.wim', 'boot.wim')
    Write-Host "Removing ReadOnly attributes from WIM files before mount..." -ForegroundColor Yellow
    $wimFilesProcessed = 0
    $wimFilesFound = 0

    foreach ($wim in $wimFiles) {
        $wimPath = Join-Path $Path $wim
        if (Test-Path $wimPath) {
            $wimFilesFound++
            $item = Get-Item -Path $wimPath -Force
            if ($item.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
                try {
                    $item.Attributes = $item.Attributes -band (-bnot [System.IO.FileAttributes]::ReadOnly)
                    # Verify the change was successful
                    $item.Refresh()
                    if ($item.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
                        Write-Host "CRITICAL: Failed to remove ReadOnly attribute from $wimPath - mount will fail" -ForegroundColor Red
                        Write-Host "Cannot proceed with mount operation. Exiting." -ForegroundColor Red
                        return $false
                    }
                    Write-Host "Removed ReadOnly attribute from $wimPath" -ForegroundColor Green
                    $wimFilesProcessed++
                } catch {
                    Write-Host "CRITICAL: Unable to modify ReadOnly attribute on $wimPath - $($_.Exception.Message)" -ForegroundColor Red
                    Write-Host "Cannot proceed with mount operation. Exiting." -ForegroundColor Red
                    return $false
                }
            } else {
                Write-Host "$wimPath is already writable" -ForegroundColor Yellow
                $wimFilesProcessed++
            }
            Write-Host ("Current attributes for {0}: {1}" -f $wimPath, $item.Attributes) -ForegroundColor Cyan
        } else {
            Write-Host "$wimPath not found in scratch folder" -ForegroundColor Red
        }
    }

    # If we found WIM files but couldn't process them all, exit
    if ($wimFilesFound -gt 0 -and $wimFilesProcessed -ne $wimFilesFound) {
        Write-Host "CRITICAL: Could not make all WIM files writable. Mount operation aborted." -ForegroundColor Red
        return $false
    }

    if ($wimFilesFound -eq 0) {
        Write-Host "No WIM files found in scratch folder - proceeding with folder permissions only" -ForegroundColor Yellow
    } else {
        Write-Host "Successfully processed $wimFilesProcessed WIM file(s) - ready for mount" -ForegroundColor Green
    }
    try {
        Write-Host "Setting DISM-compatible permissions on: $Path" -ForegroundColor Green

        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
            Write-Host "Created directory: $Path" -ForegroundColor Yellow
        }

        # Remove read-only attribute from the directory and all subdirectories
        try {
            Write-Host "Removing read-only attributes from directory and contents..." -ForegroundColor Yellow

            # Remove read-only from the main directory
            $item = Get-Item -Path $Path -Force
            if ($item.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
                $item.Attributes = $item.Attributes -band (-bnot [System.IO.FileAttributes]::ReadOnly)
                Write-Host "Removed read-only attribute from directory: $Path" -ForegroundColor Yellow
            }

            # Use attrib command to remove read-only from folder and all contents recursively
            # This is more reliable than PowerShell for folder attributes
            try {
                & attrib -R "$Path" /S /D 2>$null
                Write-Host "Successfully removed read-only attributes using attrib command" -ForegroundColor Green
            } catch {
                Write-Host "Warning: attrib command failed, using PowerShell fallback" -ForegroundColor Yellow

                # PowerShell fallback - remove read-only from any existing subdirectories and files
                Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    if ($_.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
                        $_.Attributes = $_.Attributes -band (-bnot [System.IO.FileAttributes]::ReadOnly)
                    }
                }
            }
        } catch {
            Write-Host "Warning: Could not modify read-only attributes: $($_.Exception.Message)" -ForegroundColor Yellow
        }        $acl = Get-Acl -Path $Path

        # Remove inherited permissions and set explicit ones
        $acl.SetAccessRuleProtection($true, $false)

        # Clear all existing access rules by creating a new ACL with only essential rules
        # This is more reliable than trying to remove individual rules
        try {
            # Get the current owner
            $owner = $acl.Owner

            # Create a fresh ACL object
            $newAcl = New-Object System.Security.AccessControl.DirectorySecurity
            $newAcl.SetOwner($acl.Owner)
            $newAcl.SetAccessRuleProtection($true, $false)

            # Use the fresh ACL instead of trying to modify the existing one
            $acl = $newAcl
            Write-Host "Created fresh ACL for directory" -ForegroundColor Green
        } catch {
            Write-Host "Warning: Could not create fresh ACL, attempting manual rule removal" -ForegroundColor Yellow

            # Fallback: Try to remove rules one by one with better error handling
            $accessRules = @($acl.Access)  # Create array copy to avoid collection modification issues
            foreach ($rule in $accessRules) {
                if ($rule -ne $null -and $rule.GetType().Name -eq "FileSystemAccessRule") {
                    try {
                        $acl.RemoveAccessRule($rule) | Out-Null
                    } catch {
                        # Ignore individual rule removal failures
                        Write-Host "Skipped removing rule for: $($rule.IdentityReference)" -ForegroundColor Gray
                    }
                }
            }
        }

        # Administrators - Full Control
        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $acl.SetAccessRule($adminRule)

        # SYSTEM - Full Control
        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $acl.SetAccessRule($systemRule)

        # Current User - Full Control
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        Write-Host "Setting Full Control permissions for current user: $currentUser" -ForegroundColor Cyan
        $userRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $currentUser, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $acl.SetAccessRule($userRule)

        # Current User - Full Control
        $everyoneRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "Everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $acl.SetAccessRule($everyoneRule)

        # Authenticated Users - Modify (subfolders and files only)
        $authUsersRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "Authenticated Users", "Modify", "ContainerInherit,ObjectInherit", "InheritOnly", "Allow"
        )
        $acl.SetAccessRule($authUsersRule)

        # Authenticated Users - Create folders/append data (this folder only)
        $authUsersThisFolderRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "Authenticated Users", "CreateDirectories,AppendData", "None", "None", "Allow"
        )
        $acl.SetAccessRule($authUsersThisFolderRule)

        Set-Acl -Path $Path -AclObject $acl
        Write-Host "Successfully applied DISM-compatible permissions to: $Path" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "Failed to set permissions on $Path`: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Main execution
Write-Host "=== DISM-Compatible Permission Setter ===" -ForegroundColor Cyan
Write-Host ""

# Show who is running the commands
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
Write-Host "Running as user: $currentUser" -ForegroundColor Yellow
if ($isAdmin) {
    Write-Host "Administrator privileges: Yes" -ForegroundColor Green
} else {
    Write-Host "Administrator privileges: No" -ForegroundColor Red
}
Write-Host ""

# Apply permissions
$success = Set-DismCompatiblePermissions -Path $Path

if ($success -and $ShowPermissions) {
    Write-Host ""
    Write-Host "Current permissions on $Path`:" -ForegroundColor Cyan
    $acl = Get-Acl -Path $Path
    foreach ($access in $acl.Access) {
        $color = switch ($access.AccessControlType) {
            "Allow" { "Green" }
            "Deny" { "Red" }
            default { "White" }
        }
        Write-Host "  $($access.IdentityReference): $($access.FileSystemRights) ($($access.AccessControlType))" -ForegroundColor $color
    }
}

Write-Host ""
if ($success) {
    Write-Host "✅ Permissions applied successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "This directory now has the same permissions as a working DISM scratch folder:" -ForegroundColor Cyan
    Write-Host "• Administrators: Full control" -ForegroundColor White
    Write-Host "• SYSTEM: Full control" -ForegroundColor White
    Write-Host "• Current User ($([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)): Full control" -ForegroundColor White
    Write-Host "• Authenticated Users: Modify (subfolders and files only)" -ForegroundColor White
    Write-Host "• Authenticated Users: Create folders/append data (this folder only)" -ForegroundColor White
} else {
    Write-Host "❌ Failed to apply permissions. Check the error messages above." -ForegroundColor Red
}

    return $success
}
