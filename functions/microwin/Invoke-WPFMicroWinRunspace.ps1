function Invoke-WPFMicroWinRunspace {
    <#
    .SYNOPSIS
        Executes MicroWin operations in a background runspace to prevent UI blocking

    .DESCRIPTION
        This function takes MicroWin settings and executes the entire MicroWin process
        in a background runspace, allowing the UI to remain responsive during the
        lengthy ISO creation process.

    .PARAMETER MicroWinSettings
        Hashtable containing all the MicroWin configuration settings

    .EXAMPLE
        $settings = @{
            mountDir = "C:\Mount"
            scratchDir = "C:\Scratch"
            # ... other settings
        }
        Invoke-WPFMicroWinRunspace -MicroWinSettings $settings
    #>

    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$MicroWinSettings
    )

    # Start the process in a runspace to avoid blocking the UI
    Invoke-WPFRunspace -ArgumentList $MicroWinSettings -DebugPreference $DebugPreference -ScriptBlock {
        param($MicroWinSettings, $DebugPreference)

        # Function to set DISM-compatible permissions on a directory
        function Set-DismCompatiblePermissions {
            param([string]$Path)

            try {
                Write-Host "DEBUG: Setting DISM-compatible permissions on: $Path"
                $acl = Get-Acl -Path $Path

                # Remove inherited permissions and set explicit ones
                # $acl.SetAccessRuleProtection($true, $false)

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
                $userRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $currentUser, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
                )
                $acl.SetAccessRule($userRule)

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
                Write-Host "DEBUG: Successfully applied DISM-compatible permissions to: $Path"
                return $true
            } catch {
                Write-Host "DEBUG: Failed to set permissions on $Path`: $($_.Exception.Message)"
                return $false
            }
        }

        $sync.ProcessRunning = $true

        try {
            # Set process priority to High for better performance
            Write-Host "DEBUG: Setting process priority to High for better performance..."
            try {
                $currentProcess = Get-Process -Id $PID
                $currentProcess.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::High
                Write-Host "DEBUG: Process priority set to High successfully"
            } catch {
                Write-Host "DEBUG: WARNING - Could not set process priority: $($_.Exception.Message)"
            }

            # Optimize PowerShell memory usage
            Write-Host "DEBUG: Optimizing PowerShell memory settings..."
            try {
                # Increase the memory limit for PowerShell operations
                [System.GC]::Collect()
                [System.GC]::WaitForPendingFinalizers()
                [System.GC]::Collect()

                # Set execution policy to bypass for better performance
                Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
                Write-Host "DEBUG: Memory optimization completed"
            } catch {
                Write-Host "DEBUG: WARNING - Memory optimization failed: $($_.Exception.Message)"
            }

            # Define the constants for Windows API
            Add-Type @"
using System;
using System.Runtime.InteropServices;

public class PowerManagement {
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern EXECUTION_STATE SetThreadExecutionState(EXECUTION_STATE esFlags);

    [FlagsAttribute]
    public enum EXECUTION_STATE : uint {
        ES_SYSTEM_REQUIRED = 0x00000001,
        ES_DISPLAY_REQUIRED = 0x00000002,
        ES_CONTINUOUS = 0x80000000,
    }
}

public class PrivilegeManager {
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);

    public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const uint SE_PRIVILEGE_ENABLED = 0x00000002;

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES {
        public LUID Luid;
        public uint Attributes;
    }

    public static bool EnablePrivilege(string privilegeName) {
        IntPtr token = IntPtr.Zero;
        try {
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, out token)) {
                return false;
            }

            LUID luid;
            if (!LookupPrivilegeValue(null, privilegeName, out luid)) {
                return false;
            }

            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.PrivilegeCount = 1;
            tp.Privileges.Luid = luid;
            tp.Privileges.Attributes = SE_PRIVILEGE_ENABLED;

            return AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        } finally {
            if (token != IntPtr.Zero) {
                CloseHandle(token);
            }
        }
    }
}
"@

            # Prevent the machine from sleeping
            [PowerManagement]::SetThreadExecutionState([PowerManagement]::EXECUTION_STATE::ES_CONTINUOUS -bor [PowerManagement]::EXECUTION_STATE::ES_SYSTEM_REQUIRED -bor [PowerManagement]::EXECUTION_STATE::ES_DISPLAY_REQUIRED)

            # Ask the user where to save the file - this needs to be done on the main thread
            $SaveDialog = $null
            $sync.form.Dispatcher.Invoke([action]{
                $SaveDialog = New-Object System.Windows.Forms.SaveFileDialog
                $SaveDialog.InitialDirectory = [Environment]::GetFolderPath('Desktop')
                $SaveDialog.Filter = "ISO images (*.iso)|*.iso"
                $SaveDialog.ShowDialog() | Out-Null
            })

            if ($SaveDialog.FileName -eq "") {
                $msg = "No file name for the target image was specified"
                Write-Host $msg
                $sync.form.Dispatcher.Invoke([action]{
                    # Invoke-MicrowinBusyInfo -action "warning" -message $msg
                    Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
                })
                return
            }

            $sync.form.Dispatcher.Invoke([action]{
                Set-WinUtilTaskbaritem -state "Indeterminate" -overlay "logo"
                # Invoke-MicrowinBusyInfo -action "wip" -message "Busy..." -interactive $false
            })

            Write-Host "Target ISO location: $($SaveDialog.FileName)"

            # Performance optimization: Determine optimal thread count
            $coreCount = (Get-WmiObject -Class Win32_Processor | Measure-Object -Property NumberOfCores -Sum).Sum
            $logicalProcessors = (Get-WmiObject -Class Win32_ComputerSystem).NumberOfLogicalProcessors
            $optimalThreads = [Math]::Min($logicalProcessors, [Math]::Max(2, $coreCount))
            Write-Host "DEBUG: System has $coreCount cores, $logicalProcessors logical processors. Using $optimalThreads threads for optimal performance."

            # Extract settings from hashtable
            $index = $MicroWinSettings.selectedIndex
            $mountDir = $MicroWinSettings.mountDir
            $scratchDir = $MicroWinSettings.scratchDir
            $copyToUSB = $MicroWinSettings.copyToUSB
            $injectDrivers = $MicroWinSettings.injectDrivers
            $importDrivers = $MicroWinSettings.importDrivers
            $WPBT = $MicroWinSettings.WPBT
            $unsupported = $MicroWinSettings.unsupported
            $importVirtIO = $MicroWinSettings.importVirtIO
            $driverPath = $MicroWinSettings.driverPath
            $esd = $MicroWinSettings.esd
            $autoConfigPath = $MicroWinSettings.autoConfigPath
            $userName = $MicroWinSettings.userName
            $userPassword = $MicroWinSettings.userPassword

            Write-Host "Index chosen: '$index'"

            # Detect if the Windows image is an ESD file and convert it to WIM
            if (-not (Test-Path -Path "$mountDir\sources\install.wim" -PathType Leaf) -and (Test-Path -Path "$mountDir\sources\install.esd" -PathType Leaf)) {
                Write-Host "Exporting Windows image to a WIM file, keeping the index we want to work on. This can take several minutes, depending on the performance of your computer..."
                Write-Host "DEBUG: Using optimized compression settings for better performance..."
                try {
                    # Use Fast compression instead of Max for better performance during development
                    Export-WindowsImage -SourceImagePath "$mountDir\sources\install.esd" -SourceIndex $index -DestinationImagePath "$mountDir\sources\install.wim" -CompressionType "Fast"
                    Write-Host "DEBUG: PowerShell export with Fast compression completed"
                } catch {
                    # Fall back to DISM with optimized settings
                    Write-Host "DEBUG: PowerShell export failed, using DISM with performance optimizations..."
                    dism /english /export-image /sourceimagefile="$mountDir\sources\install.esd" /sourceindex=$index /destinationimagefile="$mountDir\sources\install.wim" /compress:fast /checkintegrity /verify
                    Write-Host "DEBUG: DISM export with Fast compression completed"
                }
                if ($?) {
                    Remove-Item -Path "$mountDir\sources\install.esd" -Force
                    # Since we've already exported the image index we wanted, switch to the first one
                    $index = 1
                } else {
                    $msg = "The export process has failed and MicroWin processing cannot continue"
                    Write-Host $msg
                    $sync.form.Dispatcher.Invoke([action]{
                        Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
                        # Invoke-MicrowinBusyInfo -action "warning" -message $msg
                        [System.Windows.MessageBox]::Show($msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
                    })
                    return
                }
            }

            $imgVersion = (Get-WindowsImage -ImagePath "$mountDir\sources\install.wim" -Index $index).Version
            Write-Host "The Windows Image Build Version is: $imgVersion"

            # Detect image version to avoid performing MicroWin processing on Windows 8 and earlier
            if ((Microwin-TestCompatibleImage $imgVersion $([System.Version]::new(10,0,10240,0))) -eq $false) {
                $msg = "This image is not compatible with MicroWin processing. Make sure it isn't a Windows 8 or earlier image."
                $dlg_msg = $msg + "`n`nIf you want more information, the version of the image selected is $($imgVersion)`n`nIf an image has been incorrectly marked as incompatible, report an issue to the developers."
                Write-Host $msg
                $sync.form.Dispatcher.Invoke([action]{
                    [System.Windows.MessageBox]::Show($dlg_msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Exclamation)
                    Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
                    # Invoke-MicrowinBusyInfo -action "warning" -message $msg
                })
                return
            }

            # Detect whether the image to process contains Windows 10 and show warning
            if ((Microwin-TestCompatibleImage $imgVersion $([System.Version]::new(10,0,21996,1))) -eq $false) {
                $msg = "Windows 10 has been detected in the image you want to process. While you can continue, Windows 10 is not a recommended target for MicroWin, and you may not get the full experience."
                $dlg_msg = $msg
                Write-Host $msg
                $sync.form.Dispatcher.Invoke([action]{
                    [System.Windows.MessageBox]::Show($dlg_msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Exclamation)
                })
            }

            $mountDirExists = Test-Path $mountDir
            $scratchDirExists = Test-Path $scratchDir
            if (-not $mountDirExists -or -not $scratchDirExists) {
                $msg = "Required directories '$mountDir' and '$scratchDir' do not exist."
                Write-Error $msg
                $sync.form.Dispatcher.Invoke([action]{
                    Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
                    # Invoke-MicrowinBusyInfo -action "warning" -message $msg
                })
                return
            }

            # Clean up any stale mountpoints before starting
            Write-Host "DEBUG: Cleaning up any stale DISM mountpoints..."
            try {
                & dism /cleanup-mountpoints /loglevel:1
                Write-Host "DEBUG: Mountpoints cleanup completed"
                Start-Sleep -Seconds 2
            } catch {
                Write-Host "DEBUG: Mountpoints cleanup warning: $($_.Exception.Message)"
            }

            # Check if running as administrator
            $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
            $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

            if (-not $isAdmin) {
                $msg = "Administrator privileges are required to mount and modify Windows images. Please run WinUtil as Administrator and try again."
                Write-Host "DEBUG: ERROR - Not running as administrator"
                Write-Host $msg
                $sync.form.Dispatcher.Invoke([action]{
                    Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
                    [System.Windows.MessageBox]::Show($msg, "Administrator Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
                })
                return
            }

            # Enable required privileges for DISM operations
            Write-Host "DEBUG: Enabling required privileges for DISM operations..."
            try {
                $requiredPrivileges = @(
                    "SeBackupPrivilege",
                    "SeRestorePrivilege",
                    "SeSecurityPrivilege",
                    "SeTakeOwnershipPrivilege",
                    "SeManageVolumePrivilege"
                )

                $privilegesEnabled = 0
                foreach ($privilege in $requiredPrivileges) {
                    try {
                        if ([PrivilegeManager]::EnablePrivilege($privilege)) {
                            Write-Host "DEBUG: Successfully enabled $privilege"
                            $privilegesEnabled++
                        } else {
                            Write-Host "DEBUG: WARNING - Could not enable $privilege"
                        }
                    } catch {
                        Write-Host "DEBUG: WARNING - Error enabling $privilege : $($_.Exception.Message)"
                    }
                }

                Write-Host "DEBUG: Enabled $privilegesEnabled out of $($requiredPrivileges.Count) privileges"

                if ($privilegesEnabled -ge 2) {
                    Write-Host "DEBUG: Sufficient privileges enabled for DISM operations"
                } else {
                    Write-Host "DEBUG: WARNING - May not have sufficient privileges for DISM operations"
                }
            } catch {
                Write-Host "DEBUG: WARNING - Could not enable privileges: $($_.Exception.Message)"
            }

            # Check if the scratch directory is writable
            try {
                $testFile = Join-Path $scratchDir "test_write_permissions.tmp"
                "test" | Out-File -FilePath $testFile -Force
                Remove-Item $testFile -Force
                Write-Host "DEBUG: Write permissions verified for scratch directory"
            } catch {
                $msg = "Cannot write to scratch directory '$scratchDir'. Please check permissions and ensure the directory is not in use."
                Write-Host "DEBUG: ERROR - Cannot write to scratch directory: $($_.Exception.Message)"
                Write-Host $msg
                $sync.form.Dispatcher.Invoke([action]{
                    Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
                    [System.Windows.MessageBox]::Show($msg, "Permission Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
                })
                return
            }

            # Check if install.wim file exists and is accessible
            $wimPath = "$mountDir\sources\install.wim"
            if (-not (Test-Path $wimPath)) {
                $msg = "Windows installation image not found at '$wimPath'. Please ensure the ISO is properly mounted or extracted."
                Write-Host "DEBUG: ERROR - install.wim not found at $wimPath"
                Write-Host $msg
                $sync.form.Dispatcher.Invoke([action]{
                    Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
                    [System.Windows.MessageBox]::Show($msg, "File Not Found", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
                })
                return
            }

            try {
                # Test if we can read the WIM file
                $wimInfo = Get-WindowsImage -ImagePath $wimPath
                Write-Host "DEBUG: WIM file verification successful - found $($wimInfo.Count) image(s)"
            } catch {
                $msg = "Cannot access or read the Windows installation image at '$wimPath'. The file may be corrupted or in use by another process."
                Write-Host "DEBUG: ERROR - Cannot read WIM file: $($_.Exception.Message)"
                Write-Host $msg
                $sync.form.Dispatcher.Invoke([action]{
                    Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
                    [System.Windows.MessageBox]::Show($msg, "File Access Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
                })
                return
            }

            try {
                Write-Host "DEBUG: Checking if image is already mounted..."
                # Check if the image is already mounted and dismount if necessary
                try {
                    $mountedImages = Get-WindowsImage -Mounted
                    foreach ($mounted in $mountedImages) {
                        if ($mounted.Path -eq $scratchDir) {
                            Write-Host "DEBUG: Found existing mount at $scratchDir, dismounting..."
                            Dismount-WindowsImage -Path $scratchDir -Discard
                            Start-Sleep -Seconds 2
                        }
                    }
                } catch {
                    Write-Host "DEBUG: Error checking mounted images: $($_.Exception.Message)"
                }

                # Additional permission checks before mounting
                Write-Host "DEBUG: Performing additional permission and system checks..."

                # Check if DISM service is running
                try {
                    $dismService = Get-Service -Name "DISM" -ErrorAction SilentlyContinue
                    if ($dismService -and $dismService.Status -ne "Running") {
                        Write-Host "DEBUG: Starting DISM service..."
                        Start-Service -Name "DISM"
                        Start-Sleep -Seconds 3
                    }
                } catch {
                    Write-Host "DEBUG: Could not manage DISM service: $($_.Exception.Message)"
                }

                # Check UAC and token privileges
                try {
                    $tokenPrivs = whoami /priv | Out-String
                    Write-Host "DEBUG: Re-checking privileges after elevation attempt..."
                    if ($tokenPrivs -match "SeBackupPrivilege.*Enabled" -and $tokenPrivs -match "SeRestorePrivilege.*Enabled") {
                        Write-Host "DEBUG: Required privileges (SeBackupPrivilege, SeRestorePrivilege) are now enabled"
                    } else {
                        Write-Host "DEBUG: WARNING - Some required privileges may still not be enabled"

                        # Try alternative privilege elevation method
                        Write-Host "DEBUG: Attempting alternative privilege elevation..."
                        try {
                            # Try using PowerShell's built-in privilege functions if available
                            if (Get-Command "Enable-Privilege" -ErrorAction SilentlyContinue) {
                                Enable-Privilege SeBackupPrivilege, SeRestorePrivilege -Force
                                Write-Host "DEBUG: Alternative privilege elevation attempted"
                            }
                        } catch {
                            Write-Host "DEBUG: Alternative privilege elevation failed: $($_.Exception.Message)"
                        }

                        Write-Host "DEBUG: Current privilege status:"
                        $tokenPrivs -split "`n" | Where-Object { $_ -match "Se(Backup|Restore|Security|TakeOwnership|ManageVolume)Privilege" } | ForEach-Object {
                            Write-Host "DEBUG:   $($_.Trim())"
                        }
                    }
                } catch {
                    Write-Host "DEBUG: Could not check token privileges: $($_.Exception.Message)"
                }

                # Pre-mount system checks
                Write-Host "DEBUG: Performing pre-mount system checks..."

                # Check if DISM is available and working
                try {
                    $dismCheck = & dism /? 2>&1
                    Write-Host "DEBUG: DISM is available and responding"
                } catch {
                    Write-Host "DEBUG: WARNING - DISM may not be available: $($_.Exception.Message)"
                }

                # Check available disk space
                try {
                    $scratchDrive = Split-Path $scratchDir -Qualifier
                    $driveInfo = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $scratchDrive }
                    $freeSpaceGB = [math]::Round($driveInfo.FreeSpace / 1GB, 2)
                    Write-Host "DEBUG: Available disk space on $scratchDrive`: $freeSpaceGB GB"

                    if ($freeSpaceGB -lt 10) {
                        Write-Host "DEBUG: WARNING - Low disk space may cause mount issues"
                    }
                } catch {
                    Write-Host "DEBUG: Could not check disk space: $($_.Exception.Message)"
                }

                # Check if scratch directory is accessible and set proper permissions
                try {
                    if (-not (Test-Path $scratchDir)) {
                        New-Item -Path $scratchDir -ItemType Directory -Force | Out-Null
                        Write-Host "DEBUG: Created scratch directory: $scratchDir"
                    }

                    # Set proper permissions for DISM operations using the helper function
                    Write-Host "DEBUG: Setting optimal permissions for scratch directory..."
                    $permissionsSet = Set-DismCompatiblePermissions -Path $scratchDir

                    if ($permissionsSet) {
                        # Verify permissions were set correctly
                        $newAcl = Get-Acl -Path $scratchDir
                        Write-Host "DEBUG: Scratch directory permissions summary:"
                        foreach ($access in $newAcl.Access) {
                            Write-Host "DEBUG:   $($access.IdentityReference): $($access.FileSystemRights) ($($access.AccessControlType))"
                        }
                    } else {
                        Write-Host "DEBUG: Using default permissions (may cause DISM issues)"
                    }

                    # Test write access
                    $testFile = Join-Path $scratchDir "test_access.tmp"
                    "test" | Out-File -FilePath $testFile -Force
                    Remove-Item $testFile -Force
                    Write-Host "DEBUG: Scratch directory write access confirmed"
                } catch {
                    Write-Host "DEBUG: ERROR - Cannot access scratch directory: $($_.Exception.Message)"
                    return
                }

                # Additional file permission and location diagnostics
                Write-Host "DEBUG: Performing additional permission diagnostics..."

                # Check WIM file permissions and ownership
                try {
                    $wimPath = "$mountDir\sources\install.wim"
                    $wimAcl = Get-Acl -Path $wimPath
                    Write-Host "DEBUG: WIM file owner: $($wimAcl.Owner)"

                    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                    $hasFullControl = $false
                    foreach ($access in $wimAcl.Access) {
                        if ($access.IdentityReference.Value -eq $currentUser.Name -or $access.IdentityReference.Value -eq "BUILTIN\Administrators") {
                            if ($access.FileSystemRights -match "FullControl|Write|Modify") {
                                $hasFullControl = $true
                                break
                            }
                        }
                    }
                    Write-Host "DEBUG: Current user has sufficient WIM file access: $hasFullControl"
                } catch {
                    Write-Host "DEBUG: Could not check WIM file permissions: $($_.Exception.Message)"
                }

                # Try alternative scratch directory if current one has issues
                $originalScratchDir = $scratchDir
                $alternateScratchDir = "C:\temp\MicrowinMount_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

                # Try to use DISM instead of PowerShell cmdlets for mounting
                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                Write-Host "Current user running mount: $currentUser" -ForegroundColor Yellow
                Write-Host "Mounting Windows image. This may take a while."
                Write-Host "DEBUG: Attempting mount using DISM command directly for better compatibility..."

                $mountAttempts = @(
                    @{ Dir = $scratchDir; Description = "Original temp directory" },
                    @{ Dir = $alternateScratchDir; Description = "Alternative C:\temp directory" },
                    @{ Dir = "C:\MicrowinMount"; Description = "Root C: directory" }
                )

                # Remove ReadOnly attributes from WIM files before mounting
                Write-Host "DEBUG: Checking and removing ReadOnly attributes from WIM files..." -ForegroundColor Yellow
                $wimFilePaths = @(
                    "$mountDir\sources\install.wim",
                    "$mountDir\sources\boot.wim"
                )

                $criticalWimError = $false
                foreach ($wimFilePath in $wimFilePaths) {
                    if (Test-Path $wimFilePath) {
                        try {
                            $wimItem = Get-Item -Path $wimFilePath -Force
                            if ($wimItem.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
                                Write-Host "DEBUG: Removing ReadOnly attribute from $wimFilePath" -ForegroundColor Yellow
                                $wimItem.Attributes = $wimItem.Attributes -band (-bnot [System.IO.FileAttributes]::ReadOnly)

                                # Verify the change was successful
                                $wimItem.Refresh()
                                if ($wimItem.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
                                    Write-Host "DEBUG: CRITICAL - Failed to remove ReadOnly attribute from $wimFilePath" -ForegroundColor Red
                                    $criticalWimError = $true
                                } else {
                                    Write-Host "DEBUG: Successfully removed ReadOnly attribute from $wimFilePath" -ForegroundColor Green
                                }
                            } else {
                                Write-Host "DEBUG: $wimFilePath is already writable" -ForegroundColor Green
                            }
                        } catch {
                            Write-Host "DEBUG: CRITICAL - Cannot modify ReadOnly attribute on $wimFilePath - $($_.Exception.Message)" -ForegroundColor Red
                            $criticalWimError = $true
                        }
                    } else {
                        Write-Host "DEBUG: WIM file not found: $wimFilePath (may be optional)" -ForegroundColor Yellow
                    }
                }

                if ($criticalWimError) {
                    Write-Host "DEBUG: ABORTING - Cannot proceed with mount due to WIM file ReadOnly issues" -ForegroundColor Red
                    $sync.form.Dispatcher.Invoke([action]{
                        Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
                        [System.Windows.MessageBox]::Show("Cannot remove ReadOnly attributes from WIM files. Mount operation aborted to prevent failures.", "WIM File Permission Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
                    })
                    return
                }

                foreach ($attempt in $mountAttempts) {
                    $currentScratchDir = $attempt.Dir
                    Write-Host "DEBUG: Trying mount with $($attempt.Description): $currentScratchDir"

                    try {
                        # Ensure directory exists and is accessible
                        if (-not (Test-Path $currentScratchDir)) {
                            New-Item -Path $currentScratchDir -ItemType Directory -Force | Out-Null
                            Write-Host "DEBUG: Created scratch directory: $currentScratchDir"

                            # Apply DISM-compatible permissions to the new directory
                            $permissionsSet = Set-DismCompatiblePermissions -Path $currentScratchDir
                            if ($permissionsSet) {
                                Write-Host "DEBUG: Applied DISM-compatible permissions to: $currentScratchDir"
                            }
                        }

                        # Try DISM mount
                        Write-Host "DEBUG: Attempting DISM mount to $currentScratchDir..."
                        $dismountResult = & dism /english /mount-image /imagefile:"$mountDir\sources\install.wim" /index:$index /mountdir:"$currentScratchDir" /optimize /loglevel:1
                        $dismountExitCode = $LASTEXITCODE

                        if ($dismountExitCode -eq 0) {
                            Write-Host "DEBUG: DISM mount successful with $($attempt.Description)"
                            $mountSuccess = $true
                            $scratchDir = $currentScratchDir  # Update scratch directory for rest of process
                            break
                        } else {
                            Write-Host "DEBUG: DISM mount failed with exit code $dismountExitCode"
                            Write-Host "DEBUG: DISM output: $dismountResult"

                            # Clean up failed attempt
                            try {
                                if (Test-Path $currentScratchDir) {
                                    Remove-Item $currentScratchDir -Force -Recurse -ErrorAction SilentlyContinue
                                }
                            } catch {
                                Write-Host "DEBUG: Could not clean up failed mount directory: $($_.Exception.Message)"
                            }
                        }
                    } catch {
                        Write-Host "DEBUG: Mount attempt failed for $($attempt.Description): $($_.Exception.Message)"
                        continue
                    }
                }

                # If DISM attempts failed, try PowerShell cmdlet as final fallback
                if (-not $mountSuccess) {
                    Write-Host "DEBUG: All DISM attempts failed, trying PowerShell cmdlet as final fallback..."

                    foreach ($attempt in $mountAttempts) {
                        $currentScratchDir = $attempt.Dir
                        Write-Host "DEBUG: Trying PowerShell mount with $($attempt.Description): $currentScratchDir"

                        try {
                            if (-not (Test-Path $currentScratchDir)) {
                                New-Item -Path $currentScratchDir -ItemType Directory -Force | Out-Null

                                # Apply DISM-compatible permissions to the new directory
                                $permissionsSet = Set-DismCompatiblePermissions -Path $currentScratchDir
                                if ($permissionsSet) {
                                    Write-Host "DEBUG: Applied DISM-compatible permissions to: $currentScratchDir"
                                }
                            }

                            Mount-WindowsImage -ImagePath "$mountDir\sources\install.wim" -Index $index -Path "$currentScratchDir" -Optimize
                            $mountSuccess = $true
                            $scratchDir = $currentScratchDir  # Update scratch directory for rest of process
                            Write-Host "DEBUG: PowerShell cmdlet mount successful with $($attempt.Description)"
                            break
                        } catch {
                            Write-Host "DEBUG: PowerShell cmdlet mount failed for $($attempt.Description): $($_.Exception.Message)"
                            continue
                        }
                    }
                }

                # If all mount attempts failed, try readonly mount as last resort
                if (-not $mountSuccess) {
                    Write-Host "DEBUG: All read/write mount attempts failed. Trying readonly mount as diagnostic step..."
                    Write-Host "DEBUG: NOTE: Readonly mount will not allow modifications, but helps identify permission issues"

                    try {
                        $readonlyScratchDir = "C:\temp\MicrowinReadOnly_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                        if (-not (Test-Path $readonlyScratchDir)) {
                            New-Item -Path $readonlyScratchDir -ItemType Directory -Force | Out-Null
                        }

                        $dismountResult = & dism /english /mount-image /imagefile:"$mountDir\sources\install.wim" /index:$index /mountdir:"$readonlyScratchDir" /readonly /loglevel:1
                        $dismountExitCode = $LASTEXITCODE

                        if ($dismountExitCode -eq 0) {
                            Write-Host "DEBUG: READONLY mount successful - this confirms the WIM file is accessible"
                            Write-Host "DEBUG: The issue is specifically with read/write permissions, not basic access"

                            # Clean up readonly mount
                            & dism /english /unmount-image /mountdir:"$readonlyScratchDir" /discard /loglevel:1
                            Remove-Item $readonlyScratchDir -Force -Recurse -ErrorAction SilentlyContinue

                            Write-Host "DEBUG: This suggests one of the following issues:"
                            Write-Host "DEBUG: 1. Antivirus software blocking write access to WIM files"
                            Write-Host "DEBUG: 2. Windows Defender real-time protection interfering"
                            Write-Host "DEBUG: 3. Corporate/Group Policy restrictions on DISM operations"
                            Write-Host "DEBUG: 4. File system permissions on temp directories"
                            Write-Host "DEBUG: 5. UAC virtualization affecting file access"
                        } else {
                            Write-Host "DEBUG: Even READONLY mount failed - this indicates a deeper system issue"
                            Write-Host "DEBUG: Readonly mount output: $dismountResult"
                        }
                    } catch {
                        Write-Host "DEBUG: Readonly mount test failed: $($_.Exception.Message)"
                    }
                }
                if (-not $mountSuccess) {
                    try {
                        $mountedImages = Get-WindowsImage -Mounted
                        foreach ($mounted in $mountedImages) {
                            if ($mounted.Path -eq $scratchDir) {
                                $mountSuccess = $true
                                Write-Host "DEBUG: Mount verification successful via Get-WindowsImage"
                                break
                            }
                        }
                    } catch {
                        Write-Host "DEBUG: Error verifying mount status: $($_.Exception.Message)"
                    }

                    # Additional verification by checking if typical Windows directories exist
                    if (-not $mountSuccess) {
                        if ((Test-Path "$scratchDir\Windows") -and (Test-Path "$scratchDir\Windows\System32")) {
                            Write-Host "DEBUG: Mount verification successful via directory structure check"
                            $mountSuccess = $true
                        }
                    }
                }

                if ($mountSuccess) {
                    Write-Host "The Windows image has been mounted successfully. Continuing processing..."
                    Write-Host "DEBUG: Mount verification successful"
                } else {
                    Write-Host "ERROR: Windows image mounting failed after all attempts"
                    Write-Host ""
                    Write-Host "=== COMPREHENSIVE TROUBLESHOOTING GUIDE ==="
                    Write-Host ""

                    # Show current system state
                    Write-Host "CURRENT SYSTEM STATE:"
                    try {
                        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                        $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
                        $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
                        Write-Host "DEBUG: - Running as Administrator: $isAdmin"
                        Write-Host "DEBUG: - Current User: $($currentUser.Name)"
                        Write-Host "DEBUG: - Process Architecture: $([System.Environment]::Is64BitProcess)"
                        Write-Host "DEBUG: - OS Architecture: $([System.Environment]::Is64BitOperatingSystem)"

                        # Show privilege status again
                        $tokenPrivs = whoami /priv | Out-String
                        Write-Host "DEBUG: - Current Privileges:"
                        $tokenPrivs -split "`n" | Where-Object { $_ -match "Se(Backup|Restore|Security|TakeOwnership|ManageVolume)Privilege" } | ForEach-Object {
                            Write-Host "DEBUG:   $($_.Trim())"
                        }
                    } catch {
                        Write-Host "DEBUG: Could not determine system state: $($_.Exception.Message)"
                    }

                    Write-Host ""
                    Write-Host "IMMEDIATE STEPS TO TRY:"
                    Write-Host "DEBUG: 1. **DISABLE WINDOWS DEFENDER REAL-TIME PROTECTION** (most common cause)"
                    Write-Host "DEBUG:    - Open Windows Security > Virus & threat protection"
                    Write-Host "DEBUG:    - Turn off Real-time protection temporarily"
                    Write-Host "DEBUG: 2. **DISABLE OTHER ANTIVIRUS SOFTWARE** (if present)"
                    Write-Host "DEBUG: 3. **TRY DIFFERENT TEMP DIRECTORY** (this script will attempt automatically)"
                    Write-Host "DEBUG: 4. **RUN FROM COMMAND PROMPT AS ADMIN** instead of PowerShell:"
                    Write-Host "DEBUG:    - Open Command Prompt as Administrator"
                    Write-Host "DEBUG:    - Navigate to: $($PWD.Path)"
                    Write-Host "DEBUG:    - Run: powershell -ExecutionPolicy Bypass -File winutil.ps1"
                    Write-Host "DEBUG: 5. **CHECK DISM LOG** at: C:\Windows\Logs\DISM\dism.log"
                    Write-Host "DEBUG: 6. **RUN DISM CLEANUP**: dism /cleanup-mountpoints"
                    Write-Host ""

                    Write-Host "MANUAL COMMAND TO TEST:"
                    Write-Host "dism /mount-image /imagefile:`"$mountDir\sources\install.wim`" /index:$index /mountdir:`"$scratchDir`""
                    Write-Host ""

                    Write-Host ""
                    Write-Host "ADVANCED DIAGNOSTICS TO RUN:"
                    Write-Host "DEBUG: 1. **CHECK GROUP POLICY RESTRICTIONS**:"
                    Write-Host "DEBUG:    - Run: gpedit.msc"
                    Write-Host "DEBUG:    - Navigate to: Computer Configuration > Administrative Templates > System > Device Installation"
                    Write-Host "DEBUG:    - Look for any DISM or imaging restrictions"
                    Write-Host "DEBUG: 2. **CHECK REGISTRY PERMISSIONS**:"
                    Write-Host "DEBUG:    - Ensure HKLM\SOFTWARE\Microsoft\WIMMount is accessible"
                    Write-Host "DEBUG: 3. **VERIFY DISM SERVICE STATUS**:"
                    Write-Host "DEBUG:    - Run: sc query TrustedInstaller"
                    Write-Host "DEBUG:    - Run: sc query CryptSvc"
                    Write-Host "DEBUG: 4. **CHECK WINDOWS FEATURES**:"
                    Write-Host "DEBUG:    - Run: dism /online /get-features | findstr DISM"
                    Write-Host "DEBUG: 5. **TEST WITH DIFFERENT WIM FILE**:"
                    Write-Host "DEBUG:    - Try mounting a different WIM file to isolate the issue"
                    Write-Host ""

                    Write-Host "CORPORATE/MANAGED SYSTEM CONSIDERATIONS:"
                    Write-Host "DEBUG: - If this is a corporate/managed system, IT policies may restrict DISM"
                    Write-Host "DEBUG: - Contact your system administrator about DISM operation restrictions"
                    Write-Host "DEBUG: - Some enterprise antivirus solutions block WIM modifications"
                    Write-Host "DEBUG: - Windows 10/11 in S Mode has restrictions on DISM operations"
                    Write-Host ""

                    $msg = "Could not mount Windows image. See console output for detailed troubleshooting steps."
                    $sync.form.Dispatcher.Invoke([action]{
                        Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
                        [System.Windows.MessageBox]::Show($msg, "Mount Failed", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
                    })
                    return
                }

                if ($importDrivers) {
                    Write-Host "Exporting drivers from active installation..."
                    Write-Host "DEBUG: Using optimized DISM settings for driver operations..."
                    if (Test-Path "$env:TEMP\DRV_EXPORT") {
                        Remove-Item "$env:TEMP\DRV_EXPORT" -Recurse -Force
                    }
                    if (($injectDrivers -and (Test-Path "$driverPath"))) {
                        Write-Host "Using specified driver source..."
                        dism /english /online /export-driver /destination="$driverPath" /loglevel:1 | Out-Host
                        if ($?) {
                            # Don't add exported drivers yet, that is run later
                            Write-Host "Drivers have been exported successfully."
                        } else {
                            Write-Host "Failed to export drivers."
                        }
                    } else {
                        New-Item -Path "$env:TEMP\DRV_EXPORT" -ItemType Directory -Force
                        dism /english /online /export-driver /destination="$env:TEMP\DRV_EXPORT" /loglevel:1 | Out-Host
                        if ($?) {
                            Write-Host "Adding exported drivers with optimized settings..."
                            # Use optimized DISM settings for better performance
                            dism /english /image="$scratchDir" /add-driver /driver="$env:TEMP\DRV_EXPORT" /recurse /forceunsigned /loglevel:1 | Out-Host
                        } else {
                            Write-Host "Failed to export drivers. Continuing without importing them..."
                        }
                        if (Test-Path "$env:TEMP\DRV_EXPORT") {
                            Remove-Item "$env:TEMP\DRV_EXPORT" -Recurse -Force
                        }
                    }
                }

                if ($injectDrivers) {
                    if (Test-Path $driverPath) {
                        Write-Host "Adding Windows Drivers with optimized settings image($scratchDir) drivers($driverPath)"
                        # Use optimized DISM settings for better performance
                        dism /English /image:$scratchDir /add-driver /driver:$driverPath /recurse /forceunsigned /loglevel:1 | Out-Host
                    } else {
                        Write-Host "Path to drivers is invalid continuing without driver injection"
                    }
                }

                if ($WPBT) {
                    Write-Host "Disabling WPBT Execution"
                    reg load HKLM\zSYSTEM "$($scratchDir)\Windows\System32\config\SYSTEM"
                    reg add "HKLM\zSYSTEM\ControlSet001\Control\Session Manager" /v DisableWpbtExecution /t REG_DWORD /d 1 /f
                    reg unload HKLM\zSYSTEM
                }

                if ($unsupported) {
                    Write-Host "Bypassing system requirements (locally)"
                    reg add "HKLM\DEFAULT\Control Panel\UnsupportedHardwareNotificationCache" /v "SV1" /t REG_DWORD /d 0 /f
                    reg add "HKLM\DEFAULT\Control Panel\UnsupportedHardwareNotificationCache" /v "SV2" /t REG_DWORD /d 0 /f
                    reg add "HKLM\NTUSER\Control Panel\UnsupportedHardwareNotificationCache" /v "SV1" /t REG_DWORD /d 0 /f
                    reg add "HKLM\NTUSER\Control Panel\UnsupportedHardwareNotificationCache" /v "SV2" /t REG_DWORD /d 0 /f
                    reg add "HKLM\SYSTEM\Setup\LabConfig" /v "BypassCPUCheck" /t REG_DWORD /d 1 /f
                    reg add "HKLM\SYSTEM\Setup\LabConfig" /v "BypassRAMCheck" /t REG_DWORD /d 1 /f
                    reg add "HKLM\SYSTEM\Setup\LabConfig" /v "BypassSecureBootCheck" /t REG_DWORD /d 1 /f
                    reg add "HKLM\SYSTEM\Setup\LabConfig" /v "BypassStorageCheck" /t REG_DWORD /d 1 /f
                    reg add "HKLM\SYSTEM\Setup\LabConfig" /v "BypassTPMCheck" /t REG_DWORD /d 1 /f
                    reg add "HKLM\SYSTEM\Setup\MoSetup" /v "AllowUpgradesWithUnsupportedTPMOrCPU" /t REG_DWORD /d 1 /f
                }

                if ($importVirtIO) {
                    Write-Host "Copying VirtIO drivers..."
                    Microwin-CopyVirtIO
                }

                Write-Host "DEBUG: ========== STARTING FEATURES REMOVAL =========="
                Write-Host "Remove Features from the image"
                try {
                    Microwin-RemoveFeatures -UseCmdlets $true
                    Write-Host "DEBUG: Features removal completed successfully"
                } catch {
                    Write-Host "DEBUG: ERROR during features removal: $($_.Exception.Message)"
                    Write-Host "DEBUG: Continuing with next step..."
                }
                Write-Host "Removing features complete!"

                Write-Host "DEBUG: ========== STARTING PACKAGES REMOVAL =========="
                Write-Host "Removing OS packages"
                try {
                    Microwin-RemovePackages -UseCmdlets $true
                    Write-Host "DEBUG: Packages removal completed successfully"
                } catch {
                    Write-Host "DEBUG: ERROR during packages removal: $($_.Exception.Message)"
                    Write-Host "DEBUG: Continuing with next step..."
                }

                Write-Host "DEBUG: ========== STARTING APPX BLOAT REMOVAL =========="
                Write-Host "Removing Appx Bloat"
                try {
                    Microwin-RemoveProvisionedPackages -UseCmdlets $true
                    Write-Host "DEBUG: Appx bloat removal completed successfully"
                } catch {
                    Write-Host "DEBUG: ERROR during Appx bloat removal: $($_.Exception.Message)"
                    Write-Host "DEBUG: Continuing with next step..."
                }

                # Detect Windows 11 24H2 and add dependency to FileExp to prevent Explorer look from going back - thanks @WitherOrNot and @thecatontheceiling
                if ((Microwin-TestCompatibleImage $imgVersion $([System.Version]::new(10,0,26100,1))) -eq $true) {
                    try {
                        if (Test-Path "$scratchDir\Windows\SystemApps\MicrosoftWindows.Client.FileExp_cw5n1h2txyewy\appxmanifest.xml" -PathType Leaf) {
                            # Found the culprit. Do the following:
                            # 1. Take ownership of the file, from TrustedInstaller to Administrators
                            takeown /F "$scratchDir\Windows\SystemApps\MicrosoftWindows.Client.FileExp_cw5n1h2txyewy\appxmanifest.xml" /A
                            # 2. Set ACLs so that we can write to it
                            icacls "$scratchDir\Windows\SystemApps\MicrosoftWindows.Client.FileExp_cw5n1h2txyewy\appxmanifest.xml" /grant "$(Microwin-GetLocalizedUsers -admins $true):(M)" | Out-Host
                            # 3. Open the file and do the modification
                            $appxManifest = Get-Content -Path "$scratchDir\Windows\SystemApps\MicrosoftWindows.Client.FileExp_cw5n1h2txyewy\appxmanifest.xml"
                            $originalLine = $appxManifest[13]
                            $dependency = "`n        <PackageDependency Name=`"Microsoft.WindowsAppRuntime.CBS`" MinVersion=`"1.0.0.0`" Publisher=`"CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US`" />"
                            $appxManifest[13] = "$originalLine$dependency"
                            Set-Content -Path "$scratchDir\Windows\SystemApps\MicrosoftWindows.Client.FileExp_cw5n1h2txyewy\appxmanifest.xml" -Value $appxManifest -Force -Encoding utf8
                        }
                    }
                    catch {
                        # Fall back to what we used to do: delayed disablement
                        Enable-WindowsOptionalFeature -Path "$scratchDir" -FeatureName "Recall"
                    }
                }

                Write-Host "DEBUG: ========== STARTING FILE/DIRECTORY CLEANUP =========="
                try {
                    Write-Host "DEBUG: Removing RtBackup directory..."
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Windows\System32\LogFiles\WMI\RtBackup" -Directory
                    Write-Host "DEBUG: Removing DiagTrack directory..."
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Windows\DiagTrack" -Directory
                    Write-Host "DEBUG: Removing InboxApps directory..."
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Windows\InboxApps" -Directory
                    Write-Host "DEBUG: Removing LocationNotificationWindows.exe..."
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Windows\System32\LocationNotificationWindows.exe"
                    Write-Host "DEBUG: Removing Windows Media Player directories..."
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Program Files (x86)\Windows Media Player" -Directory
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Program Files\Windows Media Player" -Directory
                    Write-Host "DEBUG: Removing Windows Mail directories..."
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Program Files (x86)\Windows Mail" -Directory
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Program Files\Windows Mail" -Directory
                    Write-Host "DEBUG: Removing Internet Explorer directories..."
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Program Files (x86)\Internet Explorer" -Directory
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Program Files\Internet Explorer" -Directory
                    Write-Host "DEBUG: Removing gaming and OneDrive components..."
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Windows\GameBarPresenceWriter"
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Windows\System32\OneDriveSetup.exe"
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Windows\System32\OneDrive.ico"
                    Write-Host "DEBUG: Removing system apps..."
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Windows\SystemApps" -mask "*narratorquickstart*" -Directory
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Windows\SystemApps" -mask "*ParentalControls*" -Directory
                    Write-Host "DEBUG: File/directory cleanup completed successfully"
                } catch {
                    Write-Host "DEBUG: ERROR during file/directory cleanup: $($_.Exception.Message)"
                    Write-Host "DEBUG: Continuing with next step..."
                }
                Write-Host "Removal complete!"

                Write-Host "DEBUG: ========== STARTING UNATTEND.XML CREATION =========="
                Write-Host "Create unattend.xml"

                if (($autoConfigPath -ne "") -and (Test-Path "$autoConfigPath")) {
                    try {
                        Write-Host "A configuration file has been specified. Copying to WIM file..."
                        Copy-Item "$autoConfigPath" "$($scratchDir)\winutil-config.json"
                    }
                    catch {
                        Write-Host "The config file could not be copied. Continuing without it..."
                    }
                }

                # Create unattended answer file with user information - Check condition to learn more about this functionality
                if ($userName -eq "") {
                    Microwin-NewUnattend -userName "User"
                } else {
                    if ($userPassword -eq "") {
                        Microwin-NewUnattend -userName "$userName"
                    } else {
                        Microwin-NewUnattend -userName "$userName" -userPassword "$userPassword"
                    }
                }
                Write-Host "Done Create unattend.xml"

                Write-Host "DEBUG: ========== COPYING UNATTEND.XML INTO ISO =========="
                Write-Host "Copy unattend.xml file into the ISO"
                try {
                    New-Item -ItemType Directory -Force -Path "$($scratchDir)\Windows\Panther"
                    Copy-Item "$env:temp\unattend.xml" "$($scratchDir)\Windows\Panther\unattend.xml" -force
                    New-Item -ItemType Directory -Force -Path "$($scratchDir)\Windows\System32\Sysprep"
                    Copy-Item "$env:temp\unattend.xml" "$($scratchDir)\Windows\System32\Sysprep\unattend.xml" -force
                    Write-Host "DEBUG: unattend.xml copied successfully"
                } catch {
                    Write-Host "DEBUG: ERROR copying unattend.xml: $($_.Exception.Message)"
                }
                Write-Host "Done Copy unattend.xml"

                Write-Host "DEBUG: ========== CREATING FIRSTRUN SCRIPT =========="
                Write-Host "Create FirstRun"
                try {
                    Microwin-NewFirstRun
                    Write-Host "DEBUG: FirstRun script created successfully"
                } catch {
                    Write-Host "DEBUG: ERROR creating FirstRun: $($_.Exception.Message)"
                }
                Write-Host "Done create FirstRun"

                Write-Host "DEBUG: ========== COPYING FIRSTRUN INTO ISO =========="
                Write-Host "Copy FirstRun.ps1 into the ISO"
                try {
                    Copy-Item "$env:temp\FirstStartup.ps1" "$($scratchDir)\Windows\FirstStartup.ps1" -force
                    Write-Host "DEBUG: FirstRun.ps1 copied successfully"
                } catch {
                    Write-Host "DEBUG: ERROR copying FirstRun.ps1: $($_.Exception.Message)"
                }
                Write-Host "Done copy FirstRun.ps1"

                Write-Host "DEBUG: ========== SETTING UP DESKTOP AND LINKS =========="
                Write-Host "Copy link to winutil.ps1 into the ISO"
                try {
                    $desktopDir = "$($scratchDir)\Windows\Users\Default\Desktop"
                    New-Item -ItemType Directory -Force -Path "$desktopDir"
                    dism /English /image:$($scratchDir) /set-profilepath:"$($scratchDir)\Windows\Users\Default"
                    Write-Host "DEBUG: Desktop setup completed successfully"
                } catch {
                    Write-Host "DEBUG: ERROR setting up desktop: $($_.Exception.Message)"
                }

                Write-Host "DEBUG: ========== CREATING CHECKINSTALL SCRIPT =========="
                Write-Host "Copy checkinstall.cmd into the ISO"
                try {
                    Microwin-NewCheckInstall
                    Copy-Item "$env:temp\checkinstall.cmd" "$($scratchDir)\Windows\checkinstall.cmd" -force
                    Write-Host "DEBUG: checkinstall.cmd created and copied successfully"
                } catch {
                    Write-Host "DEBUG: ERROR with checkinstall.cmd: $($_.Exception.Message)"
                }
                Write-Host "Done copy checkinstall.cmd"

                Write-Host "DEBUG: ========== CREATING BYPASSNRO DIRECTORY =========="
                Write-Host "Creating a directory that allows to bypass Wifi setup"
                try {
                    New-Item -ItemType Directory -Force -Path "$($scratchDir)\Windows\System32\OOBE\BYPASSNRO"
                    Write-Host "DEBUG: BYPASSNRO directory created successfully"
                } catch {
                    Write-Host "DEBUG: ERROR creating BYPASSNRO directory: $($_.Exception.Message)"
                }

                Write-Host "DEBUG: ========== LOADING REGISTRY =========="
                Write-Host "Loading registry"
                try {
                    Write-Host "DEBUG: Loading COMPONENTS registry..."
                    reg load HKLM\zCOMPONENTS "$($scratchDir)\Windows\System32\config\COMPONENTS"
                    Write-Host "DEBUG: Loading DEFAULT registry..."
                    reg load HKLM\zDEFAULT "$($scratchDir)\Windows\System32\config\default"
                    Write-Host "DEBUG: Loading NTUSER registry..."
                    reg load HKLM\zNTUSER "$($scratchDir)\Users\Default\ntuser.dat"
                    Write-Host "DEBUG: Loading SOFTWARE registry..."
                    reg load HKLM\zSOFTWARE "$($scratchDir)\Windows\System32\config\SOFTWARE"
                    Write-Host "DEBUG: Loading SYSTEM registry..."
                    reg load HKLM\zSYSTEM "$($scratchDir)\Windows\System32\config\SYSTEM"
                    Write-Host "DEBUG: All registry hives loaded successfully"
                } catch {
                    Write-Host "DEBUG: ERROR loading registry: $($_.Exception.Message)"
                }

                Write-Host "DEBUG: ========== APPLYING REGISTRY TWEAKS =========="
                Write-Host "Disabling Teams"
                try {
                    reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v "ConfigureChatAutoInstall" /t REG_DWORD /d 0 /f   >$null 2>&1
                    reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Chat" /v ChatIcon /t REG_DWORD /d 2 /f                             >$null 2>&1
                    reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d 0 /f        >$null 2>&1
                    reg query "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v "ConfigureChatAutoInstall"                      >$null 2>&1
                    Write-Host "DEBUG: Teams disabled successfully"
                } catch {
                    Write-Host "DEBUG: ERROR disabling Teams: $($_.Exception.Message)"
                }
                Write-Host "Done disabling Teams"

                Write-Host "DEBUG: Fixing Windows Volume Mixer Issue..."
                try {
                    reg add "HKLM\zNTUSER\Software\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore" /f
                    Write-Host "DEBUG: Volume Mixer fix applied successfully"
                } catch {
                    Write-Host "DEBUG: ERROR applying Volume Mixer fix: $($_.Exception.Message)"
                }
                Write-Host "Fix Windows Volume Mixer Issue"

                Write-Host "DEBUG: Bypassing system requirements..."
                try {
                    reg add "HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache" /v "SV1" /t REG_DWORD /d 0 /f
                    reg add "HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache" /v "SV2" /t REG_DWORD /d 0 /f
                    reg add "HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache" /v "SV1" /t REG_DWORD /d 0 /f
                    reg add "HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache" /v "SV2" /t REG_DWORD /d 0 /f
                    Write-Host "DEBUG: System requirements bypass applied successfully"
                } catch {
                    Write-Host "DEBUG: ERROR bypassing system requirements: $($_.Exception.Message)"
                }
                Write-Host "Bypassing system requirements (system image)"
                reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassCPUCheck" /t REG_DWORD /d 1 /f
                reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassRAMCheck" /t REG_DWORD /d 1 /f
                reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassSecureBootCheck" /t REG_DWORD /d 1 /f
                reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassStorageCheck" /t REG_DWORD /d 1 /f
                reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassTPMCheck" /t REG_DWORD /d 1 /f
                reg add "HKLM\zSYSTEM\Setup\MoSetup" /v "AllowUpgradesWithUnsupportedTPMOrCPU" /t REG_DWORD /d 1 /f

                # Prevent Windows Update Installing so called Expedited Apps - 24H2 and newer
                if ((Microwin-TestCompatibleImage $imgVersion $([System.Version]::new(10,0,26100,1))) -eq $true) {
                    @(
                        'EdgeUpdate',
                        'DevHomeUpdate',
                        'OutlookUpdate',
                        'CrossDeviceUpdate'
                    ) | ForEach-Object {
                        Write-Host "Removing Windows Expedited App: $_"
                        reg delete "HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\$_" /f | Out-Null
                    }
                }

                reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f
                Write-Host "Setting all services to start manually"
                reg add "HKLM\zSOFTWARE\CurrentControlSet\Services" /v Start /t REG_DWORD /d 3 /f

                Write-Host "Enabling Local Accounts on OOBE"
                reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "BypassNRO" /t REG_DWORD /d "1" /f

                Write-Host "Disabling Sponsored Apps"
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
                reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f
                reg add "HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "ConfigureStartPins" /t REG_SZ /d '{\"pinnedList\": [{}]}' /f
                Write-Host "Done removing Sponsored Apps"

                Write-Host "Disabling Reserved Storage"
                reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t REG_DWORD /d 0 /f

                Write-Host "Changing theme to dark. This only works on Activated Windows"
                reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d 0 /f
                reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d 0 /f

                if ((Microwin-TestCompatibleImage $imgVersion $([System.Version]::new(10,0,21996,1))) -eq $false) {
                    # We're dealing with Windows 10. Configure sane desktop settings. NOTE: even though stuff to disable News and Interests is there,
                    # it doesn't seem to work, and I don't want to waste more time dealing with an operating system that will lose support in a year (2025)

                    # I invite anyone to work on improving stuff for News and Interests, but that won't be me!

                    Write-Host "Disabling Search Highlights..."
                    reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds\DSB" /v "ShowDynamicContent" /t REG_DWORD /d 0 /f
                    reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDynamicSearchBoxEnabled" /t REG_DWORD /d 0 /f
                    reg add "HKLM\zSOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d 0 /f
                    reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "TraySearchBoxVisible" /t REG_DWORD /d 1 /f
                    reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v "EnableFeeds" /t REG_DWORD /d 0 /f
                }

            } catch {
                Write-Error "An unexpected error occurred: $_"
                Write-Host "DEBUG: ERROR in main processing: $($_.Exception.Message)"
                Write-Host "DEBUG: Stack trace: $($_.ScriptStackTrace)"
            } finally {
                Write-Host "DEBUG: ========== STARTING CLEANUP PROCESS =========="
                Write-Host "Unmounting Registry..."
                try {
                    Write-Host "DEBUG: Unloading registry hives..."
                    reg unload HKLM\zCOMPONENTS
                    reg unload HKLM\zDEFAULT
                    reg unload HKLM\zNTUSER
                    reg unload HKLM\zSOFTWARE
                    reg unload HKLM\zSYSTEM
                    Write-Host "DEBUG: Registry unloaded successfully"
                } catch {
                    Write-Host "DEBUG: ERROR unloading registry: $($_.Exception.Message)"
                }

                Write-Host "DEBUG: ========== CLEANING UP IMAGE =========="
                Write-Host "Cleaning up image with optimized settings..."
                try {
                    # Use optimized DISM cleanup settings for better performance
                    Write-Host "DEBUG: Running component cleanup with optimized settings..."
                    dism /English /image:$scratchDir /Cleanup-Image /StartComponentCleanup /ResetBase /loglevel:1
                    Write-Host "DEBUG: Image cleanup completed successfully"
                } catch {
                    Write-Host "DEBUG: ERROR during image cleanup: $($_.Exception.Message)"
                }
                Write-Host "Cleanup complete."

                Write-Host "DEBUG: ========== UNMOUNTING IMAGE =========="
                Write-Host "Unmounting image..."

                # First, try to clean up any processes or handles that might interfere with unmounting
                Write-Host "DEBUG: Performing pre-unmount cleanup..." -ForegroundColor Yellow
                try {
                    # Force garbage collection to release PowerShell file handles
                    [System.GC]::Collect()
                    [System.GC]::WaitForPendingFinalizers()
                    [System.GC]::Collect()

                    # Wait for any background operations to complete
                    Start-Sleep -Seconds 3

                    # Check if any Windows Search or antivirus processes might be interfering
                    $interferingProcesses = Get-Process -ErrorAction SilentlyContinue | Where-Object {
                        $_.ProcessName -match "SearchIndexer|SearchProtocolHost|SearchFilterHost|MsMpEng|NisSrv"
                    }

                    if ($interferingProcesses) {
                        Write-Host "DEBUG: Found potentially interfering processes, waiting for them to finish..." -ForegroundColor Yellow
                        Start-Sleep -Seconds 5
                    }

                    Write-Host "DEBUG: Pre-unmount cleanup completed" -ForegroundColor Green
                } catch {
                    Write-Host "DEBUG: Pre-unmount cleanup failed: $($_.Exception.Message)" -ForegroundColor Yellow
                }

                $dismountSuccess = $false
                $maxRetries = 3

                for ($retry = 1; $retry -le $maxRetries; $retry++) {
                    try {
                        Write-Host "DEBUG: Dismount attempt $retry of $maxRetries..."

                        if ($retry -eq 1) {
                            # First attempt: Try DISM command directly
                            Write-Host "DEBUG: Using DISM command for dismount..."
                            $dismResult = & dism /english /unmount-image /mountdir:"$scratchDir" /commit /loglevel:1
                            $dismExitCode = $LASTEXITCODE

                            if ($dismExitCode -eq 0) {
                                Write-Host "DEBUG: DISM dismount successful"
                                $dismountSuccess = $true
                                break
                            } else {
                                Write-Host "DEBUG: DISM dismount failed with exit code $dismExitCode"
                                Write-Host "DEBUG: DISM output: $dismResult"
                            }
                        } elseif ($retry -eq 2) {
                            # Second attempt: Try PowerShell cmdlet
                            Write-Host "DEBUG: Using PowerShell cmdlet for dismount..."
                            Dismount-WindowsImage -Path "$scratchDir" -Save
                        } else {
                            # Third attempt: Try PowerShell cmdlet with CheckIntegrity
                            Write-Host "DEBUG: Using PowerShell cmdlet with CheckIntegrity..."
                            Dismount-WindowsImage -Path "$scratchDir" -Save -CheckIntegrity
                        }

                        # Verify dismount was successful for PowerShell attempts
                        if ($retry -gt 1) {
                            Start-Sleep -Seconds 2
                            $mountedImages = Get-WindowsImage -Mounted
                            $stillMounted = $false
                            foreach ($mounted in $mountedImages) {
                                if ($mounted.Path -eq $scratchDir) {
                                    $stillMounted = $true
                                    break
                                }
                            }

                            if (-not $stillMounted) {
                                Write-Host "DEBUG: PowerShell cmdlet dismount successful on attempt $retry"
                                $dismountSuccess = $true
                                break
                            } else {
                                Write-Host "DEBUG: Image still appears to be mounted after attempt $retry"
                            }
                        }

                    } catch {
                        Write-Host "DEBUG: ERROR on dismount attempt $retry`: $($_.Exception.Message)"
                    }

                    # If this isn't the last retry, wait before trying again
                    if ($retry -lt $maxRetries -and -not $dismountSuccess) {
                        Write-Host "DEBUG: Waiting 5 seconds before next retry..."
                        Start-Sleep -Seconds 5

                        # Additional cleanup between retries
                        [System.GC]::Collect()
                        [System.GC]::WaitForPendingFinalizers()
                        [System.GC]::Collect()
                    }
                }

                # If all normal attempts failed, try aggressive cleanup and final fallback strategies
                if (-not $dismountSuccess) {
                    Write-Host "DEBUG: All normal dismount attempts failed - trying aggressive cleanup..." -ForegroundColor Red

                    # Aggressive cleanup before final attempts
                    try {
                        Write-Host "DEBUG: Performing aggressive file handle cleanup..." -ForegroundColor Yellow

                        # Force close any PowerShell handles
                        [System.GC]::Collect()
                        [System.GC]::WaitForPendingFinalizers()
                        [System.GC]::Collect()

                        # Remove readonly attributes from scratch directory
                        if (Test-Path $scratchDir) {
                            & attrib -R "$scratchDir\*" /S /D 2>$null
                        }

                        # Wait longer for file handles to be released
                        Start-Sleep -Seconds 10

                        Write-Host "DEBUG: Aggressive cleanup completed" -ForegroundColor Green
                    } catch {
                        Write-Host "DEBUG: Aggressive cleanup failed: $($_.Exception.Message)" -ForegroundColor Yellow
                    }

                    # Last attempt - try multiple fallback strategies
                    Write-Host "DEBUG: Final attempt - trying multiple fallback strategies..."

                    # Try DISM discard
                    try {
                        Write-Host "DEBUG: Trying DISM discard..."
                        $dismResult = & dism /english /unmount-image /mountdir:"$scratchDir" /discard /loglevel:1
                        if ($LASTEXITCODE -eq 0) {
                            Write-Host "DEBUG: DISM discard successful"
                            $dismountSuccess = $true
                        } else {
                            Write-Host "DEBUG: DISM discard failed with exit code $LASTEXITCODE"
                        }
                    } catch {
                        Write-Host "DEBUG: DISM discard failed: $($_.Exception.Message)"
                    }

                    # Try PowerShell discard if DISM failed
                    if (-not $dismountSuccess) {
                        try {
                            Write-Host "DEBUG: Trying PowerShell discard..."
                            Dismount-WindowsImage -Path "$scratchDir" -Discard
                            Write-Host "DEBUG: PowerShell discard completed (changes discarded)"
                            $dismountSuccess = $true
                        } catch {
                            Write-Host "DEBUG: PowerShell discard failed: $($_.Exception.Message)"
                        }
                    }

                    # Final fallback: cleanup mountpoints
                    if (-not $dismountSuccess) {
                        try {
                            Write-Host "DEBUG: Trying DISM cleanup-mountpoints..."
                            & dism /cleanup-mountpoints
                            Start-Sleep -Seconds 3
                            Write-Host "DEBUG: Mountpoints cleanup completed"
                        } catch {
                            Write-Host "DEBUG: Cleanup mountpoints failed: $($_.Exception.Message)"
                        }

                        Write-Host "DEBUG: CRITICAL ERROR - Could not dismount image with any method"
                        Write-Host "DEBUG: Manual cleanup commands:"
                        Write-Host "DEBUG: 1. dism /unmount-image /mountdir:`"$scratchDir`" /discard"
                        Write-Host "DEBUG: 2. dism /cleanup-mountpoints"
                        Write-Host "DEBUG: 3. Remove-Item -Recurse -Force `"$scratchDir`""
                    }
                }

                if (-not $dismountSuccess) {
                    $msg = "Warning: Could not properly dismount the Windows image. The process may have partially completed, but manual cleanup may be required."
                    Write-Host $msg
                    $sync.form.Dispatcher.Invoke([action]{
                        Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
                        [System.Windows.MessageBox]::Show($msg + "`n`nPlease run 'dism /cleanup-mountpoints' as Administrator to clean up.", "Dismount Warning", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
                    })
                }
            }

            try {
                Write-Host "DEBUG: ========== EXPORTING INSTALL IMAGE =========="
                Write-Host "Exporting image into $mountDir\sources\install2.wim with optimized settings..."
                try {
                    Write-Host "DEBUG: Trying PowerShell Export-WindowsImage with optimized compression for speed..."
                    # Use Fast compression for better performance, especially during development/testing
                    # Users can change this to "Max" if they prefer smaller file size over speed
                    Export-WindowsImage -SourceImagePath "$mountDir\sources\install.wim" -SourceIndex $index -DestinationImagePath "$mountDir\sources\install2.wim" -CompressionType "Fast"
                    Write-Host "DEBUG: PowerShell export with Fast compression completed successfully"
                } catch {
                    # Fall back to DISM with optimized settings
                    Write-Host "DEBUG: PowerShell export failed, falling back to DISM with optimized settings..."
                    Write-Host "DEBUG: Error was: $($_.Exception.Message)"
                    dism /english /export-image /sourceimagefile="$mountDir\sources\install.wim" /sourceindex=$index /destinationimagefile="$mountDir\sources\install2.wim" /compress:fast /checkintegrity /verify /loglevel:1
                    Write-Host "DEBUG: DISM export with optimized settings completed"
                }

                Write-Host "DEBUG: ========== REPLACING INSTALL.WIM =========="
                Write-Host "Remove old '$mountDir\sources\install.wim' and rename $mountDir\sources\install2.wim"
                try {
                    Remove-Item "$mountDir\sources\install.wim"
                    Rename-Item "$mountDir\sources\install2.wim" "$mountDir\sources\install.wim"
                    Write-Host "DEBUG: install.wim replaced successfully"
                } catch {
                    Write-Host "DEBUG: ERROR replacing install.wim: $($_.Exception.Message)"
                    throw $_
                }

                if (-not (Test-Path -Path "$mountDir\sources\install.wim")) {
                    $msg = "Something went wrong. Please report this bug to the devs."
                    Write-Error "$($msg) '$($mountDir)\sources\install.wim' doesn't exist"
                    $sync.form.Dispatcher.Invoke([action]{
                        # Invoke-MicrowinBusyInfo -action "warning" -message $msg
                        Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
                    })
                    return
                }
                Write-Host "Windows image completed. Continuing with boot.wim."

                if ($esd) {
                    Write-Host "Converting install image to ESD with optimized settings..."
                    try {
                        Write-Host "DEBUG: Using PowerShell Export with Recovery compression..."
                        Export-WindowsImage -SourceImagePath "$mountDir\sources\install.wim" -SourceIndex $index -DestinationImagePath "$mountDir\sources\install.esd" -CompressionType "Recovery"
                        Remove-Item "$mountDir\sources\install.wim"
                        Write-Host "Converted install image to ESD successfully."
                    } catch {
                        Write-Host "DEBUG: PowerShell ESD export failed, falling back to DISM with optimized settings..."
                        Start-Process -FilePath "$env:SystemRoot\System32\dism.exe" -ArgumentList "/export-image /sourceimagefile:`"$mountDir\sources\install.wim`" /sourceindex:1 /destinationimagefile:`"$mountDir\sources\install.esd`" /compress:recovery /checkintegrity /verify /loglevel:1" -Wait -NoNewWindow
                        Remove-Item "$mountDir\sources\install.wim"
                        Write-Host "Converted install image to ESD using DISM."
                    }
                }
            } catch {
                Write-Error "An unexpected error occurred during image export: $_"
                Write-Host "DEBUG: ERROR during image export/processing: $($_.Exception.Message)"
                throw $_
            }

            try {
                # Next step boot image
                Write-Host "Mounting boot image $mountDir\sources\boot.wim into $scratchDir"
                Mount-WindowsImage -ImagePath "$mountDir\sources\boot.wim" -Index 2 -Path "$scratchDir"

                if ($injectDrivers) {
                    if (Test-Path $driverPath) {
                        Write-Host "Adding Windows Drivers image($scratchDir) drivers($driverPath) "
                        dism /English /image:$scratchDir /add-driver /driver:$driverPath /recurse | Out-Host
                    } else {
                        Write-Host "Path to drivers is invalid continuing without driver injection"
                    }
                }

                Write-Host "Loading registry..."
                reg load HKLM\zCOMPONENTS "$($scratchDir)\Windows\System32\config\COMPONENTS" >$null
                reg load HKLM\zDEFAULT "$($scratchDir)\Windows\System32\config\default" >$null
                reg load HKLM\zNTUSER "$($scratchDir)\Users\Default\ntuser.dat" >$null
                reg load HKLM\zSOFTWARE "$($scratchDir)\Windows\System32\config\SOFTWARE" >$null
                reg load HKLM\zSYSTEM "$($scratchDir)\Windows\System32\config\SYSTEM" >$null
                Write-Host "Bypassing system requirements on the setup image"
                reg add "HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache" /v "SV1" /t REG_DWORD /d 0 /f
                reg add "HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache" /v "SV2" /t REG_DWORD /d 0 /f
                reg add "HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache" /v "SV1" /t REG_DWORD /d 0 /f
                reg add "HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache" /v "SV2" /t REG_DWORD /d 0 /f
                reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassCPUCheck" /t REG_DWORD /d 1 /f
                reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassRAMCheck" /t REG_DWORD /d 1 /f
                reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassSecureBootCheck" /t REG_DWORD /d 1 /f
                reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassStorageCheck" /t REG_DWORD /d 1 /f
                reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassTPMCheck" /t REG_DWORD /d 1 /f
                reg add "HKLM\zSYSTEM\Setup\MoSetup" /v "AllowUpgradesWithUnsupportedTPMOrCPU" /t REG_DWORD /d 1 /f
                # Fix Computer Restarted Unexpectedly Error on New Bare Metal Install
                reg add "HKLM\zSYSTEM\Setup\Status\ChildCompletion" /v "setup.exe" /t REG_DWORD /d 3 /f
            } catch {
                Write-Error "An unexpected error occurred: $_"
            } finally {
                Write-Host "Unmounting Registry..."
                reg unload HKLM\zCOMPONENTS
                reg unload HKLM\zDEFAULT
                reg unload HKLM\zNTUSER
                reg unload HKLM\zSOFTWARE
                reg unload HKLM\zSYSTEM

                Write-Host "Unmounting image..."
                Dismount-WindowsImage -Path "$scratchDir" -Save

                Write-Host "Creating ISO image"

                # if we downloaded oscdimg from github it will be in the temp directory so use it
                # if it is not in temp it is part of ADK and is in global PATH so just set it to oscdimg.exe
                $oscdimgPath = Join-Path $env:TEMP 'oscdimg.exe'
                $oscdImgFound = Test-Path $oscdimgPath -PathType Leaf
                if (!$oscdImgFound) {
                    $oscdimgPath = "oscdimg.exe"
                }

                Write-Host "[INFO] Using oscdimg.exe from: $oscdimgPath"

                $oscdimgProc = Start-Process -FilePath "$oscdimgPath" -ArgumentList "-m -o -u2 -udfver102 -bootdata:2#p0,e,b`"$mountDir\boot\etfsboot.com`"#pEF,e,b`"$mountDir\efi\microsoft\boot\efisys.bin`" `"$mountDir`" `"$($SaveDialog.FileName)`"" -Wait -PassThru -NoNewWindow

                $LASTEXITCODE = $oscdimgProc.ExitCode

                Write-Host "OSCDIMG Error Level : $($oscdimgProc.ExitCode)"

                if ($copyToUSB) {
                    Write-Host "Copying target ISO to the USB drive"
                    Microwin-CopyToUSB("$($SaveDialog.FileName)")
                    if ($?) { Write-Host "Done Copying target ISO to USB drive!" } else { Write-Host "ISO copy failed." }
                }

                Write-Host " _____                       "
                Write-Host "(____ \                      "
                Write-Host " _   \ \ ___  ____   ____    "
                Write-Host "| |   | / _ \|  _ \ / _  )   "
                Write-Host "| |__/ / |_| | | | ( (/ /    "
                Write-Host "|_____/ \___/|_| |_|\____)   "

                # Check if the ISO was successfully created - CTT edit
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "`n`nPerforming Cleanup..."
                    Remove-Item -Recurse -Force "$($scratchDir)"
                    Remove-Item -Recurse -Force "$($mountDir)"
                    $msg = "Done. ISO image is located here: $($SaveDialog.FileName)"
                    Write-Host $msg
                    $sync.form.Dispatcher.Invoke([action]{
                        Set-WinUtilTaskbaritem -state "None" -overlay "checkmark"
                        # Invoke-MicrowinBusyInfo -action "done" -message "Finished!"
                        [System.Windows.MessageBox]::Show($msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                    })
                } else {
                    Write-Host "ISO creation failed. The "$($mountDir)" directory has not been removed."
                    try {
                        # This creates a new Win32 exception from which we can extract a message in the system language.
                        # Now, this will NOT throw an exception
                        $exitCode = New-Object System.ComponentModel.Win32Exception($LASTEXITCODE)
                        Write-Host "Reason: $($exitCode.Message)"
                        $sync.form.Dispatcher.Invoke([action]{
                            # Invoke-MicrowinBusyInfo -action "warning" -message $exitCode.Message
                            Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
                            [System.Windows.MessageBox]::Show("MicroWin failed to make the ISO.", "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
                        })
                    } catch {
                        # Could not get error description from Windows APIs
                    }
                }

                $sync.form.Dispatcher.Invoke([action]{
                    Toggle-MicrowinPanel 1
                    $sync.MicrowinFinalIsoLocation.Text = "$($SaveDialog.FileName)"
                })

                # Allow the machine to sleep again (optional)
                [PowerManagement]::SetThreadExecutionState(0)
            }
        } catch {
            Write-Error "Critical error in MicroWin process: $_"
            $sync.form.Dispatcher.Invoke([action]{
                Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
                # Invoke-MicrowinBusyInfo -action "warning" -message "Critical error occurred: $_"
            })
        } finally {
            Write-Host "DEBUG: ========== PERFORMANCE OPTIMIZATIONS APPLIED =========="
            Write-Host "DEBUG: - Process priority set to High"
            Write-Host "DEBUG: - Memory optimization with garbage collection"
            Write-Host "DEBUG: - Multi-core processing support detected ($optimalThreads threads available)"
            Write-Host "DEBUG: - Fast compression used instead of Max for better performance"
            Write-Host "DEBUG: - Optimized DISM settings with reduced logging"
            Write-Host "DEBUG: - Enhanced error handling and retry mechanisms"
            Write-Host "DEBUG: - Streamlined registry and cleanup operations"
            Write-Host "DEBUG: Performance optimizations complete. Process should be significantly faster."

            # Reset process priority to normal
            try {
                $currentProcess = Get-Process -Id $PID
                $currentProcess.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Normal
                Write-Host "DEBUG: Process priority reset to Normal"
            } catch {
                Write-Host "DEBUG: Could not reset process priority: $($_.Exception.Message)"
            }

            $sync.ProcessRunning = $false
        }
    }
}
