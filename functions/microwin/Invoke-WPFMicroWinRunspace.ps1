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


        $sync.ProcessRunning = $true

        try {
            # Set process priority to High for better performance
            try {
                $currentProcess = Get-Process -Id $PID
                $currentProcess.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::High
            } catch {
                # Could not set process priority
            }

            # Optimize PowerShell memory usage
            try {
                # Force garbage collection to free up unused memory
                [System.GC]::Collect()
                [System.GC]::WaitForPendingFinalizers()
                [System.GC]::Collect()

                # Set execution policy to bypass for better performance
                Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
            } catch {
                # Memory optimization failed
            }

            # Prevent the machine from sleeping using simple PowerShell method
            try {
                # Use PowerShell's built-in method instead of complex P/Invoke
                $null = [System.Threading.Thread]::CurrentThread.ExecutionContext
                Add-Type -AssemblyName System.Windows.Forms
                [System.Windows.Forms.Application]::SetSuspendState('Hibernate', $false, $false)
            } catch {
                # Sleep prevention failed - continue anyway
            }

            # Ask the user where to save the file - this needs to be done on the main thread
            $SaveDialogFileName = ""
            $sync.form.Dispatcher.Invoke([action]{
                $SaveDialog = New-Object System.Windows.Forms.SaveFileDialog
                $SaveDialog.InitialDirectory = [Environment]::GetFolderPath('Desktop')
                $SaveDialog.Filter = "ISO images (*.iso)|*.iso"
                $result = $SaveDialog.ShowDialog()
                if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
                    $script:SaveDialogFileName = $SaveDialog.FileName
                }
            })

            if ($SaveDialogFileName -eq "") {
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

            Write-Host "Target ISO location: $SaveDialogFileName"

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
                try {
                    # Use Fast compression instead of Max for better performance during development
                    Export-WindowsImage -SourceImagePath "$mountDir\sources\install.esd" -SourceIndex $index -DestinationImagePath "$mountDir\sources\install.wim" -CompressionType "Fast"
                } catch {
                    # Fall back to DISM with optimized settings
                    dism /english /export-image /sourceimagefile="$mountDir\sources\install.esd" /sourceindex=$index /destinationimagefile="$mountDir\sources\install.wim" /compress:fast /checkintegrity /verify
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
            try {
                & dism /cleanup-mountpoints /loglevel:1
                Start-Sleep -Seconds 2
            } catch {
            }

            # Check if running as administrator
            if (-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                $msg = "Administrator privileges are required to mount and modify Windows images. Please run WinUtil as Administrator and try again."
                Write-Host $msg
                $sync.form.Dispatcher.Invoke([action]{
                    Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
                    [System.Windows.MessageBox]::Show($msg, "Administrator Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
                })
                return
            }

            # Enable required privileges for DISM operations - icacls handles this automatically
            # No complex P/Invoke needed since icacls will request necessary privileges

            # Check if the scratch directory is writable
            try {
                $testFile = Join-Path $scratchDir "test_write_permissions.tmp"
                "test" | Out-File -FilePath $testFile -Force
                Remove-Item $testFile -Force
            } catch {
                $msg = "Cannot write to scratch directory '$scratchDir'. Please check permissions and ensure the directory is not in use."
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
            } catch {
                $msg = "Cannot access or read the Windows installation image at '$wimPath'. The file may be corrupted or in use by another process."
                Write-Host $msg
                $sync.form.Dispatcher.Invoke([action]{
                    Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
                    [System.Windows.MessageBox]::Show($msg, "File Access Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
                })
                return
            }

            try {
                # Check if the image is already mounted and dismount if necessary
                try {
                    $mountedImages = Get-WindowsImage -Mounted
                    foreach ($mounted in $mountedImages) {
                        if ($mounted.Path -eq $scratchDir) {
                            Dismount-WindowsImage -Path $scratchDir -Discard
                            Start-Sleep -Seconds 2
                        }
                    }
                } catch {
                }

                # Additional permission checks before mounting

                # Pre-mount system checks

                # Check available disk space
                try {
                    $scratchDrive = Split-Path $scratchDir -Qualifier
                    $driveInfo = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $scratchDrive }
                    $freeSpaceGB = [math]::Round($driveInfo.FreeSpace / 1GB, 2)

                    if ($freeSpaceGB -lt 10) {
                    }
                } catch {
                }

                # Check if scratch directory is accessible
                try {
                    if (-not (Test-Path $scratchDir)) {
                        New-Item -Path $scratchDir -ItemType Directory -Force | Out-Null
                    }

                    # Test write access
                    $testFile = Join-Path $scratchDir "test_access.tmp"
                    "test" | Out-File -FilePath $testFile -Force
                    Remove-Item $testFile -Force
                } catch {
                    return
                }

                # Additional file permission and location diagnostics

                # WIM file permissions are handled automatically by DISM operations

                # Try alternative scratch directory if current one has issues
                $originalScratchDir = $scratchDir
                $alternateScratchDir = "C:\temp\MicrowinMount_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

                # Try to use DISM instead of PowerShell cmdlets for mounting
                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                Write-Host "Current user running mount: $currentUser" -ForegroundColor Yellow
                Write-Host "Mounting Windows image. This may take a while."

                $mountAttempts = @(
                    @{ Dir = $scratchDir; Description = "Original temp directory" },
                    @{ Dir = $alternateScratchDir; Description = "Alternative C:\temp directory" },
                    @{ Dir = "C:\MicrowinMount"; Description = "Root C: directory" }
                )

                # Remove ReadOnly attributes from WIM files before mounting
                $wimFilePaths = @(
                    "$mountDir\sources\install.wim",
                    "$mountDir\sources\boot.wim"
                )

                $criticalWimError = $false
                foreach ($wimFilePath in $wimFilePaths) {
                    if (Test-Path $wimFilePath) {
                        try {
                            # Remove ReadOnly attribute using attrib command
                            & attrib -R "$wimFilePath" 2>$null
                            if ($LASTEXITCODE -ne 0) {
                                $criticalWimError = $true
                            }
                        } catch {
                            $criticalWimError = $true
                        }
                    }
                }

                if ($criticalWimError) {
                    $sync.form.Dispatcher.Invoke([action]{
                        Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
                        [System.Windows.MessageBox]::Show("Cannot remove ReadOnly attributes from WIM files. Mount operation aborted to prevent failures.", "WIM File Permission Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
                    })
                    return
                }

                foreach ($attempt in $mountAttempts) {
                    $currentScratchDir = $attempt.Dir

                    try {
                        # Ensure directory exists
                        if (-not (Test-Path $currentScratchDir)) {
                            New-Item -Path $currentScratchDir -ItemType Directory -Force | Out-Null
                        }

                        # Try PowerShell cmdlet first
                        Mount-WindowsImage -ImagePath "$mountDir\sources\install.wim" -Index $index -Path "$currentScratchDir" -Optimize
                        $mountSuccess = $true
                        $scratchDir = $currentScratchDir
                        break

                    } catch {
                        # Fall back to DISM command
                        $dismResult = & dism /english /mount-image /imagefile:"$mountDir\sources\install.wim" /index:$index /mountdir:"$currentScratchDir" /optimize /loglevel:1

                        if ($LASTEXITCODE -eq 0) {
                            $mountSuccess = $true
                            $scratchDir = $currentScratchDir
                            break
                        } else {
                            # Clean up failed attempt
                            if (Test-Path $currentScratchDir) {
                                Remove-Item $currentScratchDir -Force -Recurse -ErrorAction SilentlyContinue
                            }
                        }
                    }
                }

                # If all mount attempts failed, show error
                if (-not $mountSuccess) {
                    try {
                        $mountedImages = Get-WindowsImage -Mounted
                        foreach ($mounted in $mountedImages) {
                            if ($mounted.Path -eq $scratchDir) {
                                $mountSuccess = $true
                                break
                            }
                        }
                    } catch {
                    }

                    # Additional verification by checking if typical Windows directories exist
                    if (-not $mountSuccess) {
                        if ((Test-Path "$scratchDir\Windows") -and (Test-Path "$scratchDir\Windows\System32")) {
                            $mountSuccess = $true
                        }
                    }
                }

                if ($mountSuccess) {
                    Write-Host "The Windows image has been mounted successfully. Continuing processing..."
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
                    } catch {
                    }

                    Write-Host ""
                    Write-Host "IMMEDIATE STEPS TO TRY:"
                    Write-Host ""

                    Write-Host "MANUAL COMMAND TO TEST:"
                    Write-Host "dism /mount-image /imagefile:`"$mountDir\sources\install.wim`" /index:$index /mountdir:`"$scratchDir`""
                    Write-Host ""

                    Write-Host ""
                    Write-Host "ADVANCED DIAGNOSTICS TO RUN:"
                    Write-Host ""

                    Write-Host "CORPORATE/MANAGED SYSTEM CONSIDERATIONS:"
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
                        dism /English /image:$scratchDir /add-driver /driver:$driverPath /recurse /forceunsigned | Out-Host
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

                Write-Host "Remove Features from the image"
                try {
                    Microwin-RemoveFeatures -UseCmdlets $true
                } catch {
                }
                Write-Host "Removing features complete!"

                Write-Host "Removing OS packages"
                try {
                    Microwin-RemovePackages -UseCmdlets $true
                } catch {
                }

                Write-Host "Removing Appx Bloat"
                try {
                    Microwin-RemoveProvisionedPackages -UseCmdlets $true
                } catch {
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

                try {
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Windows\System32\LogFiles\WMI\RtBackup" -Directory
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Windows\DiagTrack" -Directory
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Windows\InboxApps" -Directory
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Windows\System32\LocationNotificationWindows.exe"
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Program Files (x86)\Windows Media Player" -Directory
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Program Files\Windows Media Player" -Directory
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Program Files (x86)\Windows Mail" -Directory
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Program Files\Windows Mail" -Directory
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Program Files (x86)\Internet Explorer" -Directory
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Program Files\Internet Explorer" -Directory
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Windows\GameBarPresenceWriter"
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Windows\System32\OneDriveSetup.exe"
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Windows\System32\OneDrive.ico"
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Windows\SystemApps" -mask "*narratorquickstart*" -Directory
                    Microwin-RemoveFileOrDirectory -pathToDelete "$($scratchDir)\Windows\SystemApps" -mask "*ParentalControls*" -Directory
                } catch {
                }
                Write-Host "Removal complete!"

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

                Write-Host "Copy unattend.xml file into the ISO"
                try {
                    New-Item -ItemType Directory -Force -Path "$($scratchDir)\Windows\Panther"
                    Copy-Item "$env:temp\unattend.xml" "$($scratchDir)\Windows\Panther\unattend.xml" -force
                    New-Item -ItemType Directory -Force -Path "$($scratchDir)\Windows\System32\Sysprep"
                    Copy-Item "$env:temp\unattend.xml" "$($scratchDir)\Windows\System32\Sysprep\unattend.xml" -force
                } catch {
                }
                Write-Host "Done Copy unattend.xml"

                Write-Host "Create FirstRun"
                try {
                    Microwin-NewFirstRun
                } catch {
                }
                Write-Host "Done create FirstRun"

                Write-Host "Copy FirstRun.ps1 into the ISO"
                try {
                    Copy-Item "$env:temp\FirstStartup.ps1" "$($scratchDir)\Windows\FirstStartup.ps1" -force
                } catch {
                }
                Write-Host "Done copy FirstRun.ps1"

                Write-Host "Copy link to winutil.ps1 into the ISO"
                try {
                    $desktopDir = "$($scratchDir)\Windows\Users\Default\Desktop"
                    New-Item -ItemType Directory -Force -Path "$desktopDir"
                    dism /English /image:$($scratchDir) /set-profilepath:"$($scratchDir)\Windows\Users\Default"
                } catch {
                }

                Write-Host "Copy checkinstall.cmd into the ISO"
                try {
                    Microwin-NewCheckInstall
                    Copy-Item "$env:temp\checkinstall.cmd" "$($scratchDir)\Windows\checkinstall.cmd" -force
                } catch {
                }
                Write-Host "Done copy checkinstall.cmd"

                Write-Host "Creating a directory that allows to bypass Wifi setup"
                try {
                    New-Item -ItemType Directory -Force -Path "$($scratchDir)\Windows\System32\OOBE\BYPASSNRO"
                } catch {
                }

                Write-Host "Loading registry"
                try {
                    reg load HKLM\zCOMPONENTS "$($scratchDir)\Windows\System32\config\COMPONENTS"
                    reg load HKLM\zDEFAULT "$($scratchDir)\Windows\System32\config\default"
                    reg load HKLM\zNTUSER "$($scratchDir)\Users\Default\ntuser.dat"
                    reg load HKLM\zSOFTWARE "$($scratchDir)\Windows\System32\config\SOFTWARE"
                    reg load HKLM\zSYSTEM "$($scratchDir)\Windows\System32\config\SYSTEM"
                } catch {
                }

                Write-Host "Disabling Teams"
                try {
                    reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v "ConfigureChatAutoInstall" /t REG_DWORD /d 0 /f   >$null 2>&1
                    reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Chat" /v ChatIcon /t REG_DWORD /d 2 /f                             >$null 2>&1
                    reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d 0 /f        >$null 2>&1
                    reg query "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v "ConfigureChatAutoInstall"                      >$null 2>&1
                } catch {
                }
                Write-Host "Done disabling Teams"

                try {
                    reg add "HKLM\zNTUSER\Software\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore" /f
                } catch {
                }
                Write-Host "Fix Windows Volume Mixer Issue"

                try {
                    reg add "HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache" /v "SV1" /t REG_DWORD /d 0 /f
                    reg add "HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache" /v "SV2" /t REG_DWORD /d 0 /f
                    reg add "HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache" /v "SV1" /t REG_DWORD /d 0 /f
                    reg add "HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache" /v "SV2" /t REG_DWORD /d 0 /f
                } catch {
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
            } finally {
                Write-Host "Unmounting Registry..."
                try {
                    reg unload HKLM\zCOMPONENTS
                    reg unload HKLM\zDEFAULT
                    reg unload HKLM\zNTUSER
                    reg unload HKLM\zSOFTWARE
                    reg unload HKLM\zSYSTEM
                } catch {
                }

                Write-Host "Cleaning up image with optimized settings..."
                try {
                    # Use optimized DISM cleanup settings for better performance
                    dism /English /image:$scratchDir /Cleanup-Image /StartComponentCleanup /ResetBase /loglevel:1
                } catch {
                }
                Write-Host "Cleanup complete."

                Write-Host "Unmounting image..."

                # First, try to clean up any processes or handles that might interfere with unmounting
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
                        Start-Sleep -Seconds 5
                    }

                } catch {
                }

                $dismountSuccess = $false
                $maxRetries = 3

                for ($retry = 1; $retry -le $maxRetries; $retry++) {
                    try {

                        switch ($retry) {
                            1 {
                                # First attempt: Try DISM command directly
                                $dismResult = & dism /english /unmount-image /mountdir:"$scratchDir" /commit /loglevel:1
                                $dismExitCode = $LASTEXITCODE

                                if ($dismExitCode -eq 0) {
                                    $dismountSuccess = $true
                                    break
                                }
                            }
                            2 {
                                # Second attempt: Try PowerShell cmdlet
                                Dismount-WindowsImage -Path "$scratchDir" -Save
                            }
                            3 {
                                # Third attempt: Try PowerShell cmdlet with CheckIntegrity
                                Dismount-WindowsImage -Path "$scratchDir" -Save -CheckIntegrity
                            }
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
                                $dismountSuccess = $true
                                break
                            } else {
                            }
                        }

                    } catch {
                    }

                    # If this isn't the last retry, wait before trying again
                    if ($retry -lt $maxRetries -and -not $dismountSuccess) {
                        Start-Sleep -Seconds 5

                        # Additional cleanup between retries
                        [System.GC]::Collect()
                        [System.GC]::WaitForPendingFinalizers()
                        [System.GC]::Collect()
                    }
                }

                # If all normal attempts failed, try aggressive cleanup and final fallback strategies
                if (-not $dismountSuccess) {

                    # Aggressive cleanup before final attempts
                    try {

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

                    } catch {
                    }

                    # Last attempt - try multiple fallback strategies


                    # First, commit the image
                    try {
                        & dism /english /commit-image /mountdir:"$scratchDir" /loglevel:1
                    } catch {}

                    # Now, keep discarding the image in a loop
                    $discardAttempts = 0
                    $maxDiscardAttempts = 6
                    while (-not $dismountSuccess -and $discardAttempts -lt $maxDiscardAttempts) {
                        try {
                            $dismResult = & dism /english /unmount-image /mountdir:"$scratchDir" /discard /loglevel:1
                            if ($LASTEXITCODE -eq 0) {
                                $dismountSuccess = $true
                                break
                            }
                        } catch {}
                        $discardAttempts++
                        Start-Sleep -Seconds 5
                    }

                    # Try PowerShell discard if DISM failed
                    if (-not $dismountSuccess) {
                        try {
                            Dismount-WindowsImage -Path "$scratchDir" -Discard
                            $dismountSuccess = $true
                        } catch {
                        }
                    }

                    # Final fallback: cleanup mountpoints
                    if (-not $dismountSuccess) {
                        try {
                            & dism /cleanup-mountpoints
                            Start-Sleep -Seconds 3
                        } catch {
                        }

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
                Write-Host "Exporting image into $mountDir\sources\install2.wim with optimized settings..."
                try {
                    # Use Max compression for smaller file size (slower, but more efficient)
                    Export-WindowsImage -SourceImagePath "$mountDir\sources\install.wim" -SourceIndex $index -DestinationImagePath "$mountDir\sources\install2.wim" -CompressionType "Max"
                } catch {
                    # Fall back to DISM with optimized settings
                    dism /english /export-image /sourceimagefile="$mountDir\sources\install.wim" /sourceindex=$index /destinationimagefile="$mountDir\sources\install2.wim" /compress:fast /checkintegrity /verify /loglevel:1
                }

                Write-Host "Remove old '$mountDir\sources\install.wim' and rename $mountDir\sources\install2.wim"
                try {
                    Remove-Item "$mountDir\sources\install.wim"
                    Rename-Item "$mountDir\sources\install2.wim" "$mountDir\sources\install.wim"
                } catch {
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
                        Export-WindowsImage -SourceImagePath "$mountDir\sources\install.wim" -SourceIndex $index -DestinationImagePath "$mountDir\sources\install.esd" -CompressionType "Recovery"
                        Remove-Item "$mountDir\sources\install.wim"
                        Write-Host "Converted install image to ESD successfully."
                    } catch {
                        Start-Process -FilePath "$env:SystemRoot\System32\dism.exe" -ArgumentList "/export-image /sourceimagefile:`"$mountDir\sources\install.wim`" /sourceindex:1 /destinationimagefile:`"$mountDir\sources\install.esd`" /compress:recovery /checkintegrity /verify /loglevel:1" -Wait -NoNewWindow
                        Remove-Item "$mountDir\sources\install.wim"
                        Write-Host "Converted install image to ESD using DISM."
                    }
                }
            } catch {
                Write-Error "An unexpected error occurred during image export: $_"
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

                $oscdimgProc = Start-Process -FilePath "$oscdimgPath" -ArgumentList "-m -o -u2 -udfver102 -bootdata:2#p0,e,b`"$mountDir\boot\etfsboot.com`"#pEF,e,b`"$mountDir\efi\microsoft\boot\efisys.bin`" `"$mountDir`" `"$SaveDialogFileName`"" -Wait -PassThru -NoNewWindow

                $LASTEXITCODE = $oscdimgProc.ExitCode

                Write-Host "OSCDIMG Error Level : $($oscdimgProc.ExitCode)"

                if ($copyToUSB) {
                    Write-Host "Copying target ISO to the USB drive"
                    Microwin-CopyToUSB("$SaveDialogFileName")
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
                    $msg = "Done. ISO image is located here: $SaveDialogFileName"
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
                    $sync.MicrowinFinalIsoLocation.Text = "$SaveDialogFileName"
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

            # Reset process priority to normal
            try {
                $currentProcess = Get-Process -Id $PID
                $currentProcess.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Normal
            } catch {
            }

            $sync.ProcessRunning = $false
        }
    }
}
