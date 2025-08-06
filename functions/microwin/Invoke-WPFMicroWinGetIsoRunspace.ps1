function Invoke-WPFMicroWinGetIsoRunspace {
    <#
    .SYNOPSIS
    Runs the MicroWin Get ISO process in a runspace to avoid blocking the UI

    .DESCRIPTION
    This function handles the ISO selection, mounting, and analysis process for MicroWin
    in a background runspace to keep the UI responsive.

    .PARAMETER GetIsoSettings
    Hashtable containing the settings for the Get ISO process
    #>

    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$GetIsoSettings
    )

    Write-Host "Starting MicroWin GetIso runspace with settings:"
    Write-Host "IsManual: $($GetIsoSettings.isManual)"
    Write-Host "FilePath: '$($GetIsoSettings.filePath)'"
    Write-Host "IsDownloader: $($GetIsoSettings.isDownloader)"
    Write-Host "TargetFolder: '$($GetIsoSettings.targetFolder)'"

    # Start the Get ISO process in a runspace to avoid blocking the UI
    Invoke-WPFRunspace -ArgumentList $GetIsoSettings -DebugPreference $DebugPreference -ScriptBlock {
        param($GetIsoSettings, $DebugPreference)

        Write-Host "Inside runspace - processing ISO..."

        $sync.ProcessRunning = $true

        try {
            # Initialize progress tracking
            $totalSteps = 10
            $currentStep = 0


            # Provide immediate feedback to user with progress
            try {
                $sync.form.Dispatcher.Invoke([action]{
                    try {
                        Set-WinUtilTaskbaritem -state "Normal" -value 0.1 -overlay "logo"
                    } catch {
                    }

                    # Skip the problematic Invoke-MicrowinBusyInfo call for now
                })
            } catch {
            }
            $currentStep = 1


            Write-Host "         _                     __    __  _         "
            Write-Host "  /\/\  (_)  ___  _ __   ___  / / /\ \ \(_) _ __   "
            Write-Host " /    \ | | / __|| '__| / _ \ \ \/  \/ /| || '_ \  "
            Write-Host "/ /\/\ \| || (__ | |   | (_) | \  /\  / | || | | | "
            Write-Host "\/    \/|_| \___||_|    \___/   \/  \/  |_||_| |_| "


            $filePath = ""

            if ($GetIsoSettings.isManual) {
                # Use the pre-selected file path from the main thread
                $filePath = $GetIsoSettings.filePath

                if ([string]::IsNullOrEmpty($filePath)) {
                    Write-Host "No ISO is chosen"
                    $sync.form.Dispatcher.Invoke([action]{
                        Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
                        # Invoke-MicrowinBusyInfo -action "hide" -message " "
                    })
                    $sync.ProcessRunning = $false
                    return
                }

                # Update progress
                $currentStep = 2
                $sync.form.Dispatcher.Invoke([action]{
                    Set-WinUtilTaskbaritem -state "Normal" -value ($currentStep / $totalSteps) -overlay "logo"
                    # Skip Invoke-MicrowinBusyInfo call that was causing issues
                })

            } elseif ($GetIsoSettings.isDownloader) {
                # Use the pre-selected folder path from the main thread
                $targetFolder = $GetIsoSettings.targetFolder

                if ([string]::IsNullOrEmpty($targetFolder)) {
                    $sync.form.Dispatcher.Invoke([action]{
                        # Invoke-MicrowinBusyInfo -action "hide" -message " "
                    })
                    $sync.ProcessRunning = $false
                    return
                }

                $sync.form.Dispatcher.Invoke([action]{
                    Set-WinUtilTaskbaritem -state "Indeterminate" -overlay "logo"
                    # Invoke-MicrowinBusyInfo -action "wip" -message "Preparing to download ISO... (Step 2/$totalSteps)" -interactive $false
                })
                $currentStep = 2

                # Auto download newest ISO
                $fidopath = "$env:temp\Fido.ps1"
                $originalLocation = $PSScriptRoot

                $sync.form.Dispatcher.Invoke([action]{
                    # Invoke-MicrowinBusyInfo -action "wip" -message "Downloading Fido script..." -interactive $false
                })
                Invoke-WebRequest "https://github.com/pbatard/Fido/raw/master/Fido.ps1" -OutFile $fidopath

                Set-Location -Path $env:temp
                # Detect if the first option ("System language") has been selected and get a Fido-approved language from the current culture
                $lang = if ($GetIsoSettings.languageIndex -eq 0) {
                    Microwin-GetLangFromCulture -langName (Get-Culture).Name
                } else {
                    $GetIsoSettings.language
                }

                $sync.form.Dispatcher.Invoke([action]{
                    # Invoke-MicrowinBusyInfo -action "wip" -message "Downloading Windows ISO... (This may take a long time)" -interactive $false
                })
                & $fidopath -Win 'Windows 11' -Rel $GetIsoSettings.release -Arch "x64" -Lang $lang -Ed "Windows 11 Home/Pro/Edu"
                if (-not $?) {
                    Write-Host "Could not download the ISO file. Look at the output of the console for more information."
                    $msg = "The ISO file could not be downloaded"
                    $sync.form.Dispatcher.Invoke([action]{
                        # Invoke-MicrowinBusyInfo -action "warning" -message $msg
                        Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
                        [System.Windows.MessageBox]::Show($msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
                    })
                    $sync.ProcessRunning = $false
                    return
                }
                Set-Location $originalLocation
                $filePath = (Get-ChildItem -Path "$env:temp" -Filter "Win11*.iso").FullName | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                $fileName = [IO.Path]::GetFileName("$filePath")

                if (($targetFolder -ne "") -and (Test-Path "$targetFolder")) {
                    try {
                        Write-Host "Moving ISO file. Please wait..."
                        $destinationFilePath = "$targetFolder\$fileName"
                        Move-Item -Path "$filePath" -Destination "$destinationFilePath" -Force
                        $filePath = $destinationFilePath
                    } catch {
                        $msg = "Unable to move the ISO file to the location you specified. The downloaded ISO is in the `"$env:TEMP`" folder"
                        Write-Host $msg
                        Write-Host "Error information: $($_.Exception.Message)" -ForegroundColor Yellow
                        $sync.form.Dispatcher.Invoke([action]{
                            # Invoke-MicrowinBusyInfo -action "warning" -message $msg
                        })
                        $sync.ProcessRunning = $false
                        return
                    }
                }
            }

            Write-Host "File path $($filePath)"
            if (-not (Test-Path -Path "$filePath" -PathType Leaf)) {
                $msg = "File you've chosen doesn't exist"
                $sync.form.Dispatcher.Invoke([action]{
                    # Invoke-MicrowinBusyInfo -action "warning" -message $msg
                    [System.Windows.MessageBox]::Show($msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
                })
                $sync.ProcessRunning = $false
                return
            }

            $sync.form.Dispatcher.Invoke([action]{
                Set-WinUtilTaskbaritem -state "Normal" -value (3 / $totalSteps) -overlay "logo"
                # Skip Invoke-MicrowinBusyInfo call that was causing issues
            })
            $currentStep = 3

            # Check for oscdimg.exe
            $oscdimgPath = Join-Path $env:TEMP 'oscdimg.exe'
            $oscdImgFound = [bool] (Get-Command -ErrorAction Ignore -Type Application oscdimg.exe) -or (Test-Path $oscdimgPath -PathType Leaf)
            Write-Host "oscdimg.exe on system: $oscdImgFound"

            if (!$oscdImgFound) {
                if (!$GetIsoSettings.downloadFromGitHub) {
                    $sync.form.Dispatcher.Invoke([action]{
                        [System.Windows.MessageBox]::Show("oscdimge.exe is not found on the system, winutil will now attempt do download and install it using choco. This might take a long time.")
                    })
                    # Install Choco if not already present
                    Install-WinUtilChoco
                    $chocoFound = [bool] (Get-Command -ErrorAction Ignore -Type Application choco)
                    Write-Host "choco on system: $chocoFound"
                    if (!$chocoFound) {
                        $sync.form.Dispatcher.Invoke([action]{
                            [System.Windows.MessageBox]::Show("choco.exe is not found on the system, you need choco to download oscdimg.exe")
                        })
                        $sync.ProcessRunning = $false
                        return
                    }

                    Start-Process -Verb runas -FilePath powershell.exe -ArgumentList "choco install windows-adk-oscdimg"
                    $msg = "oscdimg is installed, now close, reopen PowerShell terminal and re-launch winutil.ps1"
                    $sync.form.Dispatcher.Invoke([action]{
                        # Invoke-MicrowinBusyInfo -action "done" -message $msg
                        [System.Windows.MessageBox]::Show($msg)
                    })
                    $sync.ProcessRunning = $false
                    return
                } else {
                    $sync.form.Dispatcher.Invoke([action]{
                        [System.Windows.MessageBox]::Show("oscdimge.exe is not found on the system, winutil will now attempt do download and install it from github. This might take a long time.")
                        # Skip Invoke-MicrowinBusyInfo call that was causing issues
                    })
                    Microwin-GetOscdimg -oscdimgPath $oscdimgPath
                    $oscdImgFound = Test-Path $oscdimgPath -PathType Leaf
                    if (!$oscdImgFound) {
                        $msg = "oscdimg was not downloaded can not proceed"
                        $sync.form.Dispatcher.Invoke([action]{
                            # Skip Invoke-MicrowinBusyInfo call that was causing issues
                            [System.Windows.MessageBox]::Show($msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
                        })
                        $sync.ProcessRunning = $false
                        return
                    } else {
                        Write-Host "oscdimg.exe was successfully downloaded from github"
                    }
                }
            }

            $sync.form.Dispatcher.Invoke([action]{
                Set-WinUtilTaskbaritem -state "Normal" -value (4 / $totalSteps) -overlay "logo"
                # Skip Invoke-MicrowinBusyInfo call that was causing issues
            })
            $currentStep = 4

            # Detect the file size of the ISO and compare it with the free space of the system drive
            $isoSize = (Get-Item -Path "$filePath").Length
            $driveSpace = (Get-Volume -DriveLetter ([IO.Path]::GetPathRoot([Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)).Replace(":\", "").Trim())).SizeRemaining
            if ($driveSpace -lt ($isoSize * 2)) {
                Write-Warning "You may not have enough space for this operation. Proceed at your own risk."
            } elseif ($driveSpace -lt $isoSize) {
                $msg = "You don't have enough space for this operation. You need at least $([Math]::Round(($isoSize / ([Math]::Pow(1024, 2))) * 2, 2)) MB of free space to copy the ISO files to a temp directory and to be able to perform additional operations."
                Write-Host $msg
                $sync.form.Dispatcher.Invoke([action]{
                    Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
                    # Skip Invoke-MicrowinBusyInfo call that was causing issues
                })
                $sync.ProcessRunning = $false
                return
            } else {
                Write-Host "You have enough space for this operation."
            }

            try {
                $sync.form.Dispatcher.Invoke([action]{
                    Set-WinUtilTaskbaritem -state "Normal" -value (5 / $totalSteps) -overlay "logo"
                    # Invoke-MicrowinBusyInfo -action "wip" -message "Mounting ISO file... (Step 5/$totalSteps)" -interactive $false
                })
                $currentStep = 5
                Write-Host "Mounting Iso. Please wait."
                $mountedISO = Mount-DiskImage -PassThru "$filePath"
                Write-Host "Done mounting Iso `"$($mountedISO.ImagePath)`""
                $driveLetter = (Get-Volume -DiskImage $mountedISO).DriveLetter
                Write-Host "Iso mounted to '$driveLetter'"
            } catch {
                $msg = "Failed to mount the image. Error: $($_.Exception.Message)"
                Write-Error $msg
                Write-Error "This is NOT winutil's problem, your ISO might be corrupt, or there is a problem on the system"
                Write-Host "Please refer to this wiki for more details: https://christitustech.github.io/winutil/KnownIssues/#troubleshoot-errors-during-microwin-usage" -ForegroundColor Red
                $sync.form.Dispatcher.Invoke([action]{
                    Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
                    # Invoke-MicrowinBusyInfo -action "warning" -message $msg
                })
                $sync.ProcessRunning = $false
                return
            }

            # Store values in UI fields - must be done on UI thread
            $sync.form.Dispatcher.Invoke([action]{
                $sync.MicrowinIsoDrive.Text = $driveLetter
            })

            $mountedISOPath = (Split-Path -Path "$filePath")

            # Handle scratch directory settings - must be done on UI thread
            $sync.form.Dispatcher.Invoke([action]{
                if ($sync.MicrowinScratchDirBox.Text.Trim() -eq "Scratch") {
                    $sync.MicrowinScratchDirBox.Text = ""
                }

                if ($GetIsoSettings.useISOScratchDir) {
                    $sync.MicrowinScratchDirBox.Text = $mountedISOPath
                }

                if (-Not $sync.MicrowinScratchDirBox.Text.EndsWith('\') -And $sync.MicrowinScratchDirBox.Text.Length -gt 1) {
                    $sync.MicrowinScratchDirBox.Text = Join-Path $sync.MicrowinScratchDirBox.Text.Trim() '\'
                }
            })

            # Get current values from UI thread
            $mountDir = ""
            $scratchDir = ""
            $sync.form.Dispatcher.Invoke([action]{
                # Detect if the folders already exist and remove them
                if (($sync.MicrowinMountDir.Text -ne "") -and (Test-Path -Path $sync.MicrowinMountDir.Text)) {
                    try {
                        Write-Host "Deleting temporary files from previous run. Please wait..."
                        Remove-Item -Path $sync.MicrowinMountDir.Text -Recurse -Force
                        Remove-Item -Path $sync.MicrowinScratchDir.Text -Recurse -Force
                    } catch {
                        Write-Host "Could not delete temporary files. You need to delete those manually."
                    }
                }

                Write-Host "Setting up mount dir and scratch dirs"
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $randomNumber = Get-Random -Minimum 1 -Maximum 9999
                $randomMicrowin = "Microwin_${timestamp}_${randomNumber}"
                $randomMicrowinScratch = "MicrowinScratch_${timestamp}_${randomNumber}"

                if ($sync.MicrowinScratchDirBox.Text -eq "") {
                    $script:mountDir = Join-Path $env:TEMP $randomMicrowin
                    $script:scratchDir = Join-Path $env:TEMP $randomMicrowinScratch
                } else {
                    $script:scratchDir = $sync.MicrowinScratchDirBox.Text + "Scratch"
                    $script:mountDir = $sync.MicrowinScratchDirBox.Text + "micro"
                }

                $sync.MicrowinMountDir.Text = $script:mountDir
                $sync.MicrowinScratchDir.Text = $script:scratchDir
            })

            # Get the values after they've been set - must be done on UI thread
            $mountDir = ""
            $scratchDir = ""
            $sync.form.Dispatcher.Invoke([action]{
                $sync.TempMountDir = $sync.MicrowinMountDir.Text
                $sync.TempScratchDir = $sync.MicrowinScratchDir.Text
            })
            $mountDir = $sync.TempMountDir
            $scratchDir = $sync.TempScratchDir

            Write-Host "Done setting up mount dir and scratch dirs"
            Write-Host "Scratch dir is $scratchDir"
            Write-Host "Image dir is $mountDir"

            try {
                $sync.form.Dispatcher.Invoke([action]{
                    Set-WinUtilTaskbaritem -state "Normal" -value (6 / $totalSteps) -overlay "logo"
                    # Invoke-MicrowinBusyInfo -action "wip" -message "Creating directories... (Step 6/$totalSteps)" -interactive $false
                })
                $currentStep = 6
                New-Item -ItemType Directory -Force -Path "$($mountDir)" | Out-Null
                New-Item -ItemType Directory -Force -Path "$($scratchDir)" | Out-Null

                $sync.form.Dispatcher.Invoke([action]{
                    Set-WinUtilTaskbaritem -state "Normal" -value (7 / $totalSteps) -overlay "logo"
                    # Invoke-MicrowinBusyInfo -action "wip" -message "Copying Windows files... (Step 7/$totalSteps - This may take several minutes)" -interactive $false
                })
                $currentStep = 7
                Write-Host "Copying Windows image. This will take awhile, please don't use UI or cancel this step!"

                try {

                    $totalTime = Measure-Command {
                        Copy-Files -Path "$($driveLetter):" -Destination "$mountDir" -Recurse -Force

                        # Force UI update during long operation
                        $sync.form.Dispatcher.Invoke([action]{
                            [System.Windows.Forms.Application]::DoEvents()
                        })
                    }
                    Write-Host "Copy complete! Total Time: $($totalTime.Minutes) minutes, $($totalTime.Seconds) seconds"
                } catch {
                    throw $_
                }                $sync.form.Dispatcher.Invoke([action]{
                    Set-WinUtilTaskbaritem -state "Normal" -value (8 / $totalSteps) -overlay "logo"
                    # Invoke-MicrowinBusyInfo -action "wip" -message "Processing Windows image... (Step 8/$totalSteps)" -interactive $false
                })
                $currentStep = 8
                $wimFile = "$mountDir\sources\install.wim"
                Write-Host "Getting image information $wimFile"

                $esdFile = $wimFile.Replace(".wim", ".esd").Trim()

                if ((-not (Test-Path -Path "$wimFile" -PathType Leaf)) -and (-not (Test-Path -Path "$esdFile" -PathType Leaf))) {
                    $msg = "Neither install.wim nor install.esd exist in the image, this could happen if you use unofficial Windows images. Please don't use shady images from the internet."
                    Write-Host "$($msg) Only use official images. Here are instructions how to download ISO images if the Microsoft website is not showing the link to download and ISO. https://www.techrepublic.com/article/how-to-download-a-windows-10-iso-file-without-using-the-media-creation-tool/"
                    $sync.form.Dispatcher.Invoke([action]{
                        # Invoke-MicrowinBusyInfo -action "warning" -message $msg
                        Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
                        [System.Windows.MessageBox]::Show($msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
                    })
                    throw
                } elseif ((-not (Test-Path -Path $wimFile -PathType Leaf)) -and (Test-Path -Path $esdFile -PathType Leaf)) {
                    Write-Host "Install.esd found on the image. It needs to be converted to a WIM file in order to begin processing"
                    $wimFile = $esdFile
                }


                # Populate the Windows flavors list - must be done on UI thread
                $sync.form.Dispatcher.Invoke([action]{
                    $sync.MicrowinWindowsFlavors.Items.Clear()
                })

                try {
                    $images = Get-WindowsImage -ImagePath $wimFile

                    $images | ForEach-Object {
                        $sync.form.Dispatcher.Invoke([action]{
                            $sync.MicrowinWindowsFlavors.Items.Add("$_.ImageIndex : $_.ImageName")
                        })
                    }
                } catch {
                    throw $_
                }

                $sync.form.Dispatcher.Invoke([action]{
                    [System.Windows.Forms.Application]::DoEvents()
                    $sync.MicrowinWindowsFlavors.SelectedIndex = 0
                    Set-WinUtilTaskbaritem -state "Normal" -value (9 / $totalSteps) -overlay "logo"
                    # Invoke-MicrowinBusyInfo -action "wip" -message "Finding suitable Pro edition... (Step 9/$totalSteps)" -interactive $false
                })
                $currentStep = 9

                Write-Host "Finding suitable Pro edition. This can take some time. Do note that this is an automatic process that might not select the edition you want."

                Get-WindowsImage -ImagePath $wimFile | ForEach-Object {
                    if ((Get-WindowsImage -ImagePath $wimFile -Index $_.ImageIndex).EditionId -eq "Professional") {
                        # We have found the Pro edition
                        $sync.form.Dispatcher.Invoke([action]{
                            $sync.MicrowinWindowsFlavors.SelectedIndex = $_.ImageIndex - 1
                        })
                        break
                    }
                    # Allow UI updates during this loop
                    $sync.form.Dispatcher.Invoke([action]{
                        [System.Windows.Forms.Application]::DoEvents()
                    })
                }

                Get-Volume $driveLetter | Get-DiskImage | Dismount-DiskImage
                Write-Host "Selected value '$($sync.MicrowinWindowsFlavors.SelectedValue)'....."

                # Switch to the customization panel - must be done on UI thread
                $sync.form.Dispatcher.Invoke([action]{
                    Set-WinUtilTaskbaritem -state "Normal" -value 1.0 -overlay "checkmark"
                    Toggle-MicrowinPanel 2
                })

            } catch {

                Write-Host "Dismounting bad image..."
                try {
                    Get-Volume $driveLetter | Get-DiskImage | Dismount-DiskImage
                } catch {
                }

                try {
                    if (Test-Path "$scratchDir") {
                        Remove-Item -Recurse -Force "$($scratchDir)"
                    }
                    if (Test-Path "$mountDir") {
                        Remove-Item -Recurse -Force "$($mountDir)"
                    }
                } catch {
                }

                $sync.form.Dispatcher.Invoke([action]{
                    # Invoke-MicrowinBusyInfo -action "warning" -message "Failed to read and unpack ISO"
                    Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
                })
                $sync.ProcessRunning = $false
                return
            }

            Write-Host "Done reading and unpacking ISO"
            Write-Host ""
            Write-Host "*********************************"
            Write-Host "Check the UI for further steps!!!"

            $sync.form.Dispatcher.Invoke([action]{
                # Invoke-MicrowinBusyInfo -action "done" -message "Done! Proceed with customization."
                Set-WinUtilTaskbaritem -state "None" -overlay "checkmark"
            })

        } catch {
            Write-Error "An unexpected error occurred: $_"
            $sync.form.Dispatcher.Invoke([action]{
                # Invoke-MicrowinBusyInfo -action "warning" -message "An unexpected error occurred: $_"
                Set-WinUtilTaskbaritem -state "Error" -value 1 -overlay "warning"
            })
        } finally {
            $sync.ProcessRunning = $false
        }
    }
}
