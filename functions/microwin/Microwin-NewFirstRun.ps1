function Microwin-NewFirstRun {

    # using here string to embedd firstrun
    $firstRun = @'
    # Set the global error action preference to continue
    $ErrorActionPreference = "Continue"
    function Remove-RegistryValue {
        param (
            [Parameter(Mandatory = $true)]
            [string]$RegistryPath,

            [Parameter(Mandatory = $true)]
            [string]$ValueName
        )

        # Check if the registry path exists
        if (Test-Path -Path $RegistryPath) {
            $registryValue = Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue

            # Check if the registry value exists
            if ($registryValue) {
                # Remove the registry value
                Remove-ItemProperty -Path $RegistryPath -Name $ValueName -Force
                Write-Host "Registry value '$ValueName' removed from '$RegistryPath'."
            } else {
                Write-Host "Registry value '$ValueName' not found in '$RegistryPath'."
            }
        } else {
            Write-Host "Registry path '$RegistryPath' not found."
        }
    }

    "FirstStartup has worked" | Out-File -FilePath "$env:HOMEDRIVE\windows\LogFirstRun.txt" -Append -NoClobber

    $taskbarPath = "$env:AppData\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
    # Delete all files on the Taskbar
    Get-ChildItem -Path $taskbarPath -File | Remove-Item -Force
    Remove-RegistryValue -RegistryPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -ValueName "FavoritesRemovedChanges"
    Remove-RegistryValue -RegistryPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -ValueName "FavoritesChanges"
    Remove-RegistryValue -RegistryPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -ValueName "Favorites"

    # Delete Edge Icon from the desktop
    $edgeShortcutFiles = Get-ChildItem -Path $desktopPath -Filter "*Edge*.lnk"
    # Check if Edge shortcuts exist on the desktop
    if ($edgeShortcutFiles) {
        foreach ($shortcutFile in $edgeShortcutFiles) {
            # Remove each Edge shortcut
            Remove-Item -Path $shortcutFile.FullName -Force
            Write-Host "Edge shortcut '$($shortcutFile.Name)' removed from the desktop."
        }
    }
    Remove-Item -Path "$env:USERPROFILE\Desktop\*.lnk"
    Remove-Item -Path "$env:HOMEDRIVE\Users\Default\Desktop\*.lnk"

    try
    {
        if ((Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq 'Enabled' -and $_.FeatureName -like "Recall" }).Count -gt 0)
        {
            Disable-WindowsOptionalFeature -Online -FeatureName "Recall" -Remove
        }
    }
    catch
    {

    }

    # Get BCD entries and set bootmgr timeout accordingly
    try
    {
        # Check if the number of occurrences of "path" is 2 - this fixes the Boot Manager screen issue (#2562)
        if ((bcdedit | Select-String "path").Count -eq 2)
        {
            # Set bootmgr timeout to 0
            bcdedit /set `{bootmgr`} timeout 0
        }
    }
    catch
    {

    }

    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.Suggested" /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.Suggested" /v Enabled /t REG_DWORD /d 0 /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.StartupApp" /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.StartupApp" /v Enabled /t REG_DWORD /d 0 /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop" /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop" /v Enabled /t REG_DWORD /d 0 /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.AccountHealth" /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.AccountHealth" /v Enabled /t REG_DWORD /d 0 /f

    # Log configuration file check
    "Checking for configuration file at: $env:HOMEDRIVE\winutil-config.json" | Out-File -FilePath "$env:HOMEDRIVE\windows\LogFirstRun.txt" -Append -NoClobber

    if (Test-Path -Path "$env:HOMEDRIVE\winutil-config.json")
    {
        "Configuration file detected. Applying auto-configuration..." | Out-File -FilePath "$env:HOMEDRIVE\windows\LogFirstRun.txt" -Append -NoClobber
        Write-Host "Configuration file detected. Applying..."

        try {
            "Downloading WinUtil script from christitus.com..." | Out-File -FilePath "$env:HOMEDRIVE\windows\LogFirstRun.txt" -Append -NoClobber
            Invoke-RestMethod -Uri "https://christitus.com/win" -OutFile "$env:HOMEDRIVE\winutil.ps1"
            "WinUtil script downloaded successfully" | Out-File -FilePath "$env:HOMEDRIVE\windows\LogFirstRun.txt" -Append -NoClobber

            # Properly escaped command with ampersand quoted
            $cmd = '$env:HOMEDRIVE\winutil.ps1 -Config ''$env:HOMEDRIVE\winutil-config.json'' -Run'
            "Prepared command: $cmd" | Out-File -FilePath "$env:HOMEDRIVE\windows\LogFirstRun.txt" -Append -NoClobber

            # Start WinUtil and wait for completion
            "Starting WinUtil process and waiting for completion..." | Out-File -FilePath "$env:HOMEDRIVE\windows\LogFirstRun.txt" -Append -NoClobber
            $process = Start-Process powershell.exe -Verb RunAs -ArgumentList @(
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-Command", $cmd
            ) -PassThru -WindowStyle Hidden

            "WinUtil process started (PID: $($process.Id)). Waiting for completion..." | Out-File -FilePath "$env:HOMEDRIVE\windows\LogFirstRun.txt" -Append -NoClobber

            # Wait for the process to complete
            $process.WaitForExit()
            "WinUtil process completed with exit code: $($process.ExitCode)" | Out-File -FilePath "$env:HOMEDRIVE\windows\LogFirstRun.txt" -Append -NoClobber

            # Give a small delay to ensure all operations are complete
            Start-Sleep -Seconds 3

            "Cleaning up temporary files..." | Out-File -FilePath "$env:HOMEDRIVE\windows\LogFirstRun.txt" -Append -NoClobber
            if (Test-Path "$env:HOMEDRIVE\winutil.ps1") {
                Remove-Item -Path "$env:HOMEDRIVE\winutil.ps1" -Force
                "Removed winutil.ps1" | Out-File -FilePath "$env:HOMEDRIVE\windows\LogFirstRun.txt" -Append -NoClobber
            }
            if (Test-Path "$env:HOMEDRIVE\winutil-config.json") {
                Remove-Item -Path "$env:HOMEDRIVE\winutil-config.json" -Force
                "Removed winutil-config.json" | Out-File -FilePath "$env:HOMEDRIVE\windows\LogFirstRun.txt" -Append -NoClobber
            }
            "Cleanup completed" | Out-File -FilePath "$env:HOMEDRIVE\windows\LogFirstRun.txt" -Append -NoClobber
        }
        catch {
            "Error during WinUtil auto-configuration: $($_.Exception.Message)" | Out-File -FilePath "$env:HOMEDRIVE\windows\LogFirstRun.txt" -Append -NoClobber
            Write-Host "Error during WinUtil auto-configuration: $($_.Exception.Message)"
        }
    }
    else {
        "No configuration file found. Skipping auto-configuration." | Out-File -FilePath "$env:HOMEDRIVE\windows\LogFirstRun.txt" -Append -NoClobber
    }
'@
    $firstRun | Out-File -FilePath "$env:temp\FirstStartup.ps1" -Force
}
