function Invoke-MicrowinGetIso {
    <#
    .DESCRIPTION
    Function to get the path to Iso file for MicroWin, unpack that ISO, read basic information and populate the UI Options
    #>

    Write-Host "Invoking WPFGetIso"

    if($sync.ProcessRunning) {
        $msg = "GetIso process is currently running."
        [System.Windows.MessageBox]::Show($msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    # Handle file/folder selection on the main thread before starting runspace
    $filePath = ""
    $targetFolder = ""

    if ($sync["ISOmanual"].IsChecked) {
        # Open file dialog to let user choose the ISO file
        Invoke-MicrowinBusyInfo -action "wip" -message "Please select an ISO file..." -interactive $true
        [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
        $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $openFileDialog.filter = "ISO files (*.iso)| *.iso"
        $openFileDialog.ShowDialog() | Out-Null
        $filePath = $openFileDialog.FileName

        Write-Host "Selected file path: '$filePath'"

        if ([string]::IsNullOrEmpty($filePath)) {
            Write-Host "No ISO is chosen"
            Invoke-MicrowinBusyInfo -action "hide" -message " "
            return
        }

    } elseif ($sync["ISOdownloader"].IsChecked) {
        # Create folder browsers for user-specified locations
        Invoke-MicrowinBusyInfo -action "wip" -message "Please select download location..." -interactive $true
        [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
        $isoDownloaderFBD = New-Object System.Windows.Forms.FolderBrowserDialog
        $isoDownloaderFBD.Description = "Please specify the path to download the ISO file to:"
        $isoDownloaderFBD.ShowNewFolderButton = $true
        if ($isoDownloaderFBD.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
            Invoke-MicrowinBusyInfo -action "hide" -message " "
            return
        }
        $targetFolder = $isoDownloaderFBD.SelectedPath
    }

    # Get all the parameters we need from the UI before starting the runspace
    $getIsoSettings = @{
        isManual = $sync["ISOmanual"].IsChecked
        isDownloader = $sync["ISOdownloader"].IsChecked
        language = if ($sync["ISOLanguage"].SelectedItem) { $sync["ISOLanguage"].SelectedItem } else { "" }
        languageIndex = if ($sync["ISOLanguage"].SelectedIndex) { $sync["ISOLanguage"].SelectedIndex } else { 0 }
        release = if ($sync["ISORelease"].SelectedItem) { $sync["ISORelease"].SelectedItem } else { "" }
        downloadFromGitHub = $sync.WPFMicrowinDownloadFromGitHub.IsChecked
        useISOScratchDir = $sync.WPFMicrowinISOScratchDir.IsChecked
        filePath = $filePath
        targetFolder = $targetFolder
    }

    # Start the Get ISO process in a runspace to avoid blocking the UI
    Invoke-WPFMicroWinGetIsoRunspace -GetIsoSettings $getIsoSettings
}
