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

    # Get all the parameters we need from the UI before starting the runspace
    $getIsoSettings = @{
        isManual = $sync["ISOmanual"].IsChecked
        isDownloader = $sync["ISOdownloader"].IsChecked
        language = if ($sync["ISOLanguage"].SelectedItem) { $sync["ISOLanguage"].SelectedItem } else { "" }
        languageIndex = if ($sync["ISOLanguage"].SelectedIndex) { $sync["ISOLanguage"].SelectedIndex } else { 0 }
        release = if ($sync["ISORelease"].SelectedItem) { $sync["ISORelease"].SelectedItem } else { "" }
        downloadFromGitHub = $sync.WPFMicrowinDownloadFromGitHub.IsChecked
        useISOScratchDir = $sync.WPFMicrowinISOScratchDir.IsChecked
    }

    # Start the Get ISO process in a runspace to avoid blocking the UI
    Invoke-WPFMicroWinGetIsoRunspace -GetIsoSettings $getIsoSettings
}
