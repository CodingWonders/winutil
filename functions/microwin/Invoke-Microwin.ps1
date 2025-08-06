function Invoke-Microwin {
    <#
        .DESCRIPTION
        Invoke MicroWin routines...
    #>

    # Check if running as administrator first
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        $msg = "Administrator privileges are required for MicroWin operations. Please run WinUtil as Administrator and try again."
        [System.Windows.MessageBox]::Show($msg, "Administrator Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    if($sync.ProcessRunning) {
        $msg = "GetIso process is currently running."
        [System.Windows.MessageBox]::Show($msg, "Winutil", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    # Get all the parameters we need from the UI before starting the runspace
    $microwinsettings = @{
        mountDir = $sync.MicrowinMountDir.Text
        scratchDir = $sync.MicrowinScratchDir.Text
        copyToUSB = $sync.WPFMicrowinCopyToUsb.IsChecked
        injectDrivers = $sync.MicrowinInjectDrivers.IsChecked
        importDrivers = $sync.MicrowinImportDrivers.IsChecked
        WPBT = $sync.MicroWinWPBT.IsChecked
        unsupported = $sync.MicroWinUnsupported.IsChecked
        importVirtIO = $sync.MicrowinCopyVirtIO.IsChecked
        selectedIndex = if ($sync.MicrowinWindowsFlavors.SelectedValue) { $sync.MicrowinWindowsFlavors.SelectedValue.Split(":")[0].Trim() } else { "1" }
        driverPath = $sync.MicrowinDriverLocation.Text
        esd = $sync.MicroWinESD.IsChecked
        autoConfigPath = $sync.MicrowinAutoConfigBox.Text
        userName = $sync.MicrowinUserName.Text
        userPassword = $sync.MicrowinUserPassword.Password
    }

    # Start the MicroWin process in a runspace to avoid blocking the UI
    Invoke-WPFMicroWinRunspace -MicroWinSettings $microwinsettings
}
