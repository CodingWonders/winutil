function Get-LocalGroupNameFromSid {
    param (
        [Parameter(Mandatory, Position = 0)] [string]$sid
    )
    # You can fine-tune this to add error handling, but this should do the trick
    return (Get-LocalGroup | Where-Object { $_.SID.Value -like "$sid" }).Name
}
