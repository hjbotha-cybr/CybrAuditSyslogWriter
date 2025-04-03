function ConvertTo-SyslogMessage {
    Param(
        [PSCustomObject[]]$SyslogMessageObj
    )

    $FormattedMessage = @()
    foreach ($Message in $SyslogMessageObj) {
        $FormattedMessage += (ConvertTo-Json -Depth 10 -Compress -InputObject $Message).Trim()
        $FormattedMessage += "`r`n"
    }
    
    Return $FormattedMessage
}