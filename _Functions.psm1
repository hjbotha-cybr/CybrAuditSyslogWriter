function ConvertTo-SyslogMessage {
    Param(
        [PSCustomObject[]]$SyslogMessageObj
    )

    $FormattedMessageArray = @()
    foreach ($Message in $SyslogMessageObj) {
        $FormattedMessageArray += (ConvertTo-Json -Depth 10 -Compress -InputObject $Message).Trim()
    }
    
    Return $FormattedMessageArray
}

}