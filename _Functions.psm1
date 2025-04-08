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

Function Send-ErrorNotifications {
    <#
    This function will be called when errors occur, and can be modified to perform an action (such as sending an email or submitting a command to a monitoring system) in response.
    By default it does nothing.
    #>
    Param (
        $MessageSummary,
        $MessageDetails
    )
    return $true
}