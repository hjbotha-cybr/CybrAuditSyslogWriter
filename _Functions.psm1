function ConvertTo-SyslogMessage {
    <#
    This function takes the syslog object retrieved from the Audit API and transforms it into an array of strings, which will later be passed to the syslog receiver.
    This function can be modified to transform the message into a different format as needed.
    Events must be returned as an array of strings, with each string in the array representing a single event.
    By default, it converts events into an array of JSON strings (not a JSON array).
    #>
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