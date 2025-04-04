Function Write-LogMessage {
    <#
.SYNOPSIS
	Method to log a message on screen and in a log file

.DESCRIPTION
	Logging The input Message to the Screen and the Log File.
	The Message Type is presented in colours on the screen based on the type

.PARAMETER LogFile
	The Log File to write to. By default using the LOG_FILE_PATH
.PARAMETER MSG
	The message to log
.PARAMETER Header
	Adding a header line before the message
.PARAMETER SubHeader
	Adding a Sub header line before the message
.PARAMETER Footer
	Adding a footer line after the message
.PARAMETER Type
	The type of the message to log (Info, Warning, Error, Debug)
#>
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [String]$MSG,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Debug", "Verbose", "Success", "LogOnly")]
        [String]$type = "Info"
    )
    
    If (($type -eq "Verbose") -and ($true -ne $Script:VerboseLogging)) {
        # Ignore verbose messages if log level is set to Info
        return
    }

    If ($false -eq (Test-Path -Path $LogDirectory -PathType Container)) {
        $null = New-Item -Path $LogDirectory -ItemType Directory
    }
    Try {
        $msgToWrite = "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")] "
        # Replace empty message with 'N/A'
        if ([string]::IsNullOrEmpty($Msg)) { $Msg = "N/A" }

        # Check the message type
        switch ($type) {
            "Info" {
                $msgToWrite += "[INFO]`t$Msg"
            }
            "Verbose" {
                $msgToWrite += "[VERBOSE]`t$Msg"
            }
            "Error" {
                $msgToWrite += "[ERROR]`t$Msg"
            }
        }

        Write-Host $MSG
        $msgToWrite | Out-File -Append -FilePath $LogFile
    }
    catch {
        Write-Host $_ | ConvertTo-Json
        Throw $(New-Object System.Exception ("Failed to write a log message"), $_.Exception)
    }
}

function b64enc {
    param(
        [string]$Text
    )
    $Bytes = [System.Text.Encoding]::ASCII.GetBytes($Text)
    $EncodedText = [Convert]::ToBase64String($Bytes)
    return $EncodedText
}

function Remove-FileLock {
    param(
        [string]$File
    )
    $LockFileStream.Close()
    $LockFileStream.Dispose()
    return $true
}

function Update-CursorFile {
    param(
        [string]$CursorFile,
        $CursorRef
    )
    try {
        $null = Set-Content -Path $CursorFile -Value $CursorRef -Force
        return New-SuccesssfulReturnObject
    }
    catch {
        New-ErrorReturnObject -ErrorObject $_
    }
}

function Update-TokenFile {
    param(
        [string]$TokenFile,
        $TokenObj
    )
    $TokenJson = $TokenObj | ConvertTo-Json -Depth 3
    try {
        $null = Set-Content -Path $TokenFile -Value $TokenJson -Force
        return New-SuccesssfulReturnObject
    }
    catch {
        New-ErrorReturnObject -ErrorObject $_
    }
}


function New-ErrorReturnObject {
    Param(
        $ErrorObject,
        $AdditionalInformation
    )
    return @{
        Result  = $false
        Details = @{
            ErrorDetails          = $ErrorObject.ErrorDetails
            ExceptionMessage      = $ErrorObject.Exception.Message
            AdditionalInformation = $AdditionalInformation
        } | ConvertTo-Json -Depth 3
    }
}


function New-SuccesssfulReturnObject {
    return @{
        Result = $true
    }
}

function Send-SyslogMessage {
    Param (
        [string]$SyslogReceiverAddress,
        [boolean]$Tls,
        [string]$Message
    )
    $SyslogReceiverArray = $SyslogReceiverAddress -split ":"
    $SyslogReceiverHost = $SyslogReceiverArray[0]
    $SyslogReceiverPort = $SyslogReceiverArray[1]

    # Encode message to bytes
    $AsciiEncoder = [Text.Encoding]::ASCII
    $EncodedMessage = $AsciiEncoder.GetBytes($Message)
    try {
        $tcpConnection = New-Object -TypeName System.Net.Sockets.TcpClient
        $tcpConnection.Connect($SyslogReceiverHost, $SyslogReceiverPort)
    }
    catch {
        $null = $tcpConnection.Close()
        return New-ErrorReturnObject -ErrorObject $_ -AdditionalInformation "Error occurred while connecting to syslog server"
    }
    try {
        $ConnectionStream = $tcpConnection.GetStream()
        $ConnectionWriter = New-Object -TypeName System.IO.StreamWriter -ArgumentList $ConnectionStream
        $ConnectionWriter.AutoFlush = $true
        $ConnectionWriter.Write($EncodedMessage, 0, $EncodedMessage.length)
    }
    catch {
        $null = $ConnectionWriter.Close()
        $null = $tcpConnection.Close()
        return New-ErrorReturnObject -ErrorObject $_ -AdditionalInformation "Error occurred while attempting to send the syslog message"
    }
    $null = $ConnectionWriter.Close()
    $null = $tcpConnection.Close()
    return New-SuccesssfulReturnObject
}

function ConvertTo-HashTableFromPSCustomObject {
    Param (
        $InputObject
    )
    $HashTable = @{}
    $InputObject.psobject.properties | ForEach-Object {
        $hashtable.$($_.Name) = $_.Value
    }
    return $hashtable
}

function New-PlatformAccessHeaders {
    Param (
        [psobject]$IdentityTokenUrl,
        [PSCredential]$CredentialObject,
        [string]$AuditApiKey
    )

    # Create an HTTP Basic Authentication string and header
    $clientid = $CredentialObject.UserName
    $clientsecret = $CredentialObject.GetNetworkCredential().Password
    $creds = ("{0}:{1}" -f $clientid, $clientsecret)

    Remove-Variable -Name clientsecret

    $encodedcreds = b64enc $creds

    $Headers = @{
        Authorization = ("Basic {0}" -f $encodedcreds)
    }

    $Body = @{
        grant_type = "client_credentials"
        scope      = "isp.audit.events:read"
    }

    # Perform login to get a new token
    try {
        $Response = Invoke-RestMethod -Body $Body -Method POST -Uri $IdentityTokenUrl -Headers $Headers -TimeoutSec 10
    }
    catch {
        return New-ErrorReturnObject -ErrorObject $_
    }
    $NowTime = Get-Date
    $ExpiryTime = $NowTime.AddSeconds($Response.expires_in - 60) # subtract 1 minute from expiry time to ensure we'll refresh BEFORE it expires
    return @{
        Result     = $true
        Headers    = @{
            "Content-Type" = "application/json"
            Authorization  = ("Bearer {0}" -f $Response.access_token)
            "x-api-key"    = $AuditApiKey
        }
        ExpiryTime = $ExpiryTime
    }
}

function Get-DataFromIniFile {
    Param(
        $IniFile
    )

    # Init empty object
    $IniObj = @{}

    # Read the config data from the INI file
    $IniData = (Get-Content -Path $IniFile) | Where-Object { -not [String]::IsNullOrWhiteSpace($_) } | Where-Object { $_ -notmatch "#.*" }
    Foreach ($line in $IniData) {
        If ($line -Match "(.*?)=(.*)") {
            #Write-LogMessage -MSG ("Read {0} value from Config file" -f $Matches[1])
            $IniObj += @{
                $Matches[1] = $Matches[2]
            }
        }
        else {
            $ErrorObject = @{
                ErrorDetails = "Line `"$line`" in Config.ini is not a valid configuration line."
                Exception    = @{
                    Message = "N/A"
                }
            }
            return New-ErrorReturnObject -ErrorObject $ErrorObject
        }
    }
    return $IniObj
}

function Set-IniContent {
    Param(
        $InputObject,
        $IniFile
    )
    $Data = ""

    foreach ($property in $Config.PSObject.Properties["Keys"].value) {
        $config.$property
        If ($Config.$property) {
            $Data += ("{0}={1}`n" -f $Property, $Config.$Property)
        }
    }
    try {
        Set-Content -Force -Path $IniFile -Value $Data
        return New-SuccesssfulReturnObject
    }
    catch {
        return New-ErrorReturnObject -ErrorObject $_
    }
}

### LOAD CONFIG ###

$ConfigFile = "$PSScriptRoot\Config.ini"
$Config = Get-DataFromIniFile -IniFile $ConfigFile

# The following parameters must be defined in the config file. If any are missing, exit.
If (-not (
        $Config.StateDir -and
        $Config.OAuth2ServerAppID -and
        (
            $Config.ServiceUserPasswordEncrypted -or
            $Config.ServiceUserPasswordPlain
        ) -and
        $Config.IdentityUrl -and
        $Config.ApiBaseUrl -and
        $Config.SyslogReceiverAddress -and
        $Config.AuditApiKey -and
        $Config.ServiceUserUsername
    )
) {
    Write-LogMessage -MSG "Required parameter missing from Config file. The following parameters are required:"
    Write-LogMessage -MSG " - OAuth2ServerAppID"
    Write-LogMessage -MSG " - StateDir"
    Write-LogMessage -MSG " - ServiceUserPasswordPlain or ServiceUserPasswordEncrypted"
    Write-LogMessage -MSG " - IdentityUrl"
    Write-LogMessage -MSG " - ApiBaseUrl"
    Write-LogMessage -MSG " - SyslogReceiverAddress"
    Write-LogMessage -MSG " - AuditApiKey"
    Write-LogMessage -MSG " - ServiceUserUsername"
    exit 1
}

If ($Config.LogLevel -eq "Verbose") {
    $Script:VerboseLogging = $true
}

### END LOAD CONFIG ###

### ACQUIRE LOCK ###

# Lock file prevents more than one instance of the script trying to run at the same time
$LockFile = ("{0}\lock" -f $Config.StateDir)
#$Script:LogDirectory = ($Config.StateDir + "\Logs")

$Script:LogDirectory = ("{0}\CommunityCybrAuditSyslogWriterLogs" -f $env:temp)
$Script:LogFile = $LogDirectory + "\Writer.log"

# Delete old logs

$MaxLogSize = 0.5 * 1024 * 1024
$LogSize = (Get-Item $LogFile).Length
If ($LogSize -gt $MaxLogSize) {
    $DateStamp = Get-Date -Format yyyy-MM-dd_hh-mm-ss
    $NewLogFileName = (($LogFile -Replace "\.log", "") + "_" + $DateStamp + ".log")
    Rename-Item -Path $LogFile -NewName $NewLogFileName
}
$OlderLogs = Get-ChildItem $LogDirectory | Sort-Object -Property LastWriteTime -Descending | Select-Object -Skip 5
If ($OlderLogs) {
    Write-Host ("removing logs " -f $OlderLogs.FullName)
    Remove-Item -Path $OlderLogs.FullName
}

# Check if the state directory defined in config file exists, and attempt to create if not
If ($false -eq (Test-Path -Path $Config.StateDir -Type Container)) {
    try {
        $null = New-Item -Path $Config.StateDir -ItemType Directory
    }
    catch {
        Write-LogMessage -type Error -MSG "Failed to create state dir. This is a fatal error. Please review and correct."
        Write-LogMessage -type Error -MSG ("Error: {0}" -f $_.Exception.Message)
        exit 1
    }
}


# Checking that lock file exists
If ($false -eq (Test-Path -Path $LockFile -Type Leaf)) {
    Write-LogMessage -MSG "Lock file does not exist. Attempting to create."
    try {
        $null = Set-Content -Path $LockFile -Value "Lock file for Community CyberArk Audit Syslog Writer."
    }
    catch {
        Write-LogMessage -type Error -MSG "Failed to create lock file. This is a fatal error. Please review and correct."
        Write-LogMessage -type Error -MSG ("Error: {0}" -f $_.Exception.Message)
        exit 1
    }
}

Write-LogMessage -type Verbose -MSG "Attempting to obtain lock."

try {
    $LockFileStream = [System.IO.File]::Open($LockFile, "Open", "Write")
}    
catch {
    Write-LogMessage -MSG "Failed to obtain a lock on the lock file, which means another instance of this tool is running. Exiting."
    exit 0
}    

### LOCK ACQUIRED ###

Write-LogMessage -MSG "Acquired lock. Starting execution."

# Check if there is an updated password in the ini, encrypt it and remove it
If ($Config.ServiceUserPasswordPlain) {
    Write-LogMessage -MSG "Found a plain text password in the config. Replacing it with encrypted password."
    $Config.ServiceUserPasswordEncrypted = $Config.ServiceUserPasswordPlain | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString
    $Config.ServiceUserPasswordPlain = $null
    Set-IniContent -IniFile $ConfigFile -InputObject $Config
}

Import-Module -Name "$PSScriptRoot\_Functions.psm1" -Force

# Create a credential object from the service user name and password
try {
    $ServiceUserPassword = $Config.ServiceUserPasswordEncrypted | ConvertTo-SecureString
}
catch {
    Write-LogMessage -type Error -MSG "Failed to decrypt the password in config.ini. Note that the encrypted password cannot be transferred across systems."
    Write-LogMessage -type Error -MSG "Set `"ServiceUserPasswordPlain`" in Config.ini if you are copying the config from another system."
    exit 1
}

[PSCredential]$ServiceUserCredentials = New-Object System.Management.Automation.PSCredential($Config.ServiceUserUsername, $ServiceUserPassword)

# Load current state
$TokenFile = ("{0}\_Token.dat" -f $Config.StateDir)
$CursorFile = ("{0}\_Cursor.dat" -f $Config.StateDir)

If (Test-Path $CursorFile) {
    # Not the first run. Retrieve state from file.
    Write-LogMessage -type Verbose -MSG "Retrieving last token from state directory"
    $CursorRef = [string](Get-Content $CursorFile)
}
else {
    # This is the first run, so initialise the object that will keep a log of successfully retrieved events
    Write-LogMessage -type Verbose -MSG "Cursor not found. New search will be created."
    $CursorRef = ""
}

If (Test-Path $TokenFile) {
    # Not the first run. Retrieve state from file.
    Write-LogMessage -type Verbose -MSG "Retrieving last token from state directory"
    $TokenObj = Get-Content $TokenFile | ConvertFrom-Json

    # ConvertFrom-Json creates a PSCustomObject, while Invoke-RestMethod needs headers as a hashtable, so convert it
    $Headers = ConvertTo-HashTableFromPSCustomObject -InputObject $TokenObj.Headers
}
else {
    # This is the first run, so initialise the object that will keep a log of successfully retrieved events
    Write-LogMessage -type Verbose -MSG "Token not found. Will be retrieved."
    $TokenObj = [ordered]@{
        Headers     = @{}
        TokenExpiry = "01/01/1980 00:00:00"
    }
}

# Set a variable which is used to track errors.
$Proceed = $true

# Initialise the variable which will be used to determine whether the cursor should be saved at the end of the process
$StoreCursor = $false

# There is no token yet, or it has expired. Retrieve a new token and store it in the State Object and the Headers variable
$NowTime = Get-Date
Write-LogMessage -type Verbose -MSG ("Current time: {0}" -f $NowTime)
Write-LogMessage -type Verbose -MSG ("Token expiry: {0}" -f $TokenObj.TokenExpiry)
If ($NowTime -gt $TokenObj.TokenExpiry) {
    # if now is after token expiry time
    Write-LogMessage -type Info -MSG "No valid token available. Retrieving a new token from CyberArk."
    $IdentityTokenUrl = ("{0}/OAuth2/Token/{1}" -f $Config.IdentityUrl, $Config.OAuth2ServerAppID)
    $GetPlatformHeaderResult = New-PlatformAccessHeaders -IdentityTokenUrl $IdentityTokenUrl -CredentialObject $ServiceUserCredentials -AuditApiKey $Config.AuditApiKey
    If ($GetPlatformHeaderResult.Result) {
        $TokenObj.TokenExpiry = $GetPlatformHeaderResult.ExpiryTime
        $TokenObj.Headers = $GetPlatformHeaderResult.Headers
        $Headers = $TokenObj.Headers
        # Store the updated token in the state dir
        $null = Update-TokenFile -TokenFile $TokenFile -TokenObj $TokenObj
    }
    else {
        Write-LogMessage -MSG "Failed to update platform headers. Result was:"
        Write-LogMessage -MSG $GetPlatformHeaderResult.Details | ConvertTo-Json -Depth 5
        Write-LogMessage -MSG "This is a fatal error. Remaining steps will be skipped."
        $Proceed = $false
    }
}

# If we don't have a cursor yet, create a query to retrieve one
If ($Proceed) {
    If (-not $CursorRef) {
        Write-LogMessage -MSG "No cursor reference in state. Creating a new query."
        # Format the start time as the API expects
        $FormattedStartTime = $NowTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

        # Define the filters for the query which will be sent to the Audit service. This can be customised to retrieve information related to specific components, actions, severities, etc.
        # For available filters see https://docs.cyberark.com/audit/latest/en/content/audit/isp_siem-integration-api.htm
        $SearchBody = [PSCustomObject]@{
            query = @{
                filterModel = @{
                    date = @{
                        dateFrom = $FormattedStartTime
                    }
                }
            }
        } | ConvertTo-Json -Depth 5

        # Create the query. This returns a "cursorRef" object, which lets us fetch the data in batches, with the cursor indicating the current position in the data stream
        try {
            Write-LogMessage -type Verbose -MSG "Creating query"
            $Result = Invoke-RestMethod -Uri ('{0}/api/audits/stream/createQuery' -f $Config.ApiBaseUrl) -Headers $Headers -Method POST -Body $SearchBody
            $CursorRef = $Result.cursorRef
            # Store the updated cursor in the cursor file in the state directory
            $StoreCursor = $true
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to create query."
            Write-LogMessage -MSG (
                @{
                    ExceptionMessage = $_.Exception.message
                    ErrorDetails     = $_.ErrorDetails
                } | ConvertTo-Json -Depth 3
            )
            Write-LogMessage -type Error -MSG "This is a fatal error. Exiting."
            $Proceed = $false        
        }
    }
}
# Initialisations complete. Retrieve data.

If ($Proceed) {
    Write-LogMessage -type Verbose -MSG "Retrieving events"
    # Create the body for retrieving events
    $ResultsBody = [PSCustomObject]@{
        cursorRef = $cursorRef
    } | ConvertTo-Json

    try {
        # Request the next set of data
        Write-LogMessage -type Verbose -MSG "Retrieving events from server"
        $Result = Invoke-RestMethod -Uri ('{0}/api/audits/stream/results' -f $Config.ApiBaseUrl) -Headers $Headers -Method POST -Body $ResultsBody
        $Count = $Result.data.length
        Write-LogMessage -type Verbose -MSG "Received $Count events from server"
    }
    catch {
        Write-LogMessage -type Error -MSG "Failed to retrieve events from Audit service"
        Write-LogMessage -type Error -MSG (@{
                ErrorDetails     = $_.ErrorDetails
                ExceptionMessage = $_.Exception.Message
            } | ConvertTo-Json -Depth 5)
        Write-LogMessage -type Error -MSG "This is a fatal error. Remaining steps will be skipped."
        $Proceed = $false
    }
}

If ($Result.data) {
    # convert it to strings
    $SyslogString = ConvertTo-SyslogMessage -SyslogMessageObj $Result.data
    #Write-LogMessage -MSG "Sending:"
    #Write-LogMessage -MSG $SyslogString
    #Write-LogMessage -MSG "New Data: $SyslogString"
    try {
        # and try to send it to the syslog receiver
        $SyslogSendResult = Send-SyslogMessage -SyslogReceiverAddress $config.SyslogReceiverAddress -Message $SyslogString
        If ($SyslogSendResult.Result) {
            Write-LogMessage -MSG "$Count events sent to syslog. Updating cursor."
            $CursorRef = $Result.paging.cursor.cursorRef
            $StoreCursor = $true
        }
        else {
            throw
        }
    }
    catch {
        Write-LogMessage -type Error -MSG "Failed to send syslog message with error:"
        Write-LogMessage -type Error -MSG $SyslogSendResult.Details
        Write-LogMessage -type Error -MSG "Current cursorRef will be retained so the same logs can be retrieved again."
    }
}
else {
    # If we get here, there was no new data so just update the cursor
    Write-LogMessage -MSG "No new data."
    $CursorRef = $Result.paging.cursor.cursorRef
    $StoreCursor = $true
}


If ($StoreCursor) {
    $null = Update-CursorFile -CursorFile $CursorFile -CursorRef $CursorRef
}

Write-LogMessage -type Info -MSG "Completed execution"

# Release the lock
$null = Remove-FileLock -File $LockFileStream
