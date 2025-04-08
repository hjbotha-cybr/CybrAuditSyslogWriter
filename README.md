# Introduction
CyberArk Audit Syslog Writer retrieves events from the CyberArk Audit service and sends them to the specified syslog receiver.

NOTE: This is a community script and not supported by CyberArk.

# Installation
1. Create the required backend configuration
   - Information available in the example config file, or in CyberArk documentation (https://docs.cyberark.com/admin-space/latest/en/content/siem-integration/siem-export-3rd-party.htm)
2. Download the tool
3. Unblock the downloaded zip file
   1. Right-click on the zip file
   2. Select Properties
   3. Select the "Unblock" option, if available
   4. Click OK
4. Extract the zip file
5. Run the `Install-CyberArkAuditWriter.ps1` to install the files and create the scheduled task
   - Installs to `Program Files\CyberArk` by default. Can be modified with `-InstallPath`
6. Copy the `Config.example.ini` file to `Config.ini`
7. Edit the config as needed
   - Details below
8. Enable the scheduled task
9. Monitor logs for errors
   - Logs are written to C:\Windows\Temp\CommunityCybrAuditSyslogWriterLogs\
10. (optional) Edit _Functions.psm1 to modify data transformation methods and error responses

# Upgrades
To upgrade when a new version is released:
1. Back up the current script files
2. Download the new version
3. Unblock the downloaded zip file
   1. Right-click on the zip file
   2. Select Properties
   3. Select the "Unblock" option, if available
   4. Click OK
4. Extract the zip file
5. Overwrite `CommunityCyberArkAuditSyslogWriter.ps1` with the new version of the file
6. Review _Functions.psm1 for any newly implemented functions, and copy them to _Functions.psm1

# Usage
Run the scheduled task and review logs.

If you need to run the script in a different context (e.g. interactively), you will need to set the `ServiceUserPasswordPlain` config parameter again, because the Encrypted passwords can only be decrypted by the user that generated it.

## Return codes
The scheduled task will return one of the following error codes in specific situations.
### Error return codes
| Return code | Definition                                                                                                                                                                  |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1           | There is an error in the config.ini                                                                                                                                         |
| 2           | Failed to create the state directory specified in config.ini                                                                                                                |
| 3           | Failed to decrypt the password set in ServiceUserPasswordEncrypted. Will occur if the password was encrypted by a user which is different from the user running the script. |
| 4           | Failed to create the lock file in the state directory                                                                                                                       |
| 5           | Non-fatal errors occurred during execution. Review logs for details.                                                                                                        |

### Normal return codes

| Return code | Definition                                                                                              |
| ----------- | ------------------------------------------------------------------------------------------------------- |
| 0           | Successful execution                                                                                    |
| 9           | The script was unable to acquire a lock, indicating that another instance of the script may be running. |

# Config.ini Options Reference
This section contains mostly the same information as `Config.example.ini` and is provided here as an additional reference.

## IdentityUrl
The URL of your Identity tenant in format `https://_IdentityTenantID_.id.cyberark.cloud`. This is the URL shown at the login page for your CyberArk tenant.

## ServiceUserUsername
The username of an "OAuth2 Confidential Client" user created in Identity Administration (Core Services -> Users -> Add User -> Select "Is OAuth confidential client")

## OAuth2ServerAppID
The "Application ID" of the "OAuth2 Server" type app created in Identity Administration -> Apps -> Web Apps -> Add Web Apps -> Custom -> OAuth2 Server.
This app must be configured as follows. If option is not specified, leave as default
- Settings:
  - Provide a unique Application ID and a descriptive display name.
- Tokens: 
  -   Token auth methods: Client Creds only
  -   Access token lifetime: Flexible. Recommend 1 hour to balance lifetime and refresh overhead
  -   Issue refresh tokens: No
- Scope:
  -   Name: `isp.audit.events:read`
- Permissions
  -   Grant Run permission to the OAuth Confidential client user specified in "ServiceUserUsername"
- Advanced
  - Copy the following script (do not modify)
```
setClaim('tenant_id', TenantData.Get('CybrTenantID'));
setClaimArray('user_roles', LoginUser.RoleNames);
setClaim('user_uuid', LoginUser.Uuid);
```

## ServiceUserPasswordPlain
The password of that user in plain text. This will be automatically encrypted the first time the script runs.  
Encrypted passwords can only be decrypted by the user that encrypted it.

## SyslogReceiverAddress
The hostname and port of your Syslog Receiver (Currently only supports plain text TCP)

## SyslogReceiverProtocol
The protocol of your Syslog Receiver.

Valid values are:
| Value | Definition                        |
| ----- | --------------------------------- |
| tcp   | Plain text TCP stream             |
| tcps  | TCP stream encrypted with TLS 1.2 |

## SyslogReceiverCertValidation
Whether to validate the identity of a TLS receiver.

## StateDir
The directory where the script will store its current state between executions.

## AuditApiKey
The API key of the SIEM integration created in the Audit service (CyberArk tenant -> Service Picker -> Audit -> SIEM Integrations).

## ApiBaseUrl
The API base URL of your Audit service (e.g. `https://SUBDOMAIN.audit.cyberark.cloud`).

## LogLevel
The log level of the tool. Valid values are "Info" and "Verbose".

# SyslogMessageJoinString
When using TCP or TCPS, multiple messages can be sent in one syslog connection. Set SyslogMessageJoinString to the character strings which should be inserted between messages.

The default, `` `r`n ``, is "CRLF" - a Windows line break.