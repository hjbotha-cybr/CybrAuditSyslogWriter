# Introduction
CyberArk Audit Syslog Writer retrieves events from the CyberArk Audit service and sends them to the specified syslog receiver.

NOTE: This is a community script and not supported by CyberArk.

# Installation
- Create the required backend configuration
  - Information available in the example config file, or in CyberArk documentation
- Run the `Install-CyberArkAuditWriter.ps1` to install the files and create the scheduled task
  - Installs to `Program Files\CyberArk` by default. Can be modified with `-InstallPath`
- Copy the `Config.example.ini` file to `Config.ini`
- Edit the config as needed
  - Details below
- Enable the scheduled task
- Monitor logs for errors
  - Logs are written to C:\Windows\Temp\CommunityCybrAuditSyslogWriterLogs\

# Usage
Just run the scheduled task and review logs.

If you need to run the script in a different context (e.g. interactively), you will need to set the `ServiceUserPasswordPlain` config parameter again, because the Encrypted passwords can only be decrypted by the user that generated it.

# Configuration
Create config.ini and provide the following details:

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
  -   Name: isp.audit.events:read
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
The protocol of your Syslog Receiver (Valid values: tcp, tcps)

## SyslogReceiverCertValidation
Whether to validate the identity of a TLS receiver

## StateDir
The directory where the script will store its current state between executions

## AuditApiKey
The API key of the SIEM integration created in the Audit service (CyberArk tenant -> Service Picker -> Audit -> SIEM Integrations)

## ApiBaseUrl
The API base URL of your Audit service (e.g. `https://SUBDOMAIN.audit.cyberark.cloud`)

## LogLevel
The log level of the tool. Valid values are "Info" and "Verbose"