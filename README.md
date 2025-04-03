# Introduction
This script will retrieve events from the CyberArk Audit service and send it to the specified syslog receiver.

NOTE: This is a community script and not supported by CyberArk.

# Installation
- Create the required backend configuration
  - Information available in the example config file, or in CyberArk documentation
- Run the `Install-CyberArkAuditWriter.ps1` to install the files and create the scheduled task
  - Installs to `Program Files\CyberArk` by default. Can be modified with `-InstallPath`
- Copy the `Config.example.ini` file to `Config.ini`
- Edit the config as needed
- Enable the scheduled task
- Monitor logs for errors
  - Logs are written to C:\Windows\Temp\CommunityCybrAuditSyslogWriterLogs\

# Usage
Just run the scheduled task and review logs.

If you need to run the script in a different context (e.g. interactively), you will need to set the `ServiceUserPasswordPlain` config parameter again, because the Encrypted passwords can only be decrypted by the user that generated it.