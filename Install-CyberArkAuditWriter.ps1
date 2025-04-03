Param (
    $InstallPath = ($env:ProgramFiles + "\CyberArk")
)

$FullInstallPath = New-Item -ItemType Directory -Path $InstallPath -Name CommunityAuditServiceWriter -Force
$FilesToCopy = @(
    "$PSScriptRoot\CommunityCyberArkAuditSyslogWriter.ps1"
    "$PSScriptRoot\_Functions.psm1"
    "$PSScriptRoot\Config.example.ini"
)

Copy-Item -Path $FilesToCopy -Destination $FullInstallPath -Force

$ScriptPath = ("{0}\CommunityCyberArkAuditSyslogWriter.ps1" -f $FullInstallPath)
$PowershellPath = (Get-Command -Name powershell.exe).Source

$OneDay = New-TimeSpan -Days 1
$FiveMinutes = New-TimeSpan -Minutes 5
$RepeatingTrigger = New-ScheduledTaskTrigger -Once -RepetitionInterval $FiveMinutes -RepetitionDuration $OneDay -at 00:00
$TaskTrigger = New-ScheduledTaskTrigger -Daily -DaysInterval 1 -at 00:00
$TaskTrigger.Repetition = $RepeatingTrigger.Repetition

$TaskAction = New-ScheduledTaskAction -Execute $PowershellPath -Argument ('-file "{0}"' -f $ScriptPath)

$TaskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount

$TaskSettings = New-ScheduledTaskSettingsSet -Disable

$TaskConfiguration = New-ScheduledTask -Action $TaskAction -Settings $TaskSettings -Trigger $TaskTrigger -Principal $TaskPrincipal

$TaskName = "CyberArk Community Audit Service Syslog Writer"

try {
    $CurrentTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    If ($CurrentTask) {
        Write-Host ("Scheduled task already exists. Delete it if you want this script to recreate it.")
    }
    else {
        Write-Host ("Creating scheduled task: {0}" -f $TaskName)
        $null = Register-ScheduledTask -InputObject $TaskConfiguration -TaskName $TaskName
        Write-Host "Configured Audit Syslog Writer, created scheduled task to run every 5 minutes."
        Write-Host "Note: the task is currently disabled. Enable it after completing configuration."
    }
}
catch {
    Write-Host ("Failed to register scheduled task. Error: {0}" -f $_.Exception.Message)
    exit 1
}
Write-Host ("Next steps:")
Write-Host ("  - Create a copy of {0} and name it Config.ini" -f ($FullInstallPath.ToString() + "\Config.example.ini"))
Write-Host ("  - Edit that file to provide your details")
Write-Host ("  - Enable the scheduled task")
Write-Host ("  - Monitor logs for errors")
