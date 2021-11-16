# Email Notifications about too many failed logins
$EmailFrom = "";
$EmailTo = "";
$SmtpServer = ""
$SmtpPort = "25";

# The main logs directory for Auth logging
$LogDir = "";

$LocalDir = '';
$EmailAlertLog = 'EmailAlerts.log';

# Ealier logs to look for
$EarliestLog = Get-Date -Day 1;

# IPs of failed login attempts to ignore for email alerting
# to be used if you have a vulnerability scanner that attempts brute forcing or common credentials
$IgnoredIps = @(

);


####################################################################################################
# Variable Declarations
####################################################################################################

If ($env:UserName -eq "$(hostname)$") { exit 0; }

Clear-Host;

$AuthEvents = @();
$FailedLogins = 0;

$Win32_BIOS = Get-WMIObject -Class Win32_BIOS;

$UserLogDir = "$LogDir\user\$($env:UserName)";
$UserLogFile = "$UserLogDir\$($env:UserName)_$(Get-Date -UFormat "%b-%Y")_Auth.log";

$HostLogDir = "$LogDir\hostname\$(hostname)";
$HostLogFile = "$HostLogDir\$(hostname)_$(Get-Date -UFormat "%b-%Y")_Auth.log";

$SnLogDir = "$LogDir\serial\$($Win32_BIOS.SerialNumber)";
$SnLogFile = "$SnLogDir\$($Win32_BIOS.SerialNumber)_$(Get-Date -UFormat "%b-%Y")_Auth.log";

$LocalLogFile = "$LocalDir\Auth.log";

$EmailAlertLog = "$LocalDir\$EmailAlertLog";

$EmailParams = @{
    From=$EmailFrom;
    To=$EmailTo;
    Subject="";
    Body="";
    SMTPServer=$SmtpServer;
    port=$SmtpPort;
}


####################################################################################################
# Check if Directory and File Exist 
####################################################################################################

$LocalDir, $LogDir, $UserLogDir, $HostLogDir, $SnLogDir | ForEach-Object {
    If (-NOT (Test-Path -Path $_)){ New-Item -ItemType Directory -Path $_; }
}

$EmailAlertLog, $UserLogFile, $HostLogFile, $SnLogFile, $LocalLogFile | ForEach-Object {
    If (-NOT (Test-Path -Path $_ -PathType Leaf)) { 
        New-Item -ItemType "file" -Path $_ -Force;
        Add-Content $_ "Log File Created:  $(Get-Date)";
        Add-Content $_ "_____________________________________________________________________________________________________________________________________________________________________________________";
        Add-Content $_ "|    EventId     |        Time         |           Event             |             User               |     Origin IP     |   Origin Host    |    Hostname     |    Serial#     |";
    }
}

####################################################################################################
# Failed Authentication Events
####################################################################################################

Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=@(4625); StartTime=$EarliestLog;
} -ErrorAction SilentlyContinue | Select-Object * | ForEach-Object {
    $IpAddress = @('127.0.0.1',$_.Properties[19].Value)[($_.Properties[19].Value -ne $null)];
    If ($IgnoredIps -NotContains $IpAddress) { $FailedLogins++; }
    $AuthEvents += New-Object PSObject -Property @{
        EventId = $_.RecordId;
        Time = Get-Date $_.TimeCreated -UFormat "%d-%b-%Y %R";
        Event = "4625 (Login Failed)";
        User = "$(@($_.Properties[6].Value,".")[!$_.Properties[6].Value];)\$($_.Properties[5].Value)";
        OriginIp = $IpAddress;
        OriginHost = '';
        HostName = hostname;
        HostSN = $Win32_BIOS.SerialNumber;
    }
}

####################################################################################################
# Privilege Use Events
####################################################################################################
<#
Get-WinEvent -FilterHashtable @{
    LogName='System'; Id=@(4672); StartTime=$EarliestLog 
} -ErrorAction SilentlyContinue | Select * | ForEach-Object {
    $_
    $AuthEvents += New-Object PSObject -Property @{
        EventId=$_.RecordId
        Time = Get-Date $_.TimeCreated -UFormat "%d-%b-%Y %R";
        Event = "4625 (Login Failed)";
        User = "$(@($_.Properties[6].Value,".")[!$_.Properties[6].Value];)\$($_.Properties[5].Value)";
        OriginIp = @('127.0.0.1',$_.Properties[19].Value)[$_.Properties[19].Value -ne $null];
    }
}
#>

####################################################################################################
# Lock/Unlock Events
####################################################################################################

Get-WinEvent -FilterHashtable @{ 
    LogName='Security'; Id=@(4800,4801); StartTime=$EarliestLog;
} -ErrorAction SilentlyContinue | Select-Object * | ForEach-Object {
    Switch ($_.Id) {
        4800 { $AuthEvent = "4800 (Lock)"; }
        4801 { $AuthEvent = "4801 (Unlock)"; }
    }
    $AuthEvents += New-Object PSObject -Property @{
        EventId=$_.RecordId
        Time = Get-Date $_.TimeCreated -UFormat "%d-%b-%Y %R";
        Event = $AuthEvent;
        User = "$($_.Properties[2].Value)\$($_.Properties[1].Value)";
        OriginIp = '127.0.0.1';
        OriginHost = '';
        HostName = hostname;
        HostSN = $Win32_BIOS.SerialNumber;
    }
}


####################################################################################################
# Reconnect/Disconnect Events
####################################################################################################

Get-WinEvent -FilterHashtable @{ 
    LogName='Security'; Id=@(4778,4779); StartTime=$EarliestLog 
} -ErrorAction SilentlyContinue | Select-Object * | ForEach-Object {
    Switch ($_.Id) {
        4778 { $AuthEvent = "4778 (Session Reconnect)"; }
        4779 { $AuthEvent = "4779 (Session Disconnect)"; }
    }
    $AuthEvents += New-Object PSObject -Property @{
        EventId=$_.RecordId
        Time = Get-Date $_.TimeCreated -UFormat "%d-%b-%Y %R";
        Event = $AuthEvent;
        User = "$($_.Properties[1].Value)\$($_.Properties[0].Value)";
        OriginIp = "$($_.Properties[5].Value)";
        OriginHost = "$($_.Properties[4].Value)";
        HostName = hostname;
        HostSN = $Win32_BIOS.SerialNumber;
    }
}


####################################################################################################
# Logon/Logoff Events
####################################################################################################

Get-WinEvent -FilterHashtable @{ 
	LogName='System'; ID=@(7001,7002); StartTime=$EarliestLog
} -ErrorAction SilentlyContinue | Select-Object * | ForEach-Object {
    If ($_.Properties[1].Value.Value -like "S-*") {
        Switch ($_.Id) {
            7001 { $AuthEvent = "7001 (Logon)"; }
            7002 { $AuthEvent = "7002 (Logoff)"; }
        }
        $AuthEvents += New-Object PSObject -Property @{
            EventId=$_.RecordId
            Time = Get-Date $_.TimeCreated -UFormat "%d-%b-%Y %R";
            Event = $AuthEvent;
            User = (New-Object System.Security.Principal.SecurityIdentifier $_.Properties[1].Value.Value).Translate([System.Security.Principal.NTAccount]).Value;
            OriginIp = '127.0.0.1';
            OriginHost = '';
            HostName = hostname;
            HostSN = $Win32_BIOS.SerialNumber;
        }
    }
}


####################################################################################################
# Remote Desktop Authentication Events
####################################################################################################

Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; 
    Id=@(1149,1150,1148); StartTime=$EarliestLog;
} -ErrorAction SilentlyContinue | Select-Object * | ForEach-Object {
    Switch ($_.Id) {
        1149 { $AuthEvent = "1149 (RDP Login Success)"; }
        1150 { $AuthEvent = "1150 (RDP Login Failure)"; }
        1148 { $AuthEvent = "1148 (RDP Login Merged)"; }
    }
    $AuthEvents += New-Object PSObject -Property @{
        EventId=$_.RecordId
        Time = Get-Date $_.TimeCreated -UFormat "%d-%b-%Y %R";
        Event = $AuthEvent;
        User = "$($_.Properties[1].Value)\$($_.Properties[0].Value)";
        OriginIp = $_.Properties[2].Value;
        OriginHost = '';
        HostName = hostname;
        HostSN = $Win32_BIOS.SerialNumber;
    }
}

Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational';
    Id=@(21,23,24,25); StartTime=$EarliestLog;
} -ErrorAction SilentlyContinue | Select-Object * | ForEach-Object {
    Switch ($_.Id) {
        21 { $AuthEvent = " 21  (RDP Logon)"; }
        23 { $AuthEvent = " 23  (RDP Logoff)"; }
        24 { $AuthEvent = " 24  (RDP Disconnect)"; }
        25 { $AuthEvent = " 25  (RDP Reconnect)"; }
    }
    $AuthEvents += New-Object PSObject -Property @{
        EventId=$_.RecordId
        Time = Get-Date $_.TimeCreated -UFormat "%d-%b-%Y %R";
        Event = $AuthEvent;
        User = $_.Properties[0].Value;
        OriginIp = @('127.0.0.1',$_.Properties[2].Value)[($_.Properties[2].Value -ne $null)];
        OriginHost = '';
        HostName = hostname;
        HostSN = $Win32_BIOS.SerialNumber;
    }
}


####################################################################################################
# Check Logs and Write Missing Logs
####################################################################################################

$AuthEvents | Sort-Object Time | ForEach-Object {
    $Log = "|  $("$($_.EventId)".PadLeft(12,"0"))  |  $($_.Time)  |  $(($_.Event).padRight(25))  |  $(($_.User).padRight(28))  |  $(($_.OriginIp).padRight(15))  |  $(($_.OriginHost).padRight(14))  |  $(($_.HostName).padRight(12))  |  $(($_.HostSN).padRight(12))  |";
    $UserLogFile, $LocalLogFile, $SnLogFile | ForEach-Object {
        If (-NOT (Select-String -Path $_ -Pattern "$Log" -SimpleMatch)) { 
            Write-Host "Log Does not Exist:  $($Log)";
            Add-Content $_ $Log;
        }
    }
}

####################################################################################################
# Email Alerts for High Count Failed Authorization Attempts
####################################################################################################
$LastEmailAlert = $null;
$PrevAlertFailed = 0;
$PrevAlertTime = $EarliestLog;
If ($FailedLogins -gt 2) {
    $LastEmailAlert = Get-Content -Path $EmailAlertLog;
    If ($LastEmailAlert) {
        $LastAlert = $LastEmailAlert.Split('|');
        $PrevAlertFailed = @(0,$LastAlert[0])[($null -ne $LastAlert[0])];
        $PrevAlertTime = @($EarliestLog,(Get-Date -Date $LastAlert[1]))[($null -ne $LastAlert[1])];
    }
    $TimeSinceLastEmail = New-TimeSpan –Start $PrevAlertTime –End (Get-Date);
    If (!$LastEmailAlert -OR $FailedLogins -gt ($PrevAlertFailed + 2) -OR $TimeSinceLastEmail.TotalHours -gt 11) {
        $html = '<style type="text/css">th{text-align: left; border-bottom: 1pt solid black; padding:0 8px;} td{padding:0 8px;}</style>';
        "$($FailedLogins)|$(Get-Date)" | Out-File -FilePath $EmailAlertLog -Force;
        $EmailParams.Subject = "High Number of Failed Logins - $(hostname)";
        $EmailParams.Body = $html+"Hostname: $(hostname)`n`n"+($AuthEvents | Sort-Object Time | Select-Object EventId,Time,Event,User,OriginIp | ConvertTo-Html -AS Table | Out-String);
        Send-MailMessage @EmailParams -BodyAsHtml;
        "$($FailedLogins)|$(Get-Date)" | Out-File -FilePath $EmailAlertLog -Force;
    }
}
