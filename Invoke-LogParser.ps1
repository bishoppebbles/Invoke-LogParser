<#
.SYNOPSIS
    This is a PowerShell script that wraps LogParser.exe SQL queries written by exp0se for easier execution.  The LogParser.exe program must be installed and the script should be run with administrative privileges.
.DESCRIPTION
    This script was written with the intention to more easily reference and run a series of LogParser.exe queries.  It is primarily driven by switch options to select the query of interest.  Some queries are hard coded while others have options like entering a specific user name, event ID, IP, etc.

    There are queries for the following log types: Security, System, Task Scheduler, Windows Firewall, RDP Remote/Local Sessions. The query switch is prefaced with the log name.
.PARAMETER ProgramPath
    The path of the LogParser.exe program.  The current default is C:\Program Files (x86)\Log Parser*\LogParser.exe.
.PARAMETER SecurityFindEventId
    Search for any events for the specified Security log event ID.
.PARAMETER SecurityEventLogCleared
    The Security event log was cleared (1102).
.PARAMETER SecuritySuccessfulLogon
    Successful logon (4624)
.PARAMETER SecurityFindUser
    Find a specfic user account
.PARAMETER SecurityFindRdpLogins
    Find RDP login events in the Security log (type 10)
.PARAMETER SecurityFindConsoleLogins
    Find console login events in the Security log (type 2)
.PARAMETER SecurityFindIp
    Find a specific login IP address
.PARAMETER SecurityNtlmPassTheHash
    Potential evidence of pass-the-hash
.PARAMETER SecurityNtlmGroupByUsers
    Group by NTLM users
.PARAMETER SecurityGroupByUsers
    Group by NTLM username logon count
.PARAMETER SecurityGroupByDomain
    Group by domain logon count
.PARAMETER SecurityGroupyByAuthenticationPackage
    Group by authentication package logon count
.PARAMETER SecurityGroupyByLoginType
    Group by login type logon count
.PARAMETER SecurityGroupyByWorkstationName
    Group by workstation name logon count
.PARAMETER SecurityGroupyByProcessName
    Group by process name logon count
.EXAMPLE
    Invoke-LogParser.ps1 -SecurityFindEventId 6281

    Searches the Securty event log for the 6281 event ID
.NOTES
    All LogParser.exe queries used in this script were written by or derived from exp0se's logparser.ps1 gihub repo at https://gist.github.com/exp0se/1bae653b790cf5571d20
    
    As of this writing the latest version of LogParser.exe version 2.2 can be download from https://www.microsoft.com/en-us/download/details.aspx?id=24659

    Version 1.0.1
    Sam Pursglove
    expOse (all LogParser.exe SQL queries)
    Last modified: 22 June 2022
#>

[CmdletBinding(DefaultParameterSetName='FindEventId')]
param (
    [Parameter(ParameterSetName='FindEventId', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Find the specified security log event ID')]
    [Int]
    $SecurityFindEventId,

    [Parameter(ParameterSetName='EventIdsSortedByCount', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Event log IDs sorted by count')]
    [Switch]
    $SecurityEventIdsSortedByCount,

    [Parameter(ParameterSetName='EventLogCleared', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Event log was cleared (1102)')]
    [Switch]
    $SecurityEventLogCleared,
    
    [Parameter(ParameterSetName='SuccessfulLogon', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Successful logon (4624)')]
    [Switch]
    $SecuritySuccessfulLogon,

    [Parameter(ParameterSetName='FindUser', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Find a specific user')]
    [String]
    $SecurityFindUser,

    [Parameter(ParameterSetName='FindRdpLogins', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Find RDP login events in the security log (type 10)')]
    [Switch]
    $SecurityFindRdpLogins,

    [Parameter(ParameterSetName='FindConsoleLogins', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Find console login events in the security log (type 2)')]
    [Switch]
    $SecurityFindConsoleLogins,

    [Parameter(ParameterSetName='FindIp', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Find a specific IP address')]
    [String]
    $SecurityFindIp,

    [Parameter(ParameterSetName='NtlmPassTheHash', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Look for potential evidence of pass-the-hash')]
    [Switch]
    $SecurityNtlmPassTheHash,

    [Parameter(ParameterSetName='NtlmGroupByUsers', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Group by NTLM username')]
    [Switch]
    $SecurityNtlmGroupByUsers,

    [Parameter(ParameterSetName='GroupByUsers', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Group by username logon count')]
    [Switch]
    $SecurityGroupByUsers,

    [Parameter(ParameterSetName='GroupByDomain', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Group by domain logon count')]
    [Switch]
    $SecurityGroupByDomain,

    [Parameter(ParameterSetName='GroupByAuthenticationPackage', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Group by authentication package logon count')]
    [Switch]
    $SecurityGroupyByAuthenticationPackage,

    [Parameter(ParameterSetName='GroupByLoginType', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Group by login type logon count')]
    [Switch]
    $SecurityGroupyByLoginType,
    
    [Parameter(ParameterSetName='GroupByWorkstationName', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Group by workstatio name logon count')]
    [Switch]
    $SecurityGroupByWorkstationName,
    
    [Parameter(ParameterSetName='GroupByProcessName', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Group by process name logon count')]
    [Switch]
    $SecurityGroupyByProcessName,

    [Parameter(Mandatory=$False, ValueFromPipeline=$False, HelpMessage='The evtx log file path')]
    [String]
    $ProgramPath = "C:\Program Files (x86)\Log Parser*\LogParser.exe",
    
    [Parameter(Mandatory=$False, ValueFromPipeline=$False, HelpMessage='Use the default event log path')]
    [Switch]
    $DefaultLogPath
 )
 

 # check if the LogParser.exe program is installed
 function Check-LogParser {
    if (!(Test-Path "C:\Program Files (x86)\Log Parser*\LogParser.exe")) {
        Write-Output "LogParser.exe does not appear to be installed. Exiting."
        exit
    }
 }


# check if the shell is running with administrative privileges
function Check-Privileges {
    
    if (!((Get-LocalGroupMember Administrators).Name -like "*$($env:USERNAME)")) {
        Write-Output 'Run the script with elevated privileges for best results and/or the appropriate permissions.'
        
        while (!($input -eq 'Y' -or $input -eq 'y' -or !$input -or $input -eq 'N' -or $input -eq 'n')) {
            $input = Read-Host -Prompt 'Start now? [Y/n]'

            if($input -eq 'Y' -or $input -eq 'y' -or !$input) {
                Start-Process powershell.exe -Verb Runas -ArgumentList  '-Command', "Set-Location $($PWD.ProviderPath); powershell_ise.exe"
                Write-Output 'Prompting for an elevated shell.'
                
                # close the non-privileged powershell process
                Stop-Process -Id $PID
            } elseif ($input -eq 'N' -or $input -eq 'n') {
                Write-Output 'Exiting.'
                exit
            } else {
                Write-Output 'Invalid option.'
            }
        }
    }
}


# Hard coded LogParser.exe Options
$Options  = '-stats:OFF', '-i:EVT', '-q:ON', '-o:CSV'

# "C:\Program Files (x86)\Log Parser*\LogParser.exe" '-stats:OFF', '-i:EVT', '-q:ON', '-o:CSV'

# Event Logs
$SecurityEventLog=            '.\Security.evtx'
$SystemEventLog=              '.\System.evtx'
$TaskSchedulerOperationalLog= '.\Microsoft-Windows-TaskScheduler%4Operational.evtx'
$AdvancedFirewallEventLog=    '.\Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx'
$RdpLocalSessionLog=          '.\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx'
$RdpRemoteConnectionLog=      '.\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx'

# default event log locations
if ($DefaultLogPath) {
    $SecurityEventLog=            'C:\Windows\System32\winevt\Logs\Security.evtx'
    $SystemEventLog=              'C:\Windows\System32\winevt\Logs\System.evtx'
    $TaskSchedulerOperationalLog= 'C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx'
    $AdvancedFirewallEventLog=    'C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx'
    $RdpLocalSessionLog=          'C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx'
    $RdpRemoteConnectionLog=      'C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx'
}


Check-LogParser
Check-Privileges

#$Query = "SELECT * FROM .\Security.evtx WHERE EventID = $SecurityFindEventId"

# Find a security event ID
if($SecurityFindEventId -gt 0) {
    $Query = "SELECT * FROM .\Security.evtx WHERE EventID = $SecurityFindEventId"

# !!!Need to finish!!! Find multiple security event IDs 
} elseif($SecurityFindEventIds) {
    $Query = "SELECT * FROM $SecurityEventLog WHERE EventID IN (4634; 4624)"

# Show event IDs in the Security event log sorted by count
} elseif($SecurityEventIdsSortedByCount) {
    $Query = "SELECT COUNT(*) AS CNT, EventID FROM $SecurityEventLog GROUP BY EventID ORDER BY CNT DESC"

# Eventlog was cleared (1102)
} elseif ($SecurityEventLogCleared) {
    $Query = "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 1, '|') as Username, EXTRACT_TOKEN(Strings, 2, '|') AS Workstation FROM $SecurityEventLog WHERE EventID = '1102'"

# Successful logon (4624)
} elseif ($SecuritySuccessfulLogon) {
    $Query = "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 8, '|') as LogonType,EXTRACT_TOKEN(strings, 9, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 11, '|') AS Workstation, EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName, EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP FROM $SecurityEventLog WHERE EventID = 4624 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY')"

# Find user
} elseif ($SecurityFindUser.Length -gt 0) {
    $Query = "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 8, '|') as LogonType,EXTRACT_TOKEN(strings, 9, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 11, '|') AS Workstation, EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName, EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP FROM $SecurityEventLog WHERE EventID = 4624 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND Username = '$SecurityFindUser'"

# Find RDP logins
} elseif ($SecurityFindRdpLogins) {
    $Query = "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 8, '|') as LogonType,EXTRACT_TOKEN(strings, 9, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 11, '|') AS Workstation, EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName, EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP FROM $SecurityEventLog WHERE EventID = 4624 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND LogonType = '10'"

# Find console logins
} elseif ($SecurityFindConsoleLogins) {
    $Query = "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 8, '|') as LogonType,EXTRACT_TOKEN(strings, 9, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 11, '|') AS Workstation, EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName, EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP FROM $SecurityEventLog WHERE EventID = 4624 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND LogonType = '2'"

# Find a specific IP
} elseif ($SecurityFindIp) {
    $Query = "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 8, '|') as LogonType,EXTRACT_TOKEN(strings, 9, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 11, '|') AS Workstation, EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName, EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP FROM $SecurityEventLog WHERE EventID = 4624 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND SourceIP = '$SecurityFindIp'"

# Look for potential pass-the-hash
} elseif ($SecurityNtlmPassTheHash) {
    $Query = "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 8, '|') as LogonType, EXTRACT_TOKEN(strings, 10, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 11, '|') AS Workstation, EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName, EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP FROM $SecurityEventLog WHERE EventID = 4624 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND AuthPackage LIKE '%NtLmSsp%' AND Username NOT LIKE '%$'"

# Group by NTLM users
} elseif ($SecurityNtlmGroupByUsers) {
    $Query = "SELECT COUNT(*) AS CNT, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 8, '|') as LogonType, EXTRACT_TOKEN(strings, 9, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 11, '|') AS Workstation, EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName, EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP FROM $SecurityEventLog WHERE EventID = 4624 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND AuthPackage LIKE '%NtLmSsp%' AND Username NOT LIKE '%$' GROUP BY Username, Domain, LogonType, AuthPackage, Workstation, ProcessName, SourceIP ORDER BY CNT DESC"

# Group by username logon count
} elseif ($SecurityGroupByUsers) {
    $Query = "SELECT EXTRACT_TOKEN(Strings, 5, '|') as Username, COUNT(*) AS CNT FROM $SecurityEventLog WHERE EventID = 4624 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Username NOT LIKE '%$' GROUP BY Username ORDER BY CNT DESC"

# Group by domain logon count
} elseif ($SecurityGroupByDomain) {
    $Query = "SELECT EXTRACT_TOKEN(Strings, 6, '|') as Domain, COUNT(*) AS CNT FROM $SecurityEventLog WHERE EventID = 4624 GROUP BY Domain ORDER BY CNT DESC"

# Group by authentication package logon count
} elseif ($SecurityGroupyByAuthenticationPackage) {
    $Query = "SELECT EXTRACT_TOKEN(Strings, 9, '|') as AuthPackage, COUNT(*) AS CNT FROM $SecurityEventLog WHERE EventID = 4624 GROUP BY AuthPackage ORDER BY CNT DESC"

# Group by login type logon count
} elseif ($SecurityGroupyByLoginType) {
    $Query = "SELECT EXTRACT_TOKEN(Strings, 8, '|') as LogonType, COUNT(*) AS CNT FROM $SecurityEventLog WHERE EventID = 4624 GROUP BY LogonType ORDER BY CNT DESC"

# Group by workstation name logon count
} elseif ($SecurityGroupByWorkstationName) {
    $Query = "SELECT EXTRACT_TOKEN(Strings, 11, '|') as Workstation, COUNT(*) AS CNT FROM $SecurityEventLog WHERE EventID = 4624 GROUP BY Workstation ORDER BY CNT DESC"

# Group by process name logon count
} elseif ($SecurityGroupyByProcessName) {
    $Query = "SELECT EXTRACT_TOKEN(Strings, 17, '|') as ProcName, COUNT(*) AS CNT FROM $SecurityEventLog WHERE EventID = 4624 GROUP BY ProcName ORDER BY CNT DESC"

# 
} <#elseif () {
    $Query = 

# 
} elseif () {
    $Query = 

# 
} elseif () {
    $Query = 

# 
} elseif () {
    $Query = 

# 
} elseif () {
    $Query = 

# 
} elseif () {
    $Query = 

# 
} elseif () {
    $Query = 

# 
} 

#>

$RunQuery = & $ProgramPath $Options $Query

if($RunQuery) {
    $RunQueryCsv = ConvertFrom-Csv $RunQuery
    $RunQueryCsv
} else {
    Write-Output "No results were found."
}


<#
# Event id 4625
# unsuccessful logon
& "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 10, '|') as LogonType,EXTRACT_TOKEN(strings, 11, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 13, '|') AS Workstation, EXTRACT_TOKEN(Strings, 19, '|') AS SourceIP FROM $SecurityEventLog WHERE EventID = 4625 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY')"

# Find specific User
& "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 10, '|') as LogonType,EXTRACT_TOKEN(strings, 11, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 13, '|') AS Workstation, EXTRACT_TOKEN(Strings, 19, '|') AS SourceIP FROM $SecurityEventLog WHERE EventID = 4625 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND Username = 'Administrator'"


# Find specific IP
& "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 10, '|') as LogonType,EXTRACT_TOKEN(strings, 11, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 13, '|') AS Workstation, EXTRACT_TOKEN(Strings, 19, '|') AS SourceIP FROM $SecurityEventLog WHERE EventID = 4625 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND SourceIP = '10.1.47.151'"

# check ntlm based attempts
& "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 10, '|') as LogonType, EXTRACT_TOKEN(strings, 11, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 13, '|') AS Workstation, EXTRACT_TOKEN(Strings, 19, '|') AS SourceIP FROM $SecurityEventLog WHERE EventID = 4625 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND AuthPackage LIKE '%NtLmSsp%' AND Username NOT LIKE '%$'"

# group by ntlm users
& "SELECT COUNT(*) AS CNT, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 10, '|') as LogonType,EXTRACT_TOKEN(strings, 11, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 13, '|') AS Workstation, EXTRACT_TOKEN(Strings, 19, '|') AS SourceIP FROM $SecurityEventLog WHERE EventID = 4625 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND AuthPackage LIKE '%NtLmSsp%' AND Username NOT LIKE '%$' GROUP BY Username, Domain, LogonType, AuthPackage, Workstation, SourceIP ORDER BY CNT DESC"

# group by Username
& "SELECT COUNT(*) AS CNT, EXTRACT_TOKEN(Strings, 5, '|') as Username FROM $SecurityEventLog WHERE EventID = 4625 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Username NOT LIKE '%$' GROUP BY Username ORDER BY CNT DESC"


# event id 4634
# user logoff

& "Select TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 1, '|') AS Username, EXTRACT_TOKEN(Strings, 2, '|') AS Domain FROM $SecurityEventLog WHERE EventID = 4634 AND Domain NOT IN ('NT AUTHORITY')"


# Event id 4648
# explicit creds was used
& "SELECT timegenerated as date, extract_token(strings, 1, '|') as accountname, extract_token(strings, 2, '|') as domain, extract_token(strings, 5, '|') as usedaccount, extract_token(strings, 6, '|') as useddomain, extract_token(strings, 8, '|') as targetserver, extract_token(strings, 9, '|') as extradata, extract_token(strings, 11, '|') as procname, extract_token(strings, 12, '|') as sourceip FROM $SecurityEventLog WHERE EventID = 4648"

# Search by accountname
& "SELECT timegenerated as date, extract_token(strings, 1, '|') as accountname, extract_token(strings, 2, '|') as domain, extract_token(strings, 5, '|') as usedaccount, extract_token(strings, 6, '|') as useddomain, extract_token(strings, 8, '|') as targetserver, extract_token(strings, 9, '|') as extradata, extract_token(strings, 11, '|') as procname, extract_token(strings, 12, '|') as sourceip FROM $SecurityEventLog WHERE EventID = 4648 AND accountname = 'Administrator'"

# Search by usedaccount
& "SELECT timegenerated as date, extract_token(strings, 1, '|') as accountname, extract_token(strings, 2, '|') as domain, extract_token(strings, 5, '|') as usedaccount, extract_token(strings, 6, '|') as useddomain, extract_token(strings, 8, '|') as targetserver, extract_token(strings, 9, '|') as extradata, extract_token(strings, 11, '|') as procname, extract_token(strings, 12, '|') as sourceip FROM $SecurityEventLog WHERE EventID = 4648 AND usedaccount = 'Administrator'"

# group by accountname
& "SELECT COUNT(*) as CNT, extract_token(strings, 1, '|') as accountname FROM $SecurityEventLog WHERE EventID = 4648 GROUP BY accountname ORDER BY CNT DESC"

# group by used account
& "SELECT COUNT(*) as CNT, extract_token(strings, 5, '|') as usedaccount FROM $SecurityEventLog WHERE EventID = 4648 GROUP BY usedaccount ORDER BY CNT DESC"

# event id 4657
# A registry value was modified
& "SELECT * FROM $SecurityEventLog WHERE EventID = '4657'"


# event id 4663
# An attempt was made to access an object
& "SELECT * FROM $SecurityEventLog WHERE EventID = '4663'"


# Event id 4672
# Admin logon

& "Select TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 1, '|') AS Username, EXTRACT_TOKEN(Strings, 2, '|') AS Domain FROM $SecurityEventLog WHERE EventID = 4672 AND Domain NOT IN ('NT AUTHORITY')

# Find specific user
& "Select TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 1, '|') AS Username, EXTRACT_TOKEN(Strings, 2, '|') AS Domain FROM $SecurityEventLog WHERE EventID = 4672 AND Domain NOT IN ('NT AUTHORITY') AND Username = 'Administrator'"
# group by username
& "Select EXTRACT_TOKEN(Strings, 1, '|') AS Username, COUNT(*) AS CNT FROM $SecurityEventLog WHERE EventID = 4672 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Username NOT LIKE '%$' GROUP BY Username ORDER BY CNT DESC"
# group by domain 
& "Select EXTRACT_TOKEN(Strings, 2, '|') AS Domain, COUNT(*) AS CNT FROM $SecurityEventLog WHERE EventID = 4672 AND Domain NOT IN ('NT AUTHORITY') GROUP BY Domain ORDER BY CNT DESC"

# event id 4688
# new process was created
& "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 1, '|') AS Username, EXTRACT_TOKEN(Strings, 2, '|') AS Domain, EXTRACT_TOKEN(Strings, 5, '|') AS Process FROM $SecurityEventLog WHERE EventID = 4688"

# Search by user
& "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 1, '|') AS Username, EXTRACT_TOKEN(Strings, 2, '|') AS Domain, EXTRACT_TOKEN(Strings, 5, '|') AS Process FROM $SecurityEventLog WHERE EventID = 4688 AND Username = 'Administrator'"

# Search by process name
& "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 1, '|') AS Username, EXTRACT_TOKEN(Strings, 2, '|') AS Domain, EXTRACT_TOKEN(Strings, 5, '|') AS Process FROM $SecurityEventLog WHERE EventID = 4688 AND Process LIKE '%rundll32.exe%'"

# group by username
& "SELECT COUNT(*) AS CNT, EXTRACT_TOKEN(Strings, 1, '|') AS Username FROM $SecurityEventLog WHERE EventID = 4688 GROUP BY Username ORDER BY CNT DESC"

# group by process name
& "SELECT COUNT(*) AS CNT, EXTRACT_TOKEN(Strings, 5, '|') AS Process FROM $SecurityEventLog WHERE EventID = 4688 GROUP BY Process ORDER BY CNT DESC"


# event id 4704
# A user right was assigned
& "SELECT * FROM $SecurityEventLog WHERE EventID = '4704'"

# event id 4705
# A user right was removed
& "SELECT * FROM $SecurityEventLog WHERE EventID = '4705'"

# event id 4706
# A new trust was created to a domain
& "SELECT * FROM $SecurityEventLog WHERE EventID = '4706'"

# event id 4720
# A user account was created 
& "SELECT TimeGenerated AS Date, extract_token(Strings, 0, '|') AS createduser, extract_token(strings, 1, '|') AS createddomain, extract_token(strings, 4, '|') as whocreated, extract_token(strings, 5, '|') AS whodomain FROM $SecurityEventLog WHERE EventID = '4720'"


# Event id 4722
# user account was enabled
& "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM $SecurityEventLog WHERE EventID = 4722"
# event id 4723
# attempt to change password for the account - user changed his own password
& "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM $SecurityEventLog WHERE EventID = 4723"
# event id 4724
# attempt to reset user 
& "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM $SecurityEventLog WHERE EventID = 4724"
# event id 4725 
# user account was disabled
& "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM $SecurityEventLog WHERE EventID = 4725"

# event id 4726
# A user account was deleted 
& "SELECT TimeGenerated AS Date, extract_token(Strings, 0, '|') AS deleteduser, extract_token(strings, 1, '|') AS deleteddomain, extract_token(strings, 4, '|') as whodeleted, extract_token(strings, 5, '|') AS whodomain FROM $SecurityEventLog WHERE EventID = '4726'"

# event id 4727
# A security-enabled global group was created 
& "SELECT *  FROM $SecurityEventLog WHERE EventID = '4727'"

# event id 4728
# A member was added to a security-enabled global group
& "SELECT TimeGenerated AS Date, extract_token(Strings, 0, '|') as addeduser, extract_token(strings, 2, '|') as togroup, extract_token(strings, 3, '|') as groupdomain, extract_token(strings, 6, '|') as whoadded, extract_token(strings, 7, '|') as whodomain FROM $SecurityEventLog WHERE EventID = '4728'"

# event id 4729
# A member was removed from a security-enabled global group
& "SELECT TimeGenerated AS Date, extract_token(Strings, 0, '|') as removeduser, extract_token(strings, 2, '|') as fromgroup, extract_token(strings, 3, '|') as groupdomain, extract_token(strings, 6, '|') as whoremoved, extract_token(strings, 7, '|') as whodomain FROM $SecurityEventLog WHERE EventID = '4729'"

# event id 4730
# A security-enabled global group was deleted
& "SELECT * FROM $SecurityEventLog WHERE EventID = '4730'"


# event id 4731
# A security-enabled local group was created 
& "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as createdgroup, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM $SecurityEventLog WHERE EventID = 4731"

# event id 4732
#  A member was added to a security-enabled local group
& "SELECT TimeGenerated AS Date, extract_token(Strings, 0, '|') as addeduser, extract_token(strings, 2, '|') as togroup, extract_token(strings, 3, '|') as groupdomain, extract_token(strings, 6, '|') as whoadded, extract_token(strings, 7, '|') as whodomain FROM $SecurityEventLog WHERE EventID = '4732'"

# event id 4733
# A member was removed from a security-enabled local group
& "SELECT TimeGenerated AS Date, extract_token(Strings, 0, '|') as removeduser, extract_token(strings, 2, '|') as fromgroup, extract_token(strings, 3, '|') as groupdomain, extract_token(strings, 6, '|') as whoremoved, extract_token(strings, 7, '|') as whodomain FROM $SecurityEventLog WHERE EventID = '4733'"

# event id 4734
#  A security-enabled local group was deleted
& "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 2, '|') AS whichgroup, EXTRACT_TOKEN(Strings, 3, '|') AS domaingroup, EXTRACT_TOKEN(Strings, 6, '|') AS who, EXTRACT_TOKEN(Strings, 7, '|') AS workstation FROM $SecurityEventLog WHERE EventID = 4734"




# event id 4738
# user account was changed 
& "SELECT TimeGenerated AS Date, extract_token(strings, 1, '|') as user, extract_token(strings, 2, '|') as domain, extract_token(strings, 5, '|') as whichaccount, extract_token(strings, 6, '|') as whichdomain FROM $SecurityEventLog WHERE EventID = 4738"

# event id 4740
# A user account was locked out
& "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as workstation, extract_token(strings, 4, '|') as wholocked, extract_token(strings, 5, '|') as whodomain FROM $SecurityEventLog WHERE EventID = '4740'"

# event id 4742
# computer account was changed 
& "SELECT TimeGenerated AS Date, extract_token(strings, 5, '|') as user, extract_token(strings, 6, '|') as domain, extract_token(strings, 1, '|') as whichaccount, extract_token(strings, 2, '|') as whichdomain FROM $SecurityEventLog WHERE EventID = 4742"

# event id 4754
# A security-enabled universal group was created
& "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as createdgroup, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM $SecurityEventLog WHERE EventID = 4754"

# event id 4756
#  	A member was added to a security-enabled universal group
& "SELECT TimeGenerated AS Date, extract_token(Strings, 0, '|') as addeduser, extract_token(strings, 2, '|') as togroup, extract_token(strings, 3, '|') as groupdomain, extract_token(strings, 6, '|') as whoadded, extract_token(strings, 7, '|') as whodomain FROM $SecurityEventLog WHERE EventID = '4756'"

# event id 4757
# A member was removed from a security-enabled universal group
& "SELECT TimeGenerated AS Date, extract_token(Strings, 0, '|') as removeduser, extract_token(strings, 2, '|') as fromgroup, extract_token(strings, 3, '|') as groupdomain, extract_token(strings, 6, '|') as whoremoved, extract_token(strings, 7, '|') as whodomain FROM $SecurityEventLog WHERE EventID = '4757'"

# event id 4758
#  A security-enabled universal group was deleted
& "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 2, '|') AS whichgroup, EXTRACT_TOKEN(Strings, 3, '|') AS domaingroup, EXTRACT_TOKEN(Strings, 6, '|') AS who, EXTRACT_TOKEN(Strings, 7, '|') AS workstation FROM $SecurityEventLog WHERE EventID = 4758"


# event id 4767
# A user account was unlocked
& "SELECT * FROM $SecurityEventLog WHERE EventID = '4767'"


# event id 4768
# Kerberos TGT was requested
& "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 7, '|') as cipher, extract_token(strings, 9, '|') as sourceip FROM $SecurityEventLog WHERE EventID = 4768"

# group by user 
& "SELECT extract_token(strings, 0, '|') as user, COUNT(*) AS CNT FROM $SecurityEventLog WHERE EventID = 4768 AND user NOT LIKE '%$' GROUP BY user ORDER BY CNT DESC"
# group by domain
& "SELECT extract_token(strings, 1, '|') as domain, COUNT(*) AS CNT FROM $SecurityEventLog WHERE EventID = 4768 GROUP BY domain ORDER BY CNT DESC"
# group by cipher
& "SELECT extract_token(strings, 7, '|') as cipher, COUNT(*) AS CNT FROM $SecurityEventLog WHERE EventID = 4768 GROUP BY cipher ORDER BY CNT DESC"

# event id 4769
# Kerberos Service ticket was requested
& "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 2, '|') as service, extract_token(strings, 5, '|') as cipher, extract_token(strings, 6, '|') as sourceip FROM $SecurityEventLog WHERE EventID = 4769"

# group by user 
& "SELECT extract_token(strings, 0, '|') as user, COUNT(*) AS CNT FROM $SecurityEventLog WHERE EventID = 4769 AND user NOT LIKE '%$' GROUP BY user ORDER BY CNT DESC"
# group by domain 
& "SELECT extract_token(strings, 1, '|') as domain, COUNT(*) AS CNT FROM $SecurityEventLog WHERE EventID = 4769 GROUP BY domain ORDER BY CNT DESC"
# group by service
& "SELECT extract_token(strings, 2, '|') as service, COUNT(*) AS CNT FROM $SecurityEventLog WHERE EventID = 4769 GROUP BY service ORDER BY CNT DESC"
# group by cipher
& "SELECT extract_token(strings, 5, '|') as cipher, COUNT(*) AS CNT FROM $SecurityEventLog WHERE EventID = 4769 GROUP BY cipher ORDER BY CNT DESC"




# event id 4771
# kerberos pre-atuhentication failed
& "SELECT TimeGenerated AS Date, extract_token(strings, 0 , '|') as user, extract_token(strings, 6 , '|') as sourceip FROM $SecurityEventLog WHERE EventID = 4771 AND user NOT LIKE '%$'"
# group by user
& "SELECT extract_token(strings, 0, '|') as user, COUNT(user) AS CNT FROM $SecurityEventLog WHERE EventID = 4771 AND user NOT LIKE '%$' GROUP BY user ORDER BY CNT DESC"



# event id 4776
# domain/computer attemped to validate user credentials
& "Select TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 1, '|') AS Username, EXTRACT_TOKEN(Strings, 2, '|') AS Domain FROM $SecurityEventLog WHERE EventID = 4776 AND Domain NOT IN ('NT AUTHORITY') AND Username NOT LIKE '%$'"
# Search by username
& "Select TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 1, '|') AS Username, EXTRACT_TOKEN(Strings, 2, '|') AS Domain FROM $SecurityEventLog WHERE EventID = 4776 AND Domain NOT IN ('NT AUTHORITY') AND Username NOT LIKE '%$' AND Username = 'Administrator'"

# group by username
& "Select EXTRACT_TOKEN(Strings, 1, '|') AS Username, COUNT(*) AS CNT FROM $SecurityEventLog WHERE EventID = 4776 AND Username NOT LIKE '%$' GROUP BY Username ORDER BY CNT DESC"
# group by domain 
& "Select EXTRACT_TOKEN(Strings, 2, '|') AS Domain, COUNT(*) AS CNT FROM $SecurityEventLog WHERE EventID = 4776 GROUP BY Domain ORDER BY CNT DESC"



# event id 4778 
# RDP session reconnected
& "SELECT TimeGenerated AS Date,EXTRACT_TOKEN(Strings, 0, '|') AS Username, EXTRACT_TOKEN(Strings, 1, '|') AS Domain, EXTRACT_TOKEN(Strings, 4, '|') AS Workstation, EXTRACT_TOKEN(Strings, 5, '|') AS SourceIP  FROM $SecurityEventLog WHERE EventID = 4778"

# event id 4779
# RDP session disconnected
& "SELECT TimeGenerated AS Date,EXTRACT_TOKEN(Strings, 0, '|') AS Username, EXTRACT_TOKEN(Strings, 1, '|') AS Domain, EXTRACT_TOKEN(Strings, 4, '|') AS Workstation, EXTRACT_TOKEN(Strings, 5, '|') AS SourceIP  FROM $SecurityEventLog WHERE EventID = 4779"

# event id 4781
# User account was renamed
& "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 0, '|') AS newname, EXTRACT_TOKEN(Strings, 1, '|') AS oldname, EXTRACT_TOKEN(Strings, 2, '|') AS accdomain, EXTRACT_TOKEN(Strings, 5, '|') AS Username, EXTRACT_TOKEN(Strings, 6, '|') AS Domain FROM $SecurityEventLog WHERE EventID = 4781"

# event id 4825
# RDP Access denied
& "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 0, '|') AS Username, EXTRACT_TOKEN(Strings, 1, '|') AS Domain, EXTRACT_TOKEN(Strings, 3, '|') AS SourceIP FROM $SecurityEventLog WHERE EventID = 4825"


# event id 4946
# new exception was added to firewall
& "Select TimeGenerated AS Date, extract_token(strings, 2, '|') as rulename FROM $SecurityEventLog WHERE EventID = 4946"

# group by rule name 
& "Select Count(*) as CNT, extract_token(strings, 2, '|') as rulename FROM $SecurityEventLog WHERE EventID = 4946 GROUP BY rulename ORDER BY CNT DESC"

# event id 4948
# rule was deleted from firewall 
& "Select TimeGenerated AS Date, extract_token(strings, 2, '|') as rulename FROM $SecurityEventLog WHERE EventID = 4948"

# group by rule name
& "Select Count(*) as CNT, extract_token(strings, 2, '|') as rulename FROM $SecurityEventLog WHERE EventID = 4948 GROUP BY rulename ORDER BY CNT DESC"

# event id 5038
# Code integrity determined that the image hash of a file is not valid
& "SELECT * FROM $SecurityEventLog WHERE EventID = '5038'"

# event id 5136
# A directory service object was modified
& "SELECT TimeGenerated AS Date, extract_token(strings, 3, '|') AS Username, extract_token(strings, 4, '|') AS Domain, extract_token(strings, 8, '|') AS objectdn, extract_token(strings, 10, '|') AS objectclass, extract_token(strings, 11, '|') AS objectattrib, extract_token(strings, 13, '|') AS attribvalue FROM $SecurityEventLog WHERE EventID = '5136'"

# group by username 
& "SELECT COUNT(*) AS CNT, extract_token(strings, 3, '|') AS Username FROM $SecurityEventLog WHERE EventID = '5136' GROUP BY Username ORDER BY CNT DESC"

# group by domain 
& "SELECT COUNT(*) AS CNT, extract_token(strings, 4, '|') AS Domain FROM $SecurityEventLog WHERE EventID = '5136' GROUP BY Domain ORDER BY CNT DESC"

# group by objectdn 
& "SELECT COUNT(*) AS CNT, extract_token(strings, 8, '|') AS objectdn FROM $SecurityEventLog WHERE EventID = '5136' GROUP BY objectdn ORDER BY CNT DESC"

# group by objectclass
& "SELECT COUNT(*) AS CNT, extract_token(strings, 10, '|') AS objectclass FROM $SecurityEventLog WHERE EventID = '5136' GROUP BY objectclass ORDER BY CNT DESC"

# group by objectattrib
& "SELECT COUNT(*) AS CNT, extract_token(strings, 11, '|') AS objectattrib FROM $SecurityEventLog WHERE EventID = '5136' GROUP BY objectattrib ORDER BY CNT DESC"

# group by attribvalue
& "SELECT COUNT(*) AS CNT, extract_token(strings, 13, '|') AS attribvalue FROM $SecurityEventLog WHERE EventID = '5136' GROUP BY attribvalue ORDER BY CNT DESC"


# event id 5137
# A directory service object was created
& "SELECT * FROM $SecurityEventLog WHERE EventID = '5137'"

# event id 5138
# A directory service object was undeleted
& "SELECT * FROM $SecurityEventLog WHERE EventID = '5138'"

# event id 5139
# A directory service object was moved
& "SELECT * FROM $SecurityEventLog WHERE EventID = '5139'"

# event id 5141
# A directory service object was deleted
& "SELECT * FROM $SecurityEventLog WHERE EventID = '5141'"

# event id 5140
# A network share object was accessed
& "SELECT * FROM $SecurityEventLog WHERE EventID = '5140'"

# event id 5142
# A network share object was added
& "SELECT * FROM $SecurityEventLog WHERE EventID = '5142'"

# event id 5143
# A network share object was modified
& "SELECT * FROM $SecurityEventLog WHERE EventID = '5143'"

# event id 5144
# A network share object was deleted
& "SELECT * FROM $SecurityEventLog WHERE EventID = '5144'"

# event id 5145
# A network share object was checked to see whether client can be granted desired access
& "SELECT * FROM $SecurityEventLog WHERE EventID = '5145'"


# event id 5154
# The Windows Filtering Platform has permitted an application or service to listen on a port for incoming connections
& "SELECT * FROM $SecurityEventLog WHERE EventID = '5154'"

# event id 5155
# The Windows Filtering Platform has blocked an application or service from listening on a port for incoming connections
& "SELECT * FROM $SecurityEventLog WHERE EventID = '5155'"

# event id 5156
# The Windows Filtering Platform has allowed a connection
& "SELECT * FROM $SecurityEventLog WHERE EventID = '5156'"

# event id 5157
# The Windows Filtering Platform has blocked a connection
& "SELECT * FROM $SecurityEventLog WHERE EventID = '5157'"

# event id 5158
# The Windows Filtering Platform has permitted a bind to a local port
& "SELECT * FROM $SecurityEventLog WHERE EventID = '5158'"

# event id 5159
# The Windows Filtering Platform has blocked a bind to a local port
& "SELECT * FROM $SecurityEventLog WHERE EventID = '5159'"

#############
# System Log
#############
# EventID 7045 
# New Service was installed in system
& "Select TimeGenerated AS Date, extract_token(strings, 0, '|') AS ServiceName, extract_token(strings, 1, '|') AS ServicePath, extract_token(strings, 4, '|') AS ServiceUser FROM System WHERE EventID = 7045"


# EventID 7036
# Service actions
& "Select TimeGenerated AS Date, extract_token(strings, 0, '|') as servicename FROM System WHERE EventID = 7036"

# group by service name
& "Select COUNT(*) as CNT, extract_token(strings, 0, '|') as servicename FROM System WHERE EventID = 7036 GROUP BY servicename ORDER BY CNT DESC"

#####################
# Task Scheduler Log
#####################
# EventID 100 
# Task was run
& "Select TimeGenerated AS Date, extract_token(strings,0, '|') as taskname, extract_token(strings, 1, '|') as username FROM 'Microsoft-Windows-TaskScheduler%4Operational' WHERE EventID = 100"

# group by taskname
& "Select extract_token(strings, 0, '|') as taskname, count(*) as cnt FROM Microsoft-Windows-TaskScheduler%4Operational WHERE EventID = 100 GROUP BY taskname ORDER BY CNT DESC"

# eventid 200
# action was executed
& "Select TimeGenerated AS Date, extract_token(strings,0, '|') as taskname, extract_token(strings, 1, '|') as taskaction FROM Microsoft-Windows-TaskScheduler%4Operational.evtx WHERE EventID = 200"

# group by action
& "Select extract_token(strings, 1, '|') as taskaction, count(*) as cnt FROM Microsoft-Windows-TaskScheduler%4Operational WHERE EventID = 200 GROUP BY taskaction ORDER BY CNT DESC"

# eventid 140
# user updated a task

& "Select TimeGenerated as Date, extract_token(strings, 0, '|') as taskname, extract_token(strings, 1, '|') as user FROM Microsoft-Windows-TaskScheduler%4Operational WHERE EventID = 140"

# group by user
& "Select extract_token(strings, 1, '|') as user, count(*) as cnt FROM Microsoft-Windows-TaskScheduler%4Operational WHERE EventID = 140 GROUP BY user ORDER BY CNT DESC"

# group by taskname
& "Select extract_token(strings, 0, '|') as taskname, count(*) as cnt FROM Microsoft-Windows-TaskScheduler%4Operational WHERE EventID = 140 GROUP BY taskname ORDER BY CNT DESC"

# event id 141 
# user deleted a task
& "Select TimeGenerated as Date, extract_token(strings, 0, '|') as taskname, extract_token(strings, 1, '|') as user FROM Microsoft-Windows-TaskScheduler%4Operational WHERE EventID = 141"
# group by user
& "Select extract_token(strings, 1, '|') as user, count(*) as cnt FROM Microsoft-Windows-TaskScheduler%4Operational WHERE EventID = 141 GROUP BY user ORDER BY CNT DESC"
# group by taskname
& "Select extract_token(strings, 0, '|') as taskname, count(*) as cnt FROM Microsoft-Windows-TaskScheduler%4Operational WHERE EventID = 141 GROUP BY taskname ORDER BY CNT DESC"

#######################
# Windows Firewall Log
#######################
# EventID 2004
# New exception rule was added
& "Select TimeGenerated AS Date, extract_token(strings, 1, '|') as rulename, extract_token(strings, 3, '|') as apppath, extract_token(strings, 22, '|') as changedapp from 'Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall' WHERE EventID = 2004"

# group by apppath
& "Select COUNT(*) as CNT, extract_token(strings, 3, '|') as apppath from 'Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall' WHERE EventID = 2004 GROUP BY apppath ORDER BY CNT DESC"

# event id 2005
# rule was changed 
& "Select TimeGenerated AS Date, extract_token(Strings, 1, '|') as rulename, extract_token(Strings, 3, '|') AS apppath, extract_token(Strings, 4, '|') AS servicename, extract_token(strings, 7, '|') AS localport, extract_token(strings, 22, '|') as modifyingapp  from 'Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall' WHERE EventID = 2005"

# group by apppath
& "Select COUNT(*) as CNT, extract_token(strings, 3, '|') as apppath from 'Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall' WHERE EventID = 2005 GROUP BY apppath ORDER BY CNT DESC"

# group by rulename 
& "Select COUNT(*) as CNT, extract_token(strings, 1, '|') as rulename from 'Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall' WHERE EventID = 2005 GROUP BY rulename ORDER BY CNT DESC"

# group by servicename
& "Select COUNT(*) as CNT, extract_token(strings, 4, '|') as servicename from 'Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall' WHERE EventID = 2005 GROUP BY servicename ORDER BY CNT DESC"

# group by local port
& "Select COUNT(*) as CNT, extract_token(strings, 7, '|') as localport from 'Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall' WHERE EventID = 2005 GROUP BY localport ORDER BY CNT DESC"

# group by modifyingapp
& "Select COUNT(*) as CNT, extract_token(strings, 22, '|') as modifyingapp from 'Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall' WHERE EventID = 2005 GROUP BY modifyingapp ORDER BY CNT DESC"

# event id 2006
# rule was deleted
& "Select TimeGenerated AS Date, extract_token(Strings, 1, '|') as rulename, extract_token(strings, 3, '|') as changedapp from 'Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall' WHERE EventID = 2006"

# group by rulename 
& "Select COUNT(*) as CNT, extract_token(strings, 1, '|') as rulename from 'Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall' WHERE EventID = 2006 GROUP BY rulename ORDER BY CNT DESC"

# group by changedapp
& "Select COUNT(*) as CNT, extract_token(strings, 3, '|') as changedapp from 'Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall' WHERE EventID = 2006 GROUP BY changedapp ORDER BY CNT DESC"

# EventID 2011
# Firewall blocked inbound connections to the application, but did not notify the user
& "Select Timegenerated as date, extract_token(strings, 1, '|') as file, extract_token(strings, 4, '|') as port from 'Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall' WHERE EventID = 2011"

# group by application
& "Select COUNT(*) as CNT, extract_token(strings, 1, '|') as file from 'C:\Windows\system32\winevt\logs\Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall' WHERE EventID = 2011 GROUP BY file ORDER BY CNT DESC"

######################
# RDP LocalSession Log 
# Local logins 
######################
# Event id 21
# Successful logon
& "Select timegenerated as Date, extract_token(strings, 0, '|') as user, extract_token(strings, 2, '|') as sourceip FROM Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational WHERE EventID = 21"

# find specific user
& "Select timegenerated as Date, extract_token(strings, 0, '|') as user, extract_token(strings, 2, '|') as sourceip FROM Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational WHERE EventID = 21 AND user LIKE '%Administrator%'"


# group by user
& "Select extract_token(strings, 0, '|') as user, count(*) as CNT FROM Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational WHERE EventID = 21 GROUP BY user ORDER BY CNT DESC"

#######################
# RDP RemoteSession Log
#######################
# Event ID 1149
# Successful logon
& "Select timegenerated as Date, extract_token(strings, 0, '|') as user, extract_token(strings, 2, '|') as sourceip FROM Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational WHERE EventID = 1149"

# group by user
& "Select extract_token(strings, 0, '|') as user, count(*) as CNT FROM Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational WHERE EventID = 1149 GROUP BY user ORDER BY CNT DESC"
#>