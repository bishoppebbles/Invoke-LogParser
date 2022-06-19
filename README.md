# Invoke-LogParser

This is a PowerShell script that wraps LogParser.exe SQL queries written by [exp0se](https://gist.github.com/exp0se/1bae653b790cf5571d20) for easier execution.  The LogParser.exe program must be installed and the script should be run with administrative privileges.

This script was written with the intention to more easily reference and run a series of LogParser.exe queries.  It is primarily driven by switch options to select the query of interest.  Some queries are hard coded while others have options like entering a specific user name, event ID, IP, etc.

There are queries for the following log types: Security, System, Task Scheduler, Windows Firewall, RDP Remote/Local Sessions.  The query switch is prefaced with the log name.

## Examples
  
```Invoke-LogParser.ps1 -SecurityFindEventId -Event 6281```

Searches the Securty event log for the 6281 event ID

## Dependencies
LogParser.exe must be installed for this script to work.  As of this writing the [LogParser.exe v.2.2](https://www.microsoft.com/en-us/download/details.aspx?id=24659) was used.
