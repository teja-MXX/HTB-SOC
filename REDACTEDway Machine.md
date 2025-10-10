# Expressway HTB Writeup (Live Logging Style)

- So, I started by running nmap on the target to see what ports are open, and guess what? Only port 22 showed up. Weird, right? Usually, there's more to find.
    
- Then I thought, okay maybe the UDP ports have something, so I ran a UDP scan. Found port 500 but it was closed, which was surprising again.
    
- Still, I ran nmap specifically on port 500 to see if it reveals something. Turns out, port 500 is using ISAKMP, which I remember is something related to VPN handshakes.
    
- I even tried to speed up scanning by increasing the nmap min-rate and scanning all TCP ports, but still only port 22 showed.
    
- I ran some SSH-specific scripts with nmap to get more info about the ssh version and algorithms it uses. Nothing super exciting came up, just the usual SSH stuff.
    
- I started thinking about port 500 more and remembered it’s kinda like the handshake manager for VPNs. It helps two computers agree on encryption and keys before they actually send encrypted data through an IPsec tunnel.
    
- It’s like two spies secretly agreeing on a handshake and language before talking, so ISAKMP negotiates that secret handshake.
    
- I knew there’s a tool called ike-scan that can communicate with this protocol, so I ran `ike-scan -v [target-ip]` to check if the handshake is happening and to grab info.
    
- The output showed a “Main Mode Handshake” with encryption and auth details, and it said it uses PSK (pre-shared key) for authentication, not certificates. That’s cool because maybe I can guess the PSK.
    
- Next, I tried brute forcing the PSK with rockyou.txt using ike-scan, but the PSK ‘123456’ wasn’t right, and the response kept repeating the same handshake without success.
    
- So I switched to an aggressive ike-scan mode to get more info like IDs, random numbers, and the hash that I could try to crack. For this, I had to send requests with an ID, so first I guessed ‘htb’ as an ID.
    
- The aggressive scan with `ike-scan --aggressive --id=htb [target-ip]` gave me a proper handshake including a user ID: `ike@expressway.htb`.
    
- Since that seemed like the real ID expected by the VPN, I sent another aggressive request with that ID to get the hash for cracking, like this:
    
    text
    
    `ike-scan --aggressive --id=ike@expressway.htb [target-ip] -v --pskcrack > ike_handshake.txt`
    
- This gave me the full handshake with all the needed parameters and the hash I could crack offline.
    
- Using psk-crack with rockyou.txt on the dumped handshake, I finally cracked the PSK, which was `freakingrockstarontheroad` (redacted here obviously).
    
- With the PSK in hand, I thought: maybe I can connect through VPN now and explore more ports or services on the internal network.
    
- I created a VPN config file (`expressway.conf`) for vpnc and tried to connect using it, but vpnc asked me for a username and password. Adding XAuth username in the config didn’t help much because I got an invalid exchange error.
    
- Then I figured, maybe strongSwan will be better for connecting, so I set up `/etc/ipsec.conf` with the details I got from ike-scan, including the PSK secret in `/etc/ipsec.secrets`.
    
- When I tried to bring up the connection with strongSwan, I got a “NO_PROPOSAL_CHOSEN” error. Turns out, my client’s encryption algorithms didn’t match what the server wanted.
    
- So I changed the config to use `ike=3des-sha1-modp1024` and `esp=3des-sha1` like the server preferred and restarted strongSwan.
    
- After that, the connection tried to come up and then failed with an authentication error — because the VPN expected XAuth credentials (a username and password) in addition to the PSK.
    
- I thought, okay, the username is probably `ike@expressway.htb` (from the handshake), but what about the password?
    
- I decided to brute force the password with hydra against the XAuth mechanism:
    
    text
    
    `hydra -t 4 -P /usr/share/wordlists/rockyou.txt ike@expressway.htb xauth-ipsec-ike`
    
- Then I realized, I could have just tried these credentials with SSH. Facepalm moment.
    
- I SSH’ed in with the credentials I probably found from the previous steps.
    
- When I tried `sudo -l`, it said no permissions, but I found a `sudo.sh` script in my home directory.
    
- The script claimed to be a proof of concept exploit for CVE-2025-32463, so I gave it execute permission and ran it. Suddenly, I was root! Didn’t need to do anything else.
    
- After that, I checked the CVE details for curiosity, but honestly, the root part was already sorted by just running that script.
    
- So, final creds and keys (redacted here) were:
    
    text
    
    `ike@expressway.htb : freakingrockstarontheroad`
    
- The nmap scan file showed only port 22 open for TCP and port 500 closed for UDP.
    
- The ike-scan handshake output was saved in ike_handshake.txt with all handshake details and the PSK hash.
    
- VPN configs used were saved in `expressway.conf` for vpnc and `/etc/ipsec.conf` for strongSwan with the right tweaks for encryption algorithms.
    
- The PoC script `sudo.sh` was found and used to get root easily.
    

---

## SOC Team Stuff (How to Detect and Respond)

- So if you’re a SOC analyst, you wanna keep an eye on weird script files like sudo.sh appearing in random directories, especially if they mention CVEs or PoCs.
    
- Watch for brute force attempts on VPN protocols, especially xauth-ipsec-ike and SSH, because credential guessing is an easy way in.
    
- Keep your systems patched so nobody can use known CVEs like the one here (2025-32463).
    
- Rotate secrets regularly, especially if you see leaks of PSKs or VPN credentials.
    
- Track VPN connections carefully. Lots of failed connection attempts or unusual connection times could indicate attacks.
    
- Control and audit sudo permissions so no one can run random scripts with root powers.
    
- React fast if you find privilege escalation scripts or new SUID binaries that don’t belong. Isolate the host and do a full triage.
    
- Limit VPN and SSH attempts per user to reduce brute force chances.
    

---

That’s more or less how my head was thinking through the whole box from scanning to root. Followed the handshake, guessed the PSK, danced with VPN configs, brute forced the XAuth password, and then hit the jackpot with that sudo.sh script. Simple but fun.
