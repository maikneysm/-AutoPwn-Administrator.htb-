# 👤 Administrator HTB - Autopwn Script

This script automates the exploitation process of the `Administrator` machine from Hack The Box.
It is divided into **three phases** to simplify and control manual steps that require user interaction, such as password cracking.
---
## 📜 Requirements

- `impacket` installed (`pip install impacket`)
- `rdate` installed (`sudo apt install rdate`)
- `git` installed to clone external tools
- Tools needed in PATH:
	- `evil-winrm`
	- `hashcat` or `john` (manual cracking)
	-  `ftp` client (for manual file download)
- **Important:** Phase 2 must be run with `sudo` because `rdate` requires root privileges to synchronize system time.
---
## 🛠️ Usage

### Phase 1 - Initial Exploitation

Change the passwords for `Michael` and `Benjamin`.
```bash
python3 administrator_autopwn.py --phase 1
```

> 🚩 **Manual Step After Phase 1:**  
> - Login via FTP as `benjamin` (`pass123`), download `Backup.psafe3`.
> - Crack it manually with Hashcat or John.
> - Extract `Emily`'s password using the [Password Safe program](https://pwsafe.org/).
---
### Phase 2 - Targeted Kerberoast

Run a targeted Kerberoast attack using Emily's password.
```bash
python3 administrator_autopwn.py --phase 2 --emily-pass <EMILY_PASSWORD>
```
If `targetedKerberoast.py` is missing, it will be automatically downloaded.  
Time synchronization with the target will also be performed.
- **Important:** Phase 2 must be run with `sudo` because `rdate` requires root privileges to synchronize system time.

> 🚩 **Manual Step After Phase 2:**  
> - Crack the extracted TGS hash for Ethan using Hashcat.
> - Retrieve `Ethan`'s password.
---
### Phase 3 - DCSync Attack

Dump NTLM hashes from the Domain Controller using Ethan's credentials.
```bash
python3 administrator_autopwn.py --phase 3 --ethan-pass <ETHAN_PASSWORD>
```
This will use `secretsdump.py` or `impacket-secretsdump` if available.  
If Impacket is not installed, you will be prompted.
---
## 🔥 Summary of Phases

| Phase | Description                          |         Manual Step Required          |
| :---: | :----------------------------------- | :-----------------------------------: |
|   1   | Password changes (Michael, Benjamin) | FTP download + crack Emily's password |
|   2   | Targeted Kerberoast (Emily ➞ Ethan)  |        Crack Ethan's TGS hash         |
|   3   | DCSync attack (dump hashes)          |                 None                  |

---
## 📋 Notes

- Only the interactions directly related to the target machine are automated.
- Cracking steps are performed manually to maintain flexibility.
- The script is designed to be lightweight, modular, and easily extendable.
