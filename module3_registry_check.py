import winreg
import win32security
import ntsecuritycon as con
import os
import argparse
from tabulate import tabulate
from colorama import init, Fore
from utils.report_writer import generate_report

# Init color output
init()

DANGEROUS_GROUPS = ['Users', 'Everyone', 'Authenticated Users']
SCORE_PER_WEAK_KEY = 20

# Registry paths to check
REG_PATHS = {
    "HKLM_Run": (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    "HKCU_Run": (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    "Services": (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
}

def has_weak_permissions(hive, subkey):
    try:
        key = win32security.RegOpenKeyEx(hive, subkey, 0, con.READ_CONTROL)
        sd = win32security.GetSecurityInfo(key, win32security.SE_REGISTRY_KEY,
                                           win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            sid = ace[2]
            name, domain, _ = win32security.LookupAccountSid(None, sid)
            perms = ace[1]
            if any(group in name for group in DANGEROUS_GROUPS):
                if perms & (con.KEY_WRITE | con.KEY_ALL_ACCESS):
                    return True, f"{domain}\\{name}"
    except Exception:
        pass
    return False, None

def scan_registry_keys(silent=False):
    results = []
    score = 0
    for label, (hive, path) in REG_PATHS.items():
        if not silent:
            #print(Fore.CYAN + f"[*] Checking: {label} → {path}" + Fore.RESET)
            print(Fore.CYAN + f"[*] Checking: {label} -> {path}" + Fore.RESET)
        weak, group = has_weak_permissions(hive, path)
        if weak:
            results.append([label, path, group])
            score += SCORE_PER_WEAK_KEY
    return results, score

def run_registry_scan(output_format="txt", silent=False):
    if not silent:
        print(Fore.YELLOW + "\n[+] Scanning critical registry keys for weak permissions...\n" + Fore.RESET)

    results, score = scan_registry_keys(silent=silent)

    if results and not silent:
        print(Fore.RED + "[!] Weak registry permissions found:\n" + Fore.RESET)
        print(tabulate(results, headers=["Label", "Registry Path", "Writable by"]))
    elif not results and not silent:
        print(Fore.GREEN + "[+] No weak registry permissions found.\n" + Fore.RESET)

    print(Fore.MAGENTA + f"\n[~] Privilege Escalation Score: {score}\n" + Fore.RESET)

    generate_report("registry", ["Label", "Registry Path", "Writable by"], results, report_type=output_format)

#CLI Entry
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WinPrivScan - Registry Key Checker (Module 3)")
    parser.add_argument("--output", choices=["txt", "html"], default="txt", help="Report output format")
    parser.add_argument("--silent", action="store_true", help="Suppress terminal output")
    args = parser.parse_args()

    run_registry_scan(output_format=args.output, silent=args.silent)
