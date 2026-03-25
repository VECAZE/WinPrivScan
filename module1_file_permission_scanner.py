import os
import win32security
import ntsecuritycon as con
import argparse
from colorama import init, Fore
from tabulate import tabulate
from datetime import datetime

# Initialize colorama
init()

DANGEROUS_GROUPS = ['Everyone', 'Authenticated Users', 'Users']
SCORE_PER_ISSUE = 25  # Points per vulnerable file/folder

def is_writable_by_non_admin(path):
    try:
        sd = win32security.GetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            return False

        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            sid = ace[2]
            name, domain, _ = win32security.LookupAccountSid(None, sid)
            perms = ace[1]
            if any(group in name for group in DANGEROUS_GROUPS):
                if perms & (con.FILE_GENERIC_WRITE | con.FILE_ALL_ACCESS | con.GENERIC_ALL):
                    return True
    except Exception:
        pass
    return False

def scan_directory(directory, silent=False):
    insecure_entries = []
    if not silent:
        print(Fore.CYAN + f"[*] Scanning: {directory}" + Fore.RESET)

    for root, dirs, files in os.walk(directory):
        for name in dirs + files:
            path = os.path.join(root, name)
            if is_writable_by_non_admin(path):
                insecure_entries.append([path])
    return insecure_entries

def generate_report(results, report_type='txt', score=0):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    os.makedirs("reports", exist_ok=True)
    filename = f"reports/winprivscan_fileperm_{timestamp}.{report_type}"

    if report_type == 'txt':
        with open(filename, 'w') as f:
            f.write("WinPrivScan - File Permission Scan Report\n")
            f.write("=" * 60 + "\n")
            for entry in results:
                f.write(f"{entry[0]}\n")
            f.write("\nScore: " + str(score))
        print(Fore.GREEN + f"\n[+] TXT Report saved as {filename}\n" + Fore.RESET)

    elif report_type == 'html':
        with open(filename, 'w') as f:
            f.write("<html><head><title>WinPrivScan Report</title></head><body>")
            f.write("<h2>WinPrivScan - File Permission Scan Report</h2><hr>")
            f.write("<ul>")
            for entry in results:
                f.write(f"<li>{entry[0]}</li>")
            f.write("</ul>")
            f.write(f"<h3>Total Risk Score: {score}</h3>")
            f.write("</body></html>")
        print(Fore.GREEN + f"\n[+] HTML Report saved as {filename}\n" + Fore.RESET)

def main():
    parser = argparse.ArgumentParser(description="WinPrivScan - File/Folder Permission Scanner (Module 1)")
    parser.add_argument("--path", type=str, required=True, help="Directory path to scan")
    parser.add_argument("--output", choices=['txt', 'html'], default='txt', help="Report output format")
    parser.add_argument("--silent", action='store_true', help="Suppress console output")

    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(Fore.RED + f"[!] Error: Path '{args.path}' does not exist." + Fore.RESET)
        return

    if not args.silent:
        print(Fore.YELLOW + "\n[+] Starting WinPrivScan File Permission Scan...\n" + Fore.RESET)

    results = scan_directory(args.path, silent=args.silent)

    
    score = len(results) * SCORE_PER_ISSUE

    if results and not args.silent:
        print(Fore.RED + "\n[!] Insecure writable permissions found:\n" + Fore.RESET)
        print(tabulate(results, headers=["Writable Path by Non-Admin Users"]))
    elif not results and not args.silent:
        print(Fore.GREEN + "\n[+] No insecure writable permissions found.\n" + Fore.RESET)

    print(Fore.MAGENTA + f"\n[~] Privilege Escalation Score: {score}\n" + Fore.RESET)

    generate_report(results, args.output, score=score)

if __name__ == "__main__":
    main()
