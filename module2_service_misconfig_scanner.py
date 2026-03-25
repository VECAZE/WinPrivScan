import win32service
import win32security
import win32api
import win32con
import ntsecuritycon as con
import os
import argparse
from tabulate import tabulate
from datetime import datetime
from colorama import init, Fore

# Init terminal color
init()

DANGEROUS_GROUPS = ['Everyone', 'Authenticated Users', 'Users']
SCORE_UNQUOTED_PATH = 20
SCORE_WRITABLE_EXE = 30

def get_all_services():
    scm_handle = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
    try:
        services = win32service.EnumServicesStatus(
            scm_handle,
            win32service.SERVICE_WIN32,
            win32service.SERVICE_STATE_ALL
        )
        return services
    finally:
        win32service.CloseServiceHandle(scm_handle)

def is_path_unquoted(path):
    return ' ' in path and not path.strip().startswith('"')

def is_writable(path):
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
    except:
        pass
    return False

def scan_services(silent=False):
    vulnerable = []
    score = 0

    for svc in get_all_services():
        name, _, _ = svc

        try:
            scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
            svc_handle = win32service.OpenService(scm, name, win32service.SERVICE_QUERY_CONFIG)
            config = win32service.QueryServiceConfig(svc_handle)
            bin_path = config[3]

            # Check unquoted path
            if is_path_unquoted(bin_path):
                vulnerable.append([name, "Unquoted Service Path", bin_path])
                score += SCORE_UNQUOTED_PATH

            # Check writable EXE
            actual_path = bin_path.strip('"').split(' ')[0]
            if os.path.exists(actual_path) and is_writable(actual_path):
                vulnerable.append([name, "Writable Executable", actual_path])
                score += SCORE_WRITABLE_EXE

            win32service.CloseServiceHandle(svc_handle)
            win32service.CloseServiceHandle(scm)

        except Exception:
            continue

    return vulnerable, score

def generate_report(results, report_type='txt', score=0):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    os.makedirs("reports", exist_ok=True)
    filename = f"reports/winprivscan_services_{timestamp}.{report_type}"

    if report_type == 'txt':
        with open(filename, 'w') as f:
            f.write("WinPrivScan - Service Misconfiguration Report\n")
            f.write("=" * 70 + "\n")
            for entry in results:
                f.write(f"Service: {entry[0]}\nIssue: {entry[1]}\nPath: {entry[2]}\n\n")
            f.write(f"Privilege Escalation Score: {score}\n")
        print(Fore.GREEN + f"\n[+] TXT report saved as: {filename}\n" + Fore.RESET)

    elif report_type == 'html':
        with open(filename, 'w') as f:
            f.write("<html><head><title>WinPrivScan Service Report</title></head><body>")
            f.write("<h2>WinPrivScan - Service Misconfiguration Report</h2><hr><ul>")
            for entry in results:
                f.write(f"<li><b>Service:</b> {entry[0]}<br><b>Issue:</b> {entry[1]}<br><b>Path:</b> {entry[2]}</li><br>")
            f.write("</ul>")
            f.write(f"<h3>Total Privilege Escalation Score: {score}</h3>")
            f.write("</body></html>")
        print(Fore.GREEN + f"\n[+] HTML report saved as: {filename}\n" + Fore.RESET)

def main():
    parser = argparse.ArgumentParser(description="WinPrivScan - Service Misconfiguration Scanner (Module 2)")
    parser.add_argument("--output", choices=['txt', 'html'], default='txt', help="Report output format")
    parser.add_argument("--silent", action='store_true', help="Suppress terminal output")

    args = parser.parse_args()

    if not args.silent:
        print(Fore.YELLOW + "\n[+] Scanning Windows services for misconfigurations...\n" + Fore.RESET)

    results, score = scan_services(silent=args.silent)

    if results and not args.silent:
        print(Fore.RED + "[!] Vulnerable Services Found:\n" + Fore.RESET)
        print(tabulate(results, headers=["Service Name", "Vulnerability", "Path"]))
    elif not results and not args.silent:
        print(Fore.GREEN + "[+] No vulnerable service misconfigurations found.\n" + Fore.RESET)

    print(Fore.MAGENTA + f"\n[~] Privilege Escalation Score: {score}\n" + Fore.RESET)
    generate_report(results, args.output, score=score)

if __name__ == "__main__":
    main()
