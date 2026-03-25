import win32api
import win32con
import win32security
import psutil
import argparse
from tabulate import tabulate
from colorama import init, Fore
from utils.report_writer import generate_report

# Init colors
init()

SCORE_PER_PROCESS = 40

def check_impersonation_privileges(pid):
    try:
        handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)
        token = win32security.OpenProcessToken(handle, win32con.TOKEN_QUERY)
        privileges = win32security.GetTokenInformation(token, win32security.TokenPrivileges)

        for priv_tuple in privileges:
            priv_id = priv_tuple[0]
            priv_name = win32security.LookupPrivilegeName(None, priv_id)
            if priv_name == "SeImpersonatePrivilege":
                return True
    except:
        pass
    return False

def scan_token_impersonation(silent=False):
    results = []
    score = 0

    for proc in psutil.process_iter(['pid', 'name', 'username']):
        try:
            if check_impersonation_privileges(proc.info['pid']):
                results.append([
                    proc.info['pid'],
                    proc.info['name'],
                    proc.info['username']
                ])
                score += SCORE_PER_PROCESS
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue

    return results, score

def run_token_scan(output_format="txt", silent=False):
    if not silent:
        print(Fore.YELLOW + "\n[+] Scanning for impersonation-capable processes (SeImpersonatePrivilege)...\n" + Fore.RESET)

    results, score = scan_token_impersonation(silent=silent)

    if results and not silent:
        print(Fore.RED + "[!] Processes with impersonation privileges found:\n" + Fore.RESET)
        print(tabulate(results, headers=["PID", "Process Name", "User"]))
    elif not results and not silent:
        print(Fore.GREEN + "[+] No impersonation tokens found.\n" + Fore.RESET)

    print(Fore.MAGENTA + f"\n[~] Privilege Escalation Score: {score}\n" + Fore.RESET)

    generate_report("token_enum", ["PID", "Process Name", "User"], results, report_type=output_format)

# CLI entry point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WinPrivScan - Token/Impersonation Scanner (Module 4)")
    parser.add_argument("--output", choices=["txt", "html"], default="txt", help="Report output format")
    parser.add_argument("--silent", action="store_true", help="Suppress terminal output")
    args = parser.parse_args()

    run_token_scan(output_format=args.output, silent=args.silent)
