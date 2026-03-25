import subprocess
import os
import argparse
from colorama import init, Fore
from tabulate import tabulate
from utils.report_writer import generate_report

# Init colorama
init()

DANGEROUS_GROUPS = ['Users', 'Everyone', 'Authenticated Users']
SCORE_PER_TASK = 30

def parse_schtasks():
    try:
        output = subprocess.check_output(
            ['schtasks', '/query', '/fo', 'CSV', '/v'],
            stderr=subprocess.DEVNULL,
            universal_newlines=True
        )
        return output.splitlines()
    except Exception:
        return []

def extract_tasks(csv_lines):
    import csv
    import io

    results = []
    reader = csv.DictReader(io.StringIO("\n".join(csv_lines)))

    for row in reader:
        name_key = next((k for k in row if "task" in k.lower()), "TaskName")
        user_key = next((k for k in row if "user" in k.lower()), "RunAsUser")
        path_key = next((k for k in row if "run" in k.lower() or "action" in k.lower()), "Task To Run")

        try:
            name = row[name_key]
            user = row[user_key]
            path = row[path_key]

            if 'SYSTEM' in user.upper() or 'ADMIN' in user.upper():
                results.append([name, user, path])
        except KeyError:
            continue

    return results

def is_path_writable(path):
    exe_path = path.strip('"').split(" ")[0]
    if not os.path.exists(exe_path):
        return False
    try:
        output = subprocess.check_output(
            ['icacls', exe_path],
            stderr=subprocess.DEVNULL,
            universal_newlines=True
        )
        for line in output.splitlines():
            if any(group in line and ("(M)" in line or "W" in line) for group in DANGEROUS_GROUPS):
                return True
    except:
        return False
    return False

def scan_scheduled_tasks(silent=False):
    results = []
    score = 0
    raw_csv = parse_schtasks()
    tasks = extract_tasks(raw_csv)

    for name, user, path in tasks:
        if is_path_writable(path):
            results.append([name, user, path])
            score += SCORE_PER_TASK

    return results, score

def run_task_scan(output_format="txt", silent=False):
    if not silent:
        print(Fore.YELLOW + "\n[+] Scanning scheduled tasks for privilege escalation vectors...\n" + Fore.RESET)

    results, score = scan_scheduled_tasks(silent=silent)

    if results and not silent:
        print(Fore.RED + "[!] Insecure scheduled tasks found:\n" + Fore.RESET)
        print(tabulate(results, headers=["Task Name", "Run As", "Executable Path"]))
    elif not results and not silent:
        print(Fore.GREEN + "[+] No insecure scheduled tasks found.\n" + Fore.RESET)

    print(Fore.MAGENTA + f"\n[~] Privilege Escalation Score: {score}\n" + Fore.RESET)

    generate_report("scheduled_tasks", ["Task Name", "Run As", "Executable Path"], results, report_type=output_format)

# CLI Main
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WinPrivScan - Scheduled Task Scanner (Module 6)")
    parser.add_argument("--output", choices=["txt", "html"], default="txt", help="Report format")
    parser.add_argument("--silent", action="store_true", help="Suppress terminal output")
    args = parser.parse_args()

    run_task_scan(output_format=args.output, silent=args.silent)
