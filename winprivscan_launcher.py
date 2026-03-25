import subprocess
import sys
import os
import datetime
from tqdm import tqdm
from colorama import Fore, init

init()

# Configuration
SCAN_PATH = r"C:\Users\Public"
OUTPUT_FORMAT = "html"
SILENT = False
LOG_FILE = "logs/winprivscan.log"

SCORE_TAG = "Privilege Escalation Score:"
MODULES = [
    ("File Permission Scanner", "module1_file_permission_scanner.py", ["--path", SCAN_PATH]),
    ("Service Misconfig Scanner", "module2_service_misconfig_scanner.py", []),
    ("Registry Key Scanner", "module3_registry_check.py", []),
    ("Token/Impersonation Scanner", "module4_token_enum.py", []),
    ("Patch Checker", "module5_patch_checker.py", []),
    ("Scheduled Task Scanner", "module6_task_scanner.py", []),
    ("Summary Report Generator", "module7_report_generator.py", [])
]

def log(msg):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {msg}\n")

def get_score_from_output(output):
    for line in output.splitlines():
        if SCORE_TAG in line:
            try:
                return int(line.split(":")[1].strip())
            except:
                return 0
    return 0

def determine_risk_level(score):
    if score >= 100:
        return "🔴 HIGH RISK"
    elif score >= 50:
        return "🟡 MEDIUM RISK"
    return "🟢 LOW RISK"

def run_module(name, script, extra_args=None):
    cmd = [sys.executable, script]
    if extra_args:
        cmd += extra_args
    cmd += ["--output", OUTPUT_FORMAT]
    if SILENT:
        cmd.append("--silent")

    print(Fore.CYAN + f"\n[>] Running: {name}\n" + Fore.RESET)
    result = subprocess.run(cmd, capture_output=True, text=True)
    log(f"\n--- {name} ---\n{result.stdout}")
    if result.stderr:
        log("ERROR:\n" + result.stderr)
    score = get_score_from_output(result.stdout)
    return score

def main():
    os.makedirs("reports", exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    open(LOG_FILE, "w").close()  # Clear old log

    print(Fore.YELLOW + "\n====== WinPrivScan: Full Scan Started ======\n" + Fore.RESET)
    total_score = 0

    for name, script, args in tqdm(MODULES, desc="Running Modules", unit="module"):
        score = run_module(name, script, args)
        total_score += score
        print(Fore.MAGENTA + f"[~] Module Score: {score}\n" + Fore.RESET)

    risk_level = determine_risk_level(total_score)

    print(Fore.CYAN + "\n====== Scan Completed ======")
    print(Fore.GREEN + f"\nTOTAL PRIVILEGE ESCALATION SCORE: {total_score}")
    print(Fore.BLUE + f"RISK LEVEL: {risk_level}\n" + Fore.RESET)

    log(f"\nTOTAL SCORE: {total_score}")
    log(f"RISK LEVEL: {risk_level}")
    print(Fore.YELLOW + f"[+] Logs saved to: {LOG_FILE}" + Fore.RESET)

if __name__ == "__main__":
    main()
