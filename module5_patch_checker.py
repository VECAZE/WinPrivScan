import wmi
import platform
import argparse
from colorama import init, Fore
from tabulate import tabulate
from utils.report_writer import generate_report

# Init color output
init()

# Known outdated/vulnerable software (demo list)
VULN_SOFTWARE = {
    "7-Zip": "18.05",
    "Java": "8.0.1910.12",
    "Adobe Reader": "19.0",
}

# Example vulnerable Windows builds
VULN_WINDOWS_BUILDS = {
    "10.0.10240": "Initial Windows 10 release (missing many LPE patches)",
    "10.0.14393": "Anniversary Update (several unpatched exploits)",
}

SCORE_PER_SOFTWARE = 30
SCORE_PER_WINDOWS_VERSION = 30

def compare_versions(found, vuln):
    try:
        f = [int(part) for part in found.split('.') if part.isdigit()]
        v = [int(part) for part in vuln.split('.') if part.isdigit()]
        return f < v
    except:
        return False

def check_installed_software():
    c = wmi.WMI()
    vulnerable_apps = []
    score = 0

    for product in c.Win32_Product():
        name = product.Name
        version = product.Version
        for vuln_name in VULN_SOFTWARE:
            if name and vuln_name.lower() in name.lower():
                if version and compare_versions(version, VULN_SOFTWARE[vuln_name]):
                    vulnerable_apps.append([name, version, VULN_SOFTWARE[vuln_name]])
                    score += SCORE_PER_SOFTWARE

    return vulnerable_apps, score

def check_windows_version():
    results = []
    score = 0
    win_ver = platform.version()
    if win_ver in VULN_WINDOWS_BUILDS:
        results.append(["Windows OS", win_ver, VULN_WINDOWS_BUILDS[win_ver]])
        score += SCORE_PER_WINDOWS_VERSION
    return results, score

def run_patch_scan(output_format="txt", silent=False):
    if not silent:
        print(Fore.YELLOW + "\n[+] Scanning for outdated software and vulnerable Windows builds...\n" + Fore.RESET)

    software_issues, software_score = check_installed_software()
    os_issues, os_score = check_windows_version()

    total_score = software_score + os_score

    total_results = [["Software", *row] for row in software_issues] + \
                    [["Windows", *row] for row in os_issues]

    if total_results and not silent:
        print(Fore.RED + "[!] Potential vulnerabilities found:\n" + Fore.RESET)
        print(tabulate(total_results, headers=["Type", "Name", "Installed Version", "Vulnerable Below"]))
    elif not total_results and not silent:
        print(Fore.GREEN + "[+] No known outdated software or OS versions found.\n" + Fore.RESET)

    print(Fore.MAGENTA + f"\n[~] Privilege Escalation Score: {total_score}\n" + Fore.RESET)

    generate_report("patch_checker", ["Type", "Name", "Installed Version", "Vulnerable Below"], total_results, report_type=output_format)

# CLI main entry
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WinPrivScan - Patch/Software Vulnerability Checker (Module 5)")
    parser.add_argument("--output", choices=["txt", "html"], default="txt", help="Report output format")
    parser.add_argument("--silent", action="store_true", help="Suppress terminal output")
    args = parser.parse_args()

    run_patch_scan(output_format=args.output, silent=args.silent)
