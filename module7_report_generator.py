import os
import glob
from datetime import datetime
from colorama import init, Fore
import argparse

init()

MODULES = ["fileperm", "services", "registry", "token_enum", "patch_checker", "scheduled_tasks"]

def get_latest_report(module_name, ext="txt"):
    files = glob.glob(f"reports/winprivscan_{module_name}_*.{ext}")
    if not files:
        return None
    latest = max(files, key=os.path.getmtime)
    return latest

def extract_score_from_file(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if "Privilege Escalation Score" in line:
                    parts = line.strip().split(":")
                    if len(parts) == 2:
                        return int(parts[1].strip())
    except:
        pass
    return 0

def determine_risk_level(score):
    if score >= 100:
        return "🔴 HIGH RISK"
    elif score >= 50:
        return "🟡 MEDIUM RISK"
    else:
        return "🟢 LOW RISK"

def generate_summary_report(output_format="txt"):
    collected = []
    total_score = 0

    for mod in MODULES:
        path = get_latest_report(mod, "txt")
        if path:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().strip()
                issue_count = max(content.count("\n") - 3, 0)
                score = extract_score_from_file(path)
                total_score += score
                snippet = content[:500].replace("\n", " ") + "..." if len(content) > 500 else content
                collected.append((mod, os.path.basename(path), issue_count, score, snippet))

    risk_level = determine_risk_level(total_score)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    os.makedirs("reports", exist_ok=True)
    final_path = f"reports/winprivscan_summary_{timestamp}.{output_format}"

    if output_format == "txt":
        with open(final_path, "w", encoding="utf-8") as f:
            f.write("WinPrivScan - Consolidated Vulnerability Summary Report\n")
            f.write("=" * 70 + "\n")
            for mod, filename, count, score, snippet in collected:
                f.write(f"\n[Module: {mod}]\nIssues Detected: {count}\nScore: {score}\nSource File: {filename}\n")
                f.write(snippet + "\n" + "-" * 60 + "\n")
            f.write(f"\nTOTAL PRIVILEGE ESCALATION SCORE: {total_score}\n")
            f.write(f"RISK LEVEL: {risk_level}\n")
        print(Fore.GREEN + f"\n[+] Summary TXT report saved as: {final_path}\n" + Fore.RESET)

    elif output_format == "html":
        with open(final_path, "w", encoding="utf-8") as f:
            f.write("<html><head><title>WinPrivScan Summary</title></head><body>")
            f.write("<h2>WinPrivScan - Summary Dashboard</h2><hr>")
            for mod, filename, count, score, snippet in collected:
                f.write(f"<h3>{mod} - {count} issues - Score: {score}</h3>")
                f.write(f"<p><b>Source:</b> {filename}</p><pre>{snippet}</pre><hr>")
            f.write(f"<h2>Total Score: {total_score} — {risk_level}</h2>")
            f.write("</body></html>")
        print(Fore.GREEN + f"\n[+] Summary HTML report saved as: {final_path}\n" + Fore.RESET)

# CLI Entry
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WinPrivScan - Unified Report Generator (Module 7)")
    parser.add_argument("--output", choices=["txt", "html"], default="txt", help="Report format")
    args = parser.parse_args()

    generate_summary_report(args.output)
