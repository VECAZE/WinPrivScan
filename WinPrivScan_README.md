# WinPrivScan — Windows Privilege Escalation Vulnerability Scanner

> A modular Python-based tool that detects local privilege escalation vulnerabilities on Windows systems. Built as a final year project for MSc Cyber Forensics.

---

## What It Does

WinPrivScan scans a live Windows machine across 6 attack vectors commonly used in privilege escalation, generates a per-module risk score, and produces a consolidated HTML or TXT report.

| Module | What It Checks |
|--------|---------------|
| Module 1 | File & folder permissions writable by non-admin users |
| Module 2 | Service misconfigurations — unquoted paths & writable executables |
| Module 3 | Registry key weak permissions (Run keys, Services hive) |
| Module 4 | Processes with `SeImpersonatePrivilege` (token impersonation) |
| Module 5 | Outdated software versions & vulnerable Windows builds |
| Module 6 | Scheduled tasks running as SYSTEM with writable executables |
| Module 7 | Consolidated summary report with total risk score & risk level |

---

## Risk Scoring

Each module assigns a weighted score per finding. The final score maps to:

| Score | Risk Level |
|-------|-----------|
| 0–49 | 🟢 LOW RISK |
| 50–99 | 🟡 MEDIUM RISK |
| 100+ | 🔴 HIGH RISK |

---

## Requirements

- Windows 10 / Windows Server 2016+
- Python 3.12
- Run as **Administrator** (required for registry and token enumeration)

### Install dependencies

```bash
# Create virtual environment
virtualenv -p python3.12 winenv1
winenv1\Scripts\activate

# Install required packages
pip install pywin32 psutil wmi colorama tabulate tqdm
```

---

## Usage

### Run full scan (recommended)

```bash
python winprivscan_launcher.py
```

This runs all 7 modules sequentially, logs output to `logs/winprivscan.log`, and saves reports to `reports/`.

### Run individual modules

```bash
python module1_file_permission_scanner.py --path "C:\Users\Public" --output html
python module2_service_misconfig_scanner.py --output txt
python module3_registry_check.py --output txt
python module4_token_enum.py --output txt
python module5_patch_checker.py --output txt
python module6_task_scanner.py --output txt
python module7_report_generator.py --output html
```

### Arguments

| Argument | Options | Description |
|----------|---------|-------------|
| `--output` | `txt`, `html` | Report format |
| `--path` | any directory path | Target path (Module 1 only) |
| `--silent` | flag | Suppress terminal output |

---

## Output

Reports are saved to the `reports/` folder with timestamps:

```
reports/
├── winprivscan_fileperm_20250527_062654.html
├── winprivscan_services_20250527_062837.txt
├── winprivscan_registry_...txt
├── winprivscan_token_enum_...txt
├── winprivscan_patch_checker_...txt
├── winprivscan_scheduled_tasks_...txt
└── winprivscan_summary_...html   ← consolidated dashboard
```

---

## Project Structure

```
WinPrivScan/
├── winprivscan_launcher.py         # Main launcher — runs all modules
├── module1_file_permission_scanner.py
├── module2_service_misconfig_scanner.py
├── module3_registry_check.py
├── module4_token_enum.py
├── module5_patch_checker.py
├── module6_task_scanner.py
├── module7_report_generator.py
├── utils/
│   └── report_writer.py            # Shared report generation utility
├── reports/                        # Auto-created on first run
├── logs/                           # Auto-created on first run
└── requirements.txt
```

---

## Sample Report Output

Module 2 — Service Misconfiguration:
```
Service: SomeService
Issue:   Unquoted Service Path
Path:    C:\Program Files\Some App\service.exe

Privilege Escalation Score: 20
```

---

## Disclaimer

> This tool is intended **strictly for educational purposes and authorised security assessments only**.  
> Running this tool on systems you do not own or have explicit written permission to test is illegal.  
> The author takes no responsibility for misuse of this tool.

---

## Author

**Jerin Babu**  
MSc Cyber Forensics — Mahatma Gandhi University, Kerala (2025)  
[LinkedIn](https://linkedin.com/in/jerin-babu-281260219)

---

## License

MIT License — free to use for educational and authorised security testing purposes.
