# Linux Privilege-Escalation Audit Toolkit

This is an intern-friendly, **detection-only** Linux security-audit project. It examines the local host for common privilege-escalation risk indicators and produces a JSON report plus a readable Markdown report. It does not run exploits, modify permissions, change services, or make network requests.

Run it only on a system you own or have explicit authorization to audit—your isolated Kali VM is a good learning environment.

## What it checks

- Basic host context: OS, kernel, account, groups, and effective UID
- SUID/SGID regular files, with a separate high-risk-name review category
- World-writable files and world-writable directories without the sticky bit
- Weak permissions on account databases and home directories
- Linux file capabilities through `getcap -r`
- The current account's non-interactive `sudo -l -n` policy, without running any sudo command
- System cron configuration and potentially writable paths referenced by root-context jobs
- Systemd `.service` files, root-context executable paths, and unsafe service `PATH` settings
- Offline kernel advisory rules that you maintain and verify

The report labels results as review leads. An SUID bit, `NOPASSWD`, or a version string is not on its own proof of an exploitable vulnerability.

## Project layout

```text
linux-privesc-audit-toolkit/
├── linux_audit.py              # Main scanner — standard library only
├── data/kernel_advisories.json # Reviewed local advisory rules; starts empty
└── docs/
    ├── learning-guide.md       # Concepts and a lab sequence
    └── submission-checklist.md # Evidence for your internship deliverables
```

## Run on Kali Linux

Copy this whole folder into your Kali VM. From its root directory:

```bash
python3 --version
python3 linux_audit.py --output-dir audit-report
```

For a first quick, low-noise test against a small directory:

```bash
mkdir -p ~/audit-practice
python3 linux_audit.py --scan-root ~/audit-practice --no-getcap --no-sudo --output-dir quick-report
```

Open `audit-report/audit-report.md` after the full scan. The JSON file is useful if you later build a dashboard or additional report formatter.

The scanner is designed to work as an unprivileged user. Running with `sudo` can reveal more metadata, but it can also make every write-permission check look writable to the audit account. For a realistic normal-user escalation review, run it as the intended standard user first.

## How to explain the tool in your review

1. **Collection:** The script gathers local configuration and permission metadata.
2. **Detection:** Each module matches a small, explainable risk pattern.
3. **Triage:** Findings are sorted by severity but require manual validation.
4. **Mitigation:** Every finding carries a specific defensive recommendation.
5. **Safety boundary:** The scanner never executes a discovered binary as root, changes files, or provides an exploitation workflow.

## Kernel CVE method—important limitation

Kernel versions are deceptively hard to map to CVEs. Kali/Debian can backport a fix while retaining an older-looking upstream version. Therefore, this project starts with an empty `data/kernel_advisories.json` and makes no unverified CVE claims. Use the vendor security tracker to validate a package's status, then add a reviewed rule with its official reference. See the learning guide for the safe rule format.

## Requirements

- Kali Linux or another Linux system
- Python 3.9+ (only the Python standard library)
- Optional: `libcap2-bin` for `getcap`; the script gracefully skips it if missing

## Ethical use

Use the tool only in systems and scopes explicitly authorized by the owner. Keep reports private because they can contain hostnames, paths, user names, and security-sensitive configuration details.
