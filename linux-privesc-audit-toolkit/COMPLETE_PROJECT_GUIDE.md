# Complete Project Guide

## Project in one sentence

Build a Python tool that audits an authorized Linux machine for common privilege escalation risk indicators and writes a defensive report. The tool detects and explains risk. It never exploits a weakness or modifies the target.

## What you are building

```text
Kali Linux VM
    -> Python scanner
    -> permission and configuration checks
    -> JSON and Markdown report
    -> manual validation
    -> final report, screenshots, and presentation
```

The central security idea is simple:

> A privilege escalation risk exists when a less-trusted user can influence a file, command, or configuration that a more-privileged process later uses.

## Ethical and safe scope

- Run only on your own Kali VM or a system for which you have written authorization.
- Run the first audit as a normal non-root user.
- Do not execute discovered binaries as root.
- Do not change `/etc/passwd`, `/etc/shadow`, systemd services, sudoers, or cron files just to create a finding.
- Do not publish real audit reports with usernames, hostnames, tokens, internal paths, or IP addresses.

## Phase 1: Create the GitHub repository

1. On GitHub, create an empty private repository named `linux-privesc-audit-toolkit`.
2. Do not initialize it with a README or `.gitignore`; this project already has both.
3. Copy the HTTPS repository URL.
4. After extracting the project folder in Kali, run:

```bash
cd ~/Downloads/linux-privesc-audit-toolkit
git init
git add .
git status
git commit -m "Initial detection-only Linux audit toolkit"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/linux-privesc-audit-toolkit.git
git push -u origin main
```

If Git asks for your identity:

```bash
git config --global user.name "Your Name"
git config --global user.email "your-github-email@example.com"
```

Important Git words:

- `git add`: choose changed files for the next snapshot.
- `git commit`: save a local project snapshot with a meaningful message.
- `git push`: upload the committed snapshots to GitHub.
- `git status`: always run this before committing. It tells you what will change.

Useful commit sequence:

```bash
git add .
git commit -m "Add project documentation"
git push

git add linux_audit.py
git commit -m "Add local permission audit modules"
git push

git add README.md docs
git commit -m "Document Kali lab validation workflow"
git push
```

## Phase 2: Run the toolkit in Kali

Copy the ZIP to your Kali VM, extract it, then open a terminal in the extracted directory.

```bash
unzip Linux-Privilege-Escalation-Audit-Toolkit.zip -d linux-privesc-audit-toolkit
cd linux-privesc-audit-toolkit
python3 --version
python3 linux_audit.py --output-dir audit-report
```

The full scan can take a few minutes. It writes:

```text
audit-report/audit-report.md
audit-report/audit-report.json
```

Read the Markdown report first:

```bash
less audit-report/audit-report.md
```

Do not run the first scan with `sudo`. A root scan can make ordinary files appear writable and produces a less realistic normal-user privilege escalation review.

## Phase 3: Learn each scanner module

### 1. System information

The tool records the current user, groups, operating system, kernel version, and effective UID.

Why: a scan result depends on who ran it. A user in the `sudo`, `docker`, or another powerful group has a different risk position from an ordinary user.

Read-only commands:

```bash
id
uname -a
cat /etc/os-release
```

### 2. SUID and SGID files

Linux has special permission bits:

- SUID: a program runs with the file owner's privileges.
- SGID: a program runs with the file group's privileges.

For example, `passwd` is normally SUID root because a normal user must update their own password through a carefully controlled program. That is expected behavior, not automatically a vulnerability.

Manual comparison command:

```bash
find / -xdev -type f -perm /6000 -ls 2>/dev/null
```

What to validate:

1. Is the binary expected on this distribution?
2. Is it root-owned and not writable by a non-administrator?
3. Is it a well-known interpreter, editor, archive tool, or other high-risk program name?
4. Does package ownership explain it?

### 3. World-writable files and directories

Permission categories are owner, group, and other. A world-writable path allows every local account to modify it.

Why it matters: if a root service reads or runs a world-writable script, a lower-privileged user could influence privileged behavior.

The sticky bit is important for shared temporary directories such as `/tmp`. It prevents arbitrary users from deleting each other's files there.

Manual comparison commands:

```bash
find / -xdev -type f -perm -0002 -ls 2>/dev/null
find / -xdev -type d -perm -0002 ! -perm -1000 -ls 2>/dev/null
```

Do not call every world-writable file a privilege escalation. Logs and temporary application data can be intentionally writable. The question is whether a privileged process trusts the file.

### 4. Account file permissions

Important files include:

- `/etc/passwd`: user account metadata. It must never be world-writable.
- `/etc/shadow`: password hashes. It must not be readable or writable by ordinary users.
- `/etc/group` and `/etc/gshadow`: group membership data.

Check safely:

```bash
ls -l /etc/passwd /etc/shadow /etc/group /etc/gshadow
```

An unexpected write permission here is high priority. Do not alter these files for a demonstration.

### 5. Linux capabilities

Capabilities grant selected privileged operations without giving a file complete root privilege. For example, `cap_net_raw` may be legitimate for a network utility. Powerful examples such as `cap_setuid`, `cap_setgid`, `cap_dac_override`, and `cap_sys_admin` need close review.

Manual command:

```bash
getcap -r / 2>/dev/null
```

### 6. Sudo rules

`sudo` delegates administrative commands to selected users. `NOPASSWD` means an allowed sudo command can run without an additional password prompt.

Manual command:

```bash
sudo -l
```

The project uses `sudo -l -n`, which does not prompt for a password and does not run any allowed command.

Validation questions:

1. Which user is covered?
2. Which exact command is allowed?
3. Are arguments restricted?
4. Is passwordless access necessary and approved?

### 7. Cron jobs

Cron schedules commands. System cron jobs may run as root. The dangerous condition is a root-context job that runs or reads a path a non-owner can modify.

Safe inspection commands:

```bash
cat /etc/crontab
ls -la /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly
```

Never edit cron configuration as part of this project unless a supervisor provides a dedicated disposable lab exercise.

### 8. Systemd services

Systemd runs Linux services. A `.service` file without `User=` usually runs as root. Look for:

- group- or world-writable unit files;
- root services that execute non-owner-writable files;
- relative or unsafe `PATH` entries.

Safe inspection commands:

```bash
systemctl list-unit-files --type=service
systemctl cat NAME.service
```

Use `systemctl cat` only for a service you are inspecting. It reads the unit definition; it does not start or change the service.

### 9. Kernel version and CVEs

`uname -r` gives the running kernel version. It is not sufficient to prove a CVE because Linux distributions often backport security fixes without changing the visible upstream version in the way you may expect.

Safe command:

```bash
uname -r
```

Correct reporting language:

- Good: “The scanner identified a local advisory rule match. Vendor package status requires verification.”
- Bad: “The host is vulnerable to CVE-X” based only on a kernel version.

Use official Kali/Debian or vendor advisory information before adding an actual CVE reference to the report.

## Phase 4: Validate findings

For every High or Critical finding, fill in this mini-record:

```text
Finding ID:
Path or service:
Scanner evidence:
Manual command used to validate it:
Expected or unexpected configuration:
Privileged context:
Final severity:
Mitigation:
```

Your final severity must be your own validated conclusion, not just the scanner's initial severity.

Example of safe professional wording:

```text
The scanner identified an SUID file at [path]. Manual review confirmed that it is root-owned and belongs to an expected package. No non-owner write permission was present. The result was classified as expected configuration and no remediation was required.
```

## Phase 5: Capture evidence

Take screenshots of:

1. The normal-user command that starts the scanner.
2. The scanner progress and report location.
3. The report severity summary.
4. One manually validated finding or one expected configuration result.

Before submitting or publishing:

- Blur or redact usernames if required.
- Redact hostnames, IP addresses, tokens, passwords, and organization-specific paths.
- Do not put unredacted `audit-report/` output into a public repository.

## Phase 6: Final report

Open `Linux Privilege Escalation Audit Toolkit Project Report Template.docx` and replace the bracketed fields. Use this section order:

1. Executive summary
2. Scope and authorization
3. Objective
4. Methodology
5. Toolkit architecture
6. Test environment and screenshots
7. Validated findings table
8. Kernel advisory review
9. Limitations
10. Conclusion and next improvement

Do not invent findings. A clean Kali VM may have mostly expected configurations. That is still a valid project if you explain why the scanner flagged them and how you validated them.

## Phase 7: Presentation

Use eight slides:

1. Project title, your name, organization, date
2. Objective and authorized detection-only scope
3. Audit workflow
4. Scanner modules and concepts
5. Report design and manual validation method
6. Kali lab demonstration screenshots
7. Validated findings and mitigation table
8. Conclusion, lessons learned, and next improvement

Keep slides factual. Use your report evidence, not generic claims such as “the system was hacked” or “all SUID files are vulnerable.”

## Suggested repository layout

```text
linux-privesc-audit-toolkit/
├── linux_audit.py
├── README.md
├── .gitignore
├── data/
│   └── kernel_advisories.json
└── docs/
    ├── learning-guide.md
    └── submission-checklist.md
```

Keep generated reports outside Git or ensure they remain ignored. Commit source code, documentation, harmless screenshots after redaction, and any reviewed test cases.

## Common problems

### `python3: command not found`

Kali should include Python 3. Verify with `python3 --version`. If it is missing, install it through the Kali package manager only in your own VM.

### `getcap` not found

The tool skips that module safely. Install the distribution package that provides `getcap` if your supervisor permits it, then rerun the scan.

### Permission denied during scan

Expected for a normal-user audit. The scanner records what it can inspect. Do not automatically rerun as root.

### Git asks for login during `git push`

Complete the browser sign-in or use a GitHub personal access token as instructed by GitHub. Do not share a token in chat, screenshots, source code, or Git commits.

### Git says there is nothing to commit

Run `git status`. It means no tracked project files changed since the previous commit.

## What a strong intern submission demonstrates

- You understand Linux permissions, not only tool output.
- You stayed within an authorized, detection-only scope.
- You made the code readable and documented its limitations.
- You validated findings manually.
- You recommended proportionate defensive fixes.
- Your Git history shows steady, understandable progress.
