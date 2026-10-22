# Learning Guide: Linux Privilege-Escalation Audit Toolkit

## 1. The core idea

Privilege escalation is a condition where a lower-privileged account can influence code or configuration that runs with higher privileges. Your project is an **audit tool**: it identifies conditions worth investigating. It does not try to gain elevated access.

The useful question for every finding is:

> Can a less-trusted user modify something that a more-trusted process will later read or execute?

## 2. Concepts to learn before each module

| Module | Concept | Why it matters |
| --- | --- | --- |
| SUID/SGID | Special permission bits | A program may run with its file owner's or group owner's identity. |
| File permissions | Owner, group, other; read/write/execute | World-write often lets every local account alter a file. |
| Sticky bit | Shared-directory protection | It limits who can remove entries in a shared directory such as `/tmp`. |
| File capabilities | Fine-grained Linux privileges | A file can have selected privileged operations without an SUID bit. |
| sudo | Delegated administration | Broad or passwordless rules need careful approval and command restrictions. |
| cron | Scheduled jobs | A root-run job should never consume scripts users can edit. |
| systemd | Service manager | A service lacking `User=` normally starts as root. |
| kernel advisories | Vendor patch status | Distribution backports mean version-only CVE matching is unreliable. |

## 3. Practical learning sequence in your Kali VM

1. Take a VM snapshot before experimenting.
2. Create a normal non-root test user, sign in as that user, and run the scanner once.
3. Read the Markdown report. For each finding, identify the path, its owner/group/mode, the process that might trust it, and the mitigation.
4. Compare selected results manually using read-only commands:

   ```bash
   find / -xdev -type f -perm /6000 -ls 2>/dev/null
   getcap -r / 2>/dev/null
   sudo -l
   systemctl list-unit-files --type=service
   uname -a
   ```

5. Do not change real operating-system files just to create a finding. Instead, document a finding if your authorized lab already contains one, or create a harmless file only inside a disposable practice directory and remove it after your test.
6. Capture a screenshot of the command, another of the report summary, and a third showing one finding's remediation. Redact usernames, hostnames, and paths if your organization requires it.

## 4. How the code works

`linux_audit.py` is intentionally organized as one function per module:

```text
main()
  ├── collect_system_info()
  ├── scan_suid_sgid()
  ├── scan_weak_permissions()
  ├── scan_sensitive_permissions()
  ├── scan_capabilities()
  ├── scan_sudo()
  ├── scan_cron()
  ├── scan_systemd()
  └── scan_kernel_advisories()
       └── report_dict() → JSON + Markdown reports
```

Every module creates a `Finding` with the same fields: severity, path, evidence, impact, and remediation. That consistent structure makes the final report easy to understand and extend.

## 5. Safe kernel advisory rule format

Only add a kernel rule after checking the official distribution security advisory. This sample illustrates the shape; the regex and reference must be replaced with verified values before use:

```json
{
  "id": "KERN-EXAMPLE-001",
  "title": "Example only — replace with a verified advisory",
  "severity": "High",
  "kernel_regex": "^X\\.Y\\.Z-",
  "mitigation": "Install the vendor package that contains the verified fix, then reboot when required.",
  "reference": "Official vendor advisory URL"
}
```

Use `kernel_regex` to create an investigation lead, not to claim that a host is vulnerable. In your report, record the advisory date, distribution package version, verification method, and whether a reboot is required.

## 6. How to validate a finding responsibly

For each high or critical item:

1. Confirm the file exists and record its owner, group, and numeric mode.
2. Determine whether the privileged context is real—for example, inspect the unit or cron file without changing it.
3. Check whether the permission is intentional and package-managed.
4. Describe the business impact in defensive terms.
5. Recommend the smallest safe fix, then arrange change control before any production modification.

Avoid presenting unvalidated scanner output as a confirmed exploit or CVE.
