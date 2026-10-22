#!/usr/bin/env python3
"""Linux Privilege-Escalation Audit Toolkit (detection only).

This program inspects the host on which it is run and writes a local report. It
does not run exploits, change permissions, alter services, or contact a network
service. Run it only on systems you own or have explicit permission to audit.
"""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import json
import os
import platform
import re
import shlex
import stat
import subprocess
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

try:  # These modules are Linux/Unix-specific; the tool itself targets Linux.
    import grp
    import pwd
except ImportError:  # Lets --help and syntax checks work on non-Linux hosts.
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
PSEUDO_FILESYSTEMS = ("/proc", "/sys", "/dev", "/run")
SYSTEM_CRON_PATHS = ("/etc/crontab", "/etc/anacrontab")
CRON_DIRECTORIES = ("/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly")
UNIT_DIRECTORIES = ("/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system")

# These names are signals for manual review, not a claim that the installed
# binary is exploitable. The set is deliberately kept small and auditable.
HIGH_RISK_SUID_NAMES = {
    "awk", "bash", "busybox", "cp", "env", "find", "less", "more", "nano",
    "nmap", "perl", "python", "python3", "ruby", "tar", "tee", "vim", "vi",
}
SENSITIVE_PREFIXES = ("/etc/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/usr/local/sbin/", "/opt/", "/var/spool/cron/")


@dataclass
class Finding:
    """One review item. Evidence describes an observation, never an exploit path."""

    finding_id: str
    module: str
    severity: str
    title: str
    path: str
    evidence: str
    impact: str
    mitigation: str
    reference: str = ""


class Audit:
    """Holds scanner state and keeps all report writing in one place."""

    def __init__(self, scan_root: Path, quiet: bool = False) -> None:
        self.scan_root = scan_root
        self.quiet = quiet
        self.findings: list[Finding] = []
        self.stats: Counter[str] = Counter()
        self.notes: list[str] = []

    def log(self, message: str) -> None:
        if not self.quiet:
            print(message, file=sys.stderr)

    def add(
        self,
        finding_id: str,
        module: str,
        severity: str,
        title: str,
        path: str,
        evidence: str,
        impact: str,
        mitigation: str,
        reference: str = "",
    ) -> None:
        self.findings.append(
            Finding(finding_id, module, severity, title, path, evidence, impact, mitigation, reference)
        )


def owner_name(uid: int) -> str:
    if pwd is not None:
        try:
            return pwd.getpwuid(uid).pw_name
        except KeyError:
            pass
    return str(uid)


def group_name(gid: int) -> str:
    if grp is not None:
        try:
            return grp.getgrgid(gid).gr_name
        except KeyError:
            pass
    return str(gid)


def mode_text(mode: int) -> str:
    return stat.filemode(mode) + f" ({mode & 0o7777:04o})"


def file_metadata(path: Path, st: Optional[os.stat_result] = None) -> str:
    try:
        status = st if st is not None else path.lstat()
        return f"mode={mode_text(status.st_mode)}, owner={owner_name(status.st_uid)}:{group_name(status.st_gid)}"
    except OSError as exc:
        return f"metadata unavailable: {exc}"


def any_nonowner_writable(mode: int) -> bool:
    """True for group- or world-writable paths; ownership is reported separately."""
    return bool(mode & (stat.S_IWGRP | stat.S_IWOTH))


def world_writable(mode: int) -> bool:
    return bool(mode & stat.S_IWOTH)


def is_sensitive_path(path: Path) -> bool:
    return str(path).startswith(SENSITIVE_PREFIXES)


def is_pseudo_path(path: Path) -> bool:
    raw = str(path)
    return any(raw == pseudo or raw.startswith(pseudo + os.sep) for pseudo in PSEUDO_FILESYSTEMS)


def iter_paths(audit: Audit, root: Path, skip_pseudo: bool = True) -> Iterable[tuple[Path, os.stat_result]]:
    """Yield local files and directories without following symbolic links.

    Permission errors are expected during an unprivileged audit and are counted,
    not treated as a vulnerability finding.
    """

    def onerror(_error: OSError) -> None:
        audit.stats["walk_errors"] += 1

    for directory, directory_names, file_names in os.walk(root, topdown=True, followlinks=False, onerror=onerror):
        directory_path = Path(directory)
        if skip_pseudo:
            directory_names[:] = [name for name in directory_names if not is_pseudo_path(directory_path / name)]
        for name in ["."] + file_names:
            path = directory_path if name == "." else directory_path / name
            try:
                status = path.lstat()
            except OSError:
                audit.stats["stat_errors"] += 1
                continue
            audit.stats["paths_examined"] += 1
            yield path, status


def collect_system_info(audit: Audit) -> dict[str, Any]:
    """Collect facts needed to put permission findings in context."""
    os_release: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                os_release[key] = value.strip().strip('"')
    except OSError as exc:
        audit.notes.append(f"Could not read /etc/os-release: {exc}")

    uid = os.geteuid() if hasattr(os, "geteuid") else None
    try:
        groups = os.getgroups()
    except AttributeError:
        groups = []
    info = {
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "hostname": platform.node(),
        "username": getpass.getuser(),
        "effective_uid": uid,
        "effective_user": owner_name(uid) if uid is not None else "unknown",
        "groups": [group_name(group) for group in groups],
        "kernel": platform.release(),
        "platform": platform.platform(),
        "os_release": os_release,
        "scan_root": str(audit.scan_root),
    }
    audit.add(
        "SYS-001",
        "system",
        "Info",
        "Audit context collected",
        "/",
        f"user={info['effective_user']} (uid={uid}); kernel={info['kernel']}; OS={os_release.get('PRETTY_NAME', 'unknown')}",
        "Context only. Findings must be interpreted for this host and this auditing account.",
        "Keep the final report with the scan date, host identity, and authorization record.",
    )
    return info


def scan_suid_sgid(audit: Audit, root: Path, skip_pseudo: bool) -> None:
    audit.log("[1/7] Scanning regular files for SUID/SGID permission bits …")
    for path, status in iter_paths(audit, root, skip_pseudo):
        if not stat.S_ISREG(status.st_mode):
            continue
        has_suid = bool(status.st_mode & stat.S_ISUID)
        has_sgid = bool(status.st_mode & stat.S_ISGID)
        if not (has_suid or has_sgid):
            continue
        bits = "+".join(bit for bit, enabled in (("SUID", has_suid), ("SGID", has_sgid)) if enabled)
        high_risk = path.name.lower() in HIGH_RISK_SUID_NAMES
        severity = "High" if high_risk else "Low"
        title = "High-risk program name has SUID/SGID" if high_risk else "SUID/SGID binary requires review"
        audit.add(
            "SUID-001" if high_risk else "SUID-002",
            "suid_sgid",
            severity,
            title,
            str(path),
            f"bits={bits}; {file_metadata(path, status)}",
            "SUID/SGID can run with the file owner's or group's privileges. This result alone does not prove exploitability.",
            "Confirm the binary is required, vendor-supported, root-owned, and not writable by non-administrators. Remove unnecessary privilege bits.",
            "Manual review: verify documented behavior and the installed package version.",
        )
        audit.stats["suid_sgid_files"] += 1


def scan_weak_permissions(audit: Audit, root: Path, skip_pseudo: bool) -> None:
    audit.log("[2/7] Scanning for world-writable files and unsafe directories …")
    for path, status in iter_paths(audit, root, skip_pseudo):
        if stat.S_ISREG(status.st_mode) and world_writable(status.st_mode):
            severity = "High" if is_sensitive_path(path) else "Medium"
            audit.add(
                "PERM-001",
                "permissions",
                severity,
                "World-writable regular file",
                str(path),
                file_metadata(path, status),
                "Any local account may alter this file. Risk increases if a privileged process reads or executes it.",
                "Remove world-write permission unless it is demonstrably required; use a dedicated group and least-privilege ownership instead.",
            )
            audit.stats["world_writable_files"] += 1
        elif stat.S_ISDIR(status.st_mode) and world_writable(status.st_mode) and not (status.st_mode & stat.S_ISVTX):
            severity = "High" if is_sensitive_path(path) else "Medium"
            audit.add(
                "PERM-002",
                "permissions",
                severity,
                "World-writable directory without sticky bit",
                str(path),
                file_metadata(path, status),
                "Any user may create, rename, or remove entries here. A privileged workflow using predictable names may be exposed to replacement attacks.",
                "Use a restricted owner/group and enable the sticky bit only for intended shared temporary directories. Review privileged processes that use this directory.",
            )
            audit.stats["unsafe_directories"] += 1


def scan_sensitive_permissions(audit: Audit) -> None:
    audit.log("[3/7] Checking account files and home-directory permissions …")
    targets = (Path("/etc/passwd"), Path("/etc/shadow"), Path("/etc/group"), Path("/etc/gshadow"))
    for path in targets:
        try:
            status = path.lstat()
        except OSError:
            continue
        mode = status.st_mode
        if path.name in {"shadow", "gshadow"}:
            exposed = mode & (stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH)
            if exposed:
                audit.add(
                    "ACCT-001",
                    "account_permissions",
                    "Critical",
                    "Sensitive account database accessible by all users",
                    str(path),
                    file_metadata(path, status),
                    "Password-hash or account-integrity data may be exposed or altered.",
                    "Restore distribution-recommended ownership and permissions immediately (normally root-owned and not accessible to other users).",
                )
        if mode & stat.S_IWOTH:
            audit.add(
                "ACCT-002",
                "account_permissions",
                "Critical",
                "Account database is world-writable",
                str(path),
                file_metadata(path, status),
                "Any local user can modify account data, which can compromise system authentication and authorization.",
                "Immediately remove world-write permission, investigate changes, and restore the package-default owner, group, and mode.",
            )
        elif mode & stat.S_IWGRP:
            audit.add(
                "ACCT-003",
                "account_permissions",
                "High",
                "Account database is group-writable",
                str(path),
                file_metadata(path, status),
                "Group members may be able to change authentication or authorization data depending on group membership.",
                "Verify the designated administrative group is intentional and use the package-default permission mode.",
            )

    home = Path("/home")
    if home.is_dir():
        try:
            home_entries = list(home.iterdir())
        except OSError as exc:
            audit.notes.append(f"Could not list /home: {exc}")
            home_entries = []
        for entry in home_entries:
            try:
                status = entry.lstat()
            except OSError:
                continue
            if stat.S_ISDIR(status.st_mode) and world_writable(status.st_mode):
                audit.add(
                    "HOME-001",
                    "account_permissions",
                    "Medium",
                    "Home directory is world-writable",
                    str(entry),
                    file_metadata(entry, status),
                    "Other users can modify content that may later be trusted by login shells, desktop sessions, or administrative workflows.",
                    "Restrict the home directory to its owner and required group; inspect shell startup files and SSH configuration for unauthorized changes.",
                )


def scan_capabilities(audit: Audit, enabled: bool) -> None:
    if not enabled:
        audit.notes.append("Capability scan was disabled by command-line option.")
        return
    audit.log("[4/7] Enumerating file capabilities with getcap …")
    try:
        completed = subprocess.run(
            ["getcap", "-r", str(audit.scan_root)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=180,
        )
    except FileNotFoundError:
        audit.notes.append("getcap is not installed; file-capability scan was skipped.")
        return
    except subprocess.TimeoutExpired:
        audit.notes.append("getcap scan timed out after 180 seconds; it was skipped.")
        return
    for line in completed.stdout.splitlines():
        if not line.strip():
            continue
        path_text, _, capability = line.partition(" ")
        high_impact = any(cap in capability for cap in ("cap_setuid", "cap_setgid", "cap_dac_override", "cap_sys_admin"))
        audit.add(
            "CAP-001" if high_impact else "CAP-002",
            "capabilities",
            "High" if high_impact else "Low",
            "High-impact Linux capability assigned" if high_impact else "Linux capability assigned",
            path_text,
            capability.strip(),
            "File capabilities grant selected privileged operations without using SUID. This requires an explicit business justification.",
            "Confirm the package owner and documented purpose. Remove capabilities that are not required and monitor changes to capability assignments.",
        )
        audit.stats["capability_files"] += 1


def scan_sudo(audit: Audit, enabled: bool) -> None:
    if not enabled:
        audit.notes.append("sudo policy check was disabled by command-line option.")
        return
    audit.log("[5/7] Reading non-interactive sudo policy (sudo -l -n) …")
    try:
        completed = subprocess.run(
            ["sudo", "-l", "-n"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=15,
        )
    except FileNotFoundError:
        audit.notes.append("sudo is not installed; sudo policy check was skipped.")
        return
    except subprocess.TimeoutExpired:
        audit.notes.append("sudo -l -n timed out; sudo policy check was skipped.")
        return
    policy = completed.stdout.strip()
    if completed.returncode != 0:
        audit.notes.append("sudo policy could not be read non-interactively for this account (no password was requested).")
        return
    if re.search(r"\bNOPASSWD\b", policy, re.IGNORECASE):
        audit.add(
            "SUDO-001",
            "sudo",
            "High",
            "Passwordless sudo rule present",
            "sudo policy for current user",
            policy[:3000],
            "The current account can run at least one authorized command through sudo without an additional password challenge. Risk depends on the allowed command and argument constraints.",
            "Review each NOPASSWD rule. Limit commands and arguments, avoid editor/interpreter-like programs, and require authentication where appropriate.",
            "This tool did not execute any sudo-authorized command.",
        )
    else:
        audit.add(
            "SUDO-002",
            "sudo",
            "Info",
            "Sudo policy read; no NOPASSWD token observed",
            "sudo policy for current user",
            policy[:3000],
            "The result applies only to the account running this scan and may not include rules requiring a password.",
            "Review sudoers configuration centrally and use least privilege.",
        )


def cron_command_paths(line: str) -> list[Path]:
    """Extract absolute path tokens from a cron command for permission review.

    It deliberately does not interpret shell syntax or execute any part of a job.
    """
    return [Path(token) for token in re.findall(r"(?<![\w.-])(/[A-Za-z0-9_./+@:=~-]+)", line)]


def path_has_nonowner_write(path: Path) -> bool:
    try:
        return any_nonowner_writable(path.lstat().st_mode)
    except OSError:
        return False


def cron_file_is_root_context(path: Path) -> bool:
    return str(path).startswith(("/etc/cron.d/", "/etc/cron.hourly/", "/etc/cron.daily/", "/etc/cron.weekly/", "/etc/cron.monthly/")) or str(path) in SYSTEM_CRON_PATHS


def scan_cron(audit: Audit) -> None:
    audit.log("[6/7] Inspecting system cron configuration and referenced scripts …")
    cron_files: list[Path] = [Path(item) for item in SYSTEM_CRON_PATHS]
    for directory_name in CRON_DIRECTORIES:
        directory = Path(directory_name)
        if directory.is_dir():
            try:
                cron_files.extend(entry for entry in directory.iterdir() if entry.is_file())
            except OSError as exc:
                audit.notes.append(f"Could not read {directory}: {exc}")
    for cron_file in sorted(set(cron_files)):
        try:
            status = cron_file.lstat()
        except OSError:
            continue
        if any_nonowner_writable(status.st_mode):
            audit.add(
                "CRON-001",
                "cron",
                "High",
                "System cron file is writable by a non-owner",
                str(cron_file),
                file_metadata(cron_file, status),
                "A non-owner may alter scheduled work that can run with a privileged account, depending on the cron entry.",
                "Restrict ownership to root and remove group/world write permission. Review cron history and all commands in this file.",
            )
        try:
            lines = cron_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line_number, raw_line in enumerate(lines, 1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            root_context = cron_file_is_root_context(cron_file)
            if cron_file.name == "crontab" or str(cron_file).startswith("/etc/cron.d/"):
                fields = line.split()
                if len(fields) >= 7 and fields[5] == "root":
                    root_context = True
            if not root_context:
                continue
            for command_path in cron_command_paths(line):
                if command_path.exists() and path_has_nonowner_write(command_path):
                    audit.add(
                        "CRON-002",
                        "cron",
                        "High",
                        "Root-context cron job references a non-owner-writable path",
                        str(command_path),
                        f"Referenced by {cron_file}:{line_number}; {file_metadata(command_path)}",
                        "A scheduled privileged process may consume content that another account can change. The exact risk depends on the command and its arguments.",
                        "Make the referenced script/binary and its parent directories root-owned and non-writable by non-administrators. Validate the job's command path and avoid writable temporary locations.",
                    )


def service_exec_paths(content: str) -> list[Path]:
    paths: list[Path] = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped.startswith("ExecStart") or "=" not in stripped:
            continue
        value = stripped.split("=", 1)[1].lstrip("-+!:@")
        try:
            command = shlex.split(value, posix=True)
        except ValueError:
            continue
        if command and command[0].startswith("/"):
            paths.append(Path(command[0]))
    return paths


def service_path_risks(content: str) -> list[str]:
    risks: list[str] = []
    for match in re.finditer(r"(?:^|\s)(?:Environment=)?[\"']?PATH=([^\"'\s]+)", content, re.MULTILINE):
        value = match.group(1)
        for directory in value.split(":"):
            if directory in ("", ".") or not directory.startswith("/"):
                risks.append(f"unsafe PATH element: {directory or '<empty>'}")
                continue
            candidate = Path(directory)
            try:
                if any_nonowner_writable(candidate.lstat().st_mode):
                    risks.append(f"non-owner-writable PATH directory: {candidate}")
            except OSError:
                risks.append(f"PATH directory missing or unreadable: {candidate}")
    return risks


def scan_systemd(audit: Audit) -> None:
    audit.log("[7/7] Inspecting systemd unit files and root-context executable paths …")
    seen: set[Path] = set()
    for directory_name in UNIT_DIRECTORIES:
        directory = Path(directory_name)
        if not directory.is_dir():
            continue
        try:
            unit_files = list(directory.glob("*.service"))
        except OSError as exc:
            audit.notes.append(f"Could not list {directory}: {exc}")
            continue
        for unit_file in unit_files:
            if unit_file in seen:
                continue
            seen.add(unit_file)
            try:
                status = unit_file.lstat()
                content = unit_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if any_nonowner_writable(status.st_mode):
                audit.add(
                    "SVC-001",
                    "systemd",
                    "High",
                    "Systemd service file is writable by a non-owner",
                    str(unit_file),
                    file_metadata(unit_file, status),
                    "A non-owner may be able to alter a system service definition. Services without User= normally run as root.",
                    "Make unit files root-owned and remove group/world write permission. Reload and review service definitions after remediation.",
                )
            user_match = re.search(r"^\s*User\s*=\s*(\S+)", content, re.MULTILINE)
            root_context = user_match is None or user_match.group(1).lower() == "root"
            if not root_context:
                continue
            for executable in service_exec_paths(content):
                if executable.exists() and path_has_nonowner_write(executable):
                    audit.add(
                        "SVC-002",
                        "systemd",
                        "High",
                        "Root-context systemd service runs a non-owner-writable executable",
                        str(executable),
                        f"Referenced by {unit_file}; {file_metadata(executable)}",
                        "A root-context service may execute code whose contents can be changed by a non-owner.",
                        "Make the executable and each parent directory root-owned and non-writable by non-administrators. Use an explicit absolute executable path.",
                    )
            for risk in service_path_risks(content):
                audit.add(
                    "SVC-003",
                    "systemd",
                    "High",
                    "Root-context systemd service has an unsafe PATH setting",
                    str(unit_file),
                    risk,
                    "A service may resolve a command from an unintended location if it relies on an unsafe PATH.",
                    "Use absolute paths in ExecStart and a minimal PATH containing only root-owned, non-writable directories.",
                )


def kernel_version_tuple(version: str) -> tuple[int, ...]:
    match = re.match(r"(\d+(?:\.\d+){0,3})", version)
    if not match:
        return ()
    return tuple(int(part) for part in match.group(1).split("."))


def scan_kernel_advisories(audit: Audit, rules_path: Path) -> None:
    """Match only locally supplied, reviewable advisory rules.

    Distro kernels regularly backport fixes, so the scanner never infers a CVE
    solely from an upstream version number. A match is an investigation lead.
    """
    kernel = platform.release()
    if not rules_path.is_file():
        audit.notes.append(f"Kernel advisory rules not found: {rules_path}; no CVE assertions were made.")
        audit.add(
            "KERN-001",
            "kernel",
            "Info",
            "Kernel advisory database unavailable",
            "/proc/version",
            f"running kernel={kernel}",
            "Kernel age alone cannot reliably establish CVE exposure because distributions backport security fixes.",
            "Compare the installed distribution package version with the vendor security tracker, then maintain reviewed local advisory rules for repeatable checks.",
        )
        return
    try:
        rules = json.loads(rules_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        audit.notes.append(f"Could not read kernel advisory rules: {exc}")
        return
    advisories = rules.get("advisories", [])
    if not isinstance(advisories, list):
        audit.notes.append("Kernel advisory rule file has no valid advisories list.")
        return
    matches = 0
    for advisory in advisories:
        if not isinstance(advisory, dict):
            continue
        pattern = advisory.get("kernel_regex", "")
        if not isinstance(pattern, str) or not pattern:
            continue
        try:
            matched = re.search(pattern, kernel)
        except re.error:
            audit.notes.append(f"Ignored invalid kernel advisory regex: {pattern!r}")
            continue
        if not matched:
            continue
        matches += 1
        audit.add(
            str(advisory.get("id", "KERN-ADV")),
            "kernel",
            str(advisory.get("severity", "High")).title(),
            str(advisory.get("title", "Local kernel advisory rule matched")),
            "/proc/version",
            f"running kernel={kernel}; local rule={rules_path.name}; pattern={pattern}",
            "This is an offline rule match, not proof that the distribution package lacks a backported fix.",
            str(advisory.get("mitigation", "Verify the vendor package status and install the vendor-provided security update if affected.")),
            str(advisory.get("reference", "")),
        )
    if matches == 0:
        audit.add(
            "KERN-002",
            "kernel",
            "Info",
            "No local kernel advisory rule matched",
            "/proc/version",
            f"running kernel={kernel}; advisory rules={len(advisories)}; parsed_version={kernel_version_tuple(kernel)}",
            "No match in the local rule set is not proof that the system is fully patched.",
            "Check your distribution's official security tracker and keep the local rule set reviewed and dated.",
        )


def report_dict(audit: Audit, system_info: dict[str, Any], arguments: argparse.Namespace) -> dict[str, Any]:
    ordered_findings = sorted(audit.findings, key=lambda finding: (SEVERITY_ORDER.get(finding.severity, 99), finding.module, finding.path))
    summary = Counter(finding.severity for finding in ordered_findings)
    return {
        "tool": "Linux Privilege-Escalation Audit Toolkit",
        "tool_version": "0.1.0",
        "safety_scope": "Detection only; no exploits or configuration changes were performed.",
        "system": system_info,
        "options": {
            "scan_root": str(arguments.scan_root),
            "skip_pseudo_filesystems": not arguments.include_pseudo_filesystems,
            "capability_scan": not arguments.no_getcap,
            "sudo_policy_check": not arguments.no_sudo,
        },
        "summary": {severity: summary.get(severity, 0) for severity in SEVERITY_ORDER},
        "scanner_stats": dict(audit.stats),
        "notes": audit.notes,
        "findings": [asdict(finding) for finding in ordered_findings],
    }


def markdown_report(report: dict[str, Any]) -> str:
    system_info = report["system"]
    lines = [
        "# Linux Privilege-Escalation Audit Report",
        "",
        f"- Scan time (UTC): {system_info['timestamp_utc']}",
        f"- Host: `{system_info['hostname']}`",
        f"- OS: {system_info['os_release'].get('PRETTY_NAME', 'unknown')}",
        f"- Kernel: `{system_info['kernel']}`",
        f"- Auditing account: `{system_info['effective_user']}` (uid {system_info['effective_uid']})",
        f"- Scope: `{system_info['scan_root']}`",
        "- Safety: Detection only; the scanner did not execute exploits or change system configuration.",
        "",
        "## Summary",
        "",
        "| Critical | High | Medium | Low | Info |",
        "| ---: | ---: | ---: | ---: | ---: |",
        "| {Critical} | {High} | {Medium} | {Low} | {Info} |".format(**report["summary"]),
        "",
        "## Findings",
        "",
    ]
    for index, finding in enumerate(report["findings"], 1):
        lines.extend(
            [
                f"### {index}. [{finding['severity']}] {finding['title']}",
                "",
                f"- ID / module: `{finding['finding_id']}` / `{finding['module']}`",
                f"- Path: `{finding['path']}`",
                f"- Evidence: {finding['evidence']}",
                f"- Why it matters: {finding['impact']}",
                f"- Recommended remediation: {finding['mitigation']}",
            ]
        )
        if finding["reference"]:
            lines.append(f"- Reference / review note: {finding['reference']}")
        lines.append("")
    if report["notes"]:
        lines.extend(["## Scan limitations and notes", ""])
        lines.extend(f"- {note}" for note in report["notes"])
        lines.append("")
    lines.extend(["## Interpretation", "", "Treat every result as a review lead. Validate ownership, package provenance, service context, and approved operational purpose before assigning a final risk rating or changing a production system.", ""])
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detection-only local Linux privilege-escalation audit scanner.",
        epilog="Run only on systems you own or are explicitly authorized to assess.",
    )
    parser.add_argument("--scan-root", type=Path, default=Path("/"), help="filesystem tree to scan (default: /)")
    parser.add_argument("--output-dir", type=Path, default=Path("audit-report"), help="directory for JSON and Markdown reports")
    parser.add_argument("--kernel-rules", type=Path, default=Path("data/kernel_advisories.json"), help="reviewed local kernel advisory rule file")
    parser.add_argument("--include-pseudo-filesystems", action="store_true", help="also scan /proc, /sys, /dev, and /run when they are below scan root")
    parser.add_argument("--no-getcap", action="store_true", help="skip the getcap capability enumeration")
    parser.add_argument("--no-sudo", action="store_true", help="skip the non-interactive sudo -l policy check")
    parser.add_argument("--quiet", action="store_true", help="suppress progress messages")
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    if sys.platform != "linux":
        print("This audit toolkit must be run on Linux (for example, your Kali VM).", file=sys.stderr)
        return 2
    scan_root = arguments.scan_root.resolve()
    if not scan_root.is_dir():
        print(f"Scan root is not a directory: {scan_root}", file=sys.stderr)
        return 2
    audit = Audit(scan_root, arguments.quiet)
    print("Linux Privilege-Escalation Audit Toolkit — detection only", file=sys.stderr)
    print("Authorized systems only. No exploits or configuration changes are performed.", file=sys.stderr)
    system_info = collect_system_info(audit)
    scan_suid_sgid(audit, scan_root, not arguments.include_pseudo_filesystems)
    scan_weak_permissions(audit, scan_root, not arguments.include_pseudo_filesystems)
    scan_sensitive_permissions(audit)
    scan_capabilities(audit, not arguments.no_getcap)
    scan_sudo(audit, not arguments.no_sudo)
    scan_cron(audit)
    scan_systemd(audit)
    scan_kernel_advisories(audit, arguments.kernel_rules)
    report = report_dict(audit, system_info, arguments)
    output_dir = arguments.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "audit-report.json"
    markdown_path = output_dir / "audit-report.md"
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(markdown_report(report), encoding="utf-8")
    print(f"Report written: {json_path}", file=sys.stderr)
    print(f"Report written: {markdown_path}", file=sys.stderr)
    print("Findings: " + ", ".join(f"{level}={count}" for level, count in report["summary"].items()), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
