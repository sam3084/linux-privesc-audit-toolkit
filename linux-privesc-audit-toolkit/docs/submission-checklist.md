# Internship Submission Checklist

## Required deliverables

- [ ] `linux_audit.py` runs successfully in the authorized Kali VM.
- [ ] `audit-report/audit-report.md` and `audit-report/audit-report.json` are saved with the submission.
- [ ] Screenshots show the non-root run, progress output, report summary, and one anonymized finding.
- [ ] Each high/critical result is manually validated or clearly marked as a false positive / not applicable.
- [ ] The report states the test scope, authorization, scan date, Kali version, kernel version, and audit account.
- [ ] Each finding includes evidence, impact, severity, and mitigation.
- [ ] Kernel CVE entries cite an official distribution or vendor advisory and state that backports were considered.
- [ ] The final presentation explains that the toolkit is detection-only and did not exploit anything.

## Suggested report structure

1. Executive summary
2. Scope and authorization
3. Lab environment and methodology
4. Toolkit architecture and modules
5. Findings table
6. Evidence and remediation by finding
7. Limitations and false-positive handling
8. Conclusion and future improvements

## Suggested finding table

| ID | Severity | Asset/path | Evidence | Validation outcome | Recommended action |
| --- | --- | --- | --- | --- | --- |
| SUID-002 | Low | `/path/example` | SUID bit set | Expected package behavior / needs owner review | Retain or remove after approval |

## Suggested 8-slide presentation

1. Project title, intern name, and objective
2. The security problem: why permissions and privileged processes matter
3. Scope, authorization, and safety boundary
4. Architecture / workflow
5. Modules and the Linux concepts they assess
6. Demonstration screenshots and report format
7. Validated findings and mitigation plan
8. Limitations, lessons learned, and next steps

## Evidence hygiene

Before handing in reports or screenshots, redact passwords, tokens, internal host names, IP addresses, user names, and any sensitive command output. Store the unredacted report only where your organization permits.
