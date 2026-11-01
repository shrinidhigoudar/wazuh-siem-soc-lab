# Detection notes

## Rule 100010 – RDP brute-force

- Alert description in the captured event: `Possible RDP brute-force attack: 5 failed logons within 120 seconds`
- Level: `10`
- Frequency shown: `5`
- MITRE ATT&CK: `T1110` – Brute Force
- Tactic: Credential Access
- Related Windows event in the captured document: `4625` – failed logon

The captured alert is evidence that the configured detection matched repeated failed logon activity. Confirm source details and correlate with other authentication events during triage.

## Rule 100011 – MSHTA invoking PowerShell

- Alert description in the captured event: `Suspicious mshta VBScript execution invoking PowerShell - Possible T1218.005`
- Level: `10`
- Frequency shown in the event: `3`
- MITRE ATT&CK: `T1218.005` – Mshta
- Tactic: Defense Evasion
- Process: `C:\Windows\System32\mshta.exe`
- Parent process: `C:\Windows\System32\cmd.exe`
- Account shown: `labuser`

The captured command line shows an MSHTA VBScript execution path that invokes PowerShell and references an Atomic Red Team test script. This is consistent with a controlled test scenario for the MSHTA technique.

## Configuration reproducibility

The screenshots establish the alert IDs, descriptions, severity, event fields, and ATT&CK mappings. They do not expose the complete underlying Wazuh XML rule definitions or all manager/agent configuration. Add your actual `local_rules.xml` and relevant configuration exports to this repository if you want others to reproduce the exact detections.
