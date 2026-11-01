# Wazuh SIEM – SOC Home Lab

A hands-on blue-team lab focused on endpoint monitoring, Windows security-event analysis, and custom detection in **Wazuh**. The lab uses a Windows 11 endpoint monitored by a Wazuh agent and investigates alerts through the Wazuh Discover interface.

## Project overview

The goal of this project was to build practical experience with SIEM-based detection and investigation: ingest endpoint telemetry, identify suspicious activity, inspect the underlying event fields, and relate detections to MITRE ATT&CK.

### Lab environment

| Component | Details |
|---|---|
| SIEM | Wazuh |
| Monitored endpoint | Windows 11 (`Win11-Target`) |
| Wazuh agent ID | `001` |
| Endpoint IP shown in events | `192.168.56.5` |
| Investigation interface | Wazuh Discover |
| Event sources shown | Windows Security Auditing / EventChannel |

> The screenshots document the observed events and alerts. Exact manager deployment details and network configuration are intentionally not assumed where they are not visible in the evidence.

## Detection use cases

### 1. RDP brute-force activity

**Wazuh rule:** `100010`  
**Severity:** Level 10  
**Observed description:** `Possible RDP brute-force attack: 5 failed logons within 120 seconds`  
**MITRE ATT&CK:** [T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/)  
**Tactic:** Credential Access

The alert identifies repeated failed logon activity within a defined time window. The investigated event includes Windows Security event ID `4625` (failed logon) and an `AUDIT_FAILURE` result.

**Investigation points**
- Review the source and target account details in the event.
- Check the number and timing of failed attempts.
- Correlate repeated failures with successful logons or other endpoint activity.
- Validate whether the activity is expected before classifying it as an incident.

### 2. Suspicious MSHTA / VBScript execution invoking PowerShell

**Wazuh rule:** `100011`  
**Severity:** Level 10  
**Observed description:** `Suspicious mshta VBScript execution invoking PowerShell - Possible T1218.005`  
**MITRE ATT&CK:** [T1218.005 – Mshta](https://attack.mitre.org/techniques/T1218/005/)  
**Tactic:** Defense Evasion

The event records `mshta.exe` launching a VBScript command that invokes PowerShell. The expanded event shows:
- New process: `C:\Windows\System32\mshta.exe`
- Parent process: `C:\Windows\System32\cmd.exe`
- Account: `labuser`
- Command line referencing a PowerShell script under `C:\AtomicRedTeam\atomics\T1218.005\`

This is a useful detection scenario because `mshta.exe` is a legitimate Windows utility that can also be abused to execute script content and proxy execution.

**Investigation points**
- Inspect the full command line and process ancestry.
- Confirm whether the script and test activity were intentionally executed.
- Correlate process creation with surrounding endpoint events.
- Treat the alert as suspicious activity requiring validation, not automatic proof of compromise.

## Investigation workflow

1. Open **Wazuh → Discover** and select the `wazuh-alerts-*` index pattern.
2. Set a time range that includes the test activity.
3. Search for the relevant rule ID, for example `rule.id:100010` or `rule.id:100011`.
4. Expand an event and inspect fields such as `agent.name`, `agent.ip`, `data.win.eventdata.commandLine`, `data.win.eventdata.newProcessName`, `data.win.eventdata.parentProcessName`, and `rule.mitre.*`.
5. Record the alert description, severity, timestamp, endpoint, user, process information, and MITRE mapping.
6. Correlate related events before deciding whether the activity is malicious or part of an authorised test.

## Evidence

Screenshots captured from the Wazuh Discover interface are stored in [`screenshots/`](screenshots/).

| Screenshot | Evidence |
|---|---|
| `01-discover-no-results.png` | Example of a query returning no results in the selected time range |
| `02-mshta-process-event.png` | Expanded Windows process event showing `mshta.exe`, its parent process, and command line |
| `03-rdp-bruteforce-alert.png` | RDP brute-force alert and its rule metadata |
| `04-rdp-alert-details.png` | Rule `100010`, level 10, and MITRE T1110 mapping |
| `05-mshta-alert-details.png` | Rule `100011`, level 10, and MITRE T1218.005 mapping |
| `06-mshta-alert-results.png` | Multiple events matching the MSHTA detection |

## Repository structure

```text
wazuh-siem-soc-lab/
├── README.md
├── .gitignore
├── docs/
│   ├── investigation-workflow.md
│   └── detection-notes.md
└── screenshots/
    ├── 01-discover-no-results.png
    ├── 02-mshta-process-event.png
    ├── 03-rdp-bruteforce-alert.png
    ├── 04-rdp-alert-details.png
    ├── 05-mshta-alert-details.png
    └── 06-mshta-alert-results.png
```

## Skills demonstrated

- SIEM deployment concepts and endpoint log monitoring
- Windows Security event analysis
- Alert triage and event-field investigation
- Process and command-line analysis
- Brute-force detection concepts
- Living-off-the-land binary (LOLBin) abuse detection
- MITRE ATT&CK mapping
- Blue-team investigation and documentation

## Notes

This repository documents a controlled learning lab. Run attack simulations only in systems you own or are explicitly authorised to test. The screenshots are evidence of the events observed in this lab; they do not by themselves establish that a real system was compromised.
