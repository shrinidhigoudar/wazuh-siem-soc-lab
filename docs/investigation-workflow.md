# Wazuh alert investigation workflow

## Search

In Wazuh Discover:
- Select `wazuh-alerts-*`.
- Choose a time range covering the lab execution.
- Search by rule ID, such as `rule.id:100010` or `rule.id:100011`.

A query can return no results if the selected time range does not include the event timestamp. Widen the range or use the date picker to inspect the relevant period.

## Fields to inspect

| Field | Why it matters |
|---|---|
| `timestamp` | Establishes when the event occurred |
| `agent.name`, `agent.ip`, `agent.id` | Identifies the monitored endpoint |
| `rule.id`, `rule.level`, `rule.description` | Describes the detection and severity |
| `rule.mitre.id`, `rule.mitre.tactic`, `rule.mitre.technique` | Provides ATT&CK context |
| `data.win.eventdata.commandLine` | Shows the executed command |
| `data.win.eventdata.newProcessName` | Identifies the newly created process |
| `data.win.eventdata.parentProcessName` | Helps establish process ancestry |
| `data.win.eventdata.subjectUserName` | Identifies the account associated with the event |

## Triage

1. Confirm the endpoint and event timestamp.
2. Read the complete event rather than relying only on the alert title.
3. Examine the account, process, parent process, and command line.
4. Correlate with adjacent events and other telemetry.
5. Determine whether the activity was an authorised lab simulation.
6. Document evidence, impact, and recommended next steps.
