# Suspicious-PowerShell-Detection
Developed a Microsoft Sentinel and KQL detection for suspicious PowerShell activity, identifying encoded commands, execution policy bypass, and hidden-window execution. Included parent-process context, false-positive tuning, MITRE ATT&amp;CK mapping, analytics rule configuration, entity mapping, alert grouping, and investigation workflow. 


# Suspicious PowerShell Detection Using Microsoft Sentinel & KQL

## 1. Project Overview

This project focuses on identifying potentially suspicious PowerShell execution activity using Microsoft Sentinel and Kusto Query Language (KQL).

PowerShell is a legitimate Windows administration and automation tool. However, attackers also abuse it to execute commands, run scripts, evade detection, and perform malicious activities.

The objective of this project is to develop a detection use case that identifies suspicious PowerShell execution patterns, provides useful investigation context, and supports security analysts during incident investigation.

## 2. Objectives

- Identify suspicious PowerShell process execution.
- Detect encoded PowerShell commands.
- Identify execution policy bypass attempts.
- Detect hidden-window PowerShell execution.
- Combine multiple suspicious indicators into a single detection.
- Analyze parent-process context.
- Perform false-positive analysis and detection tuning.
- Map relevant behaviors to MITRE ATT&CK.
- Design a Microsoft Sentinel scheduled analytics rule.
- Develop an analyst investigation runbook.

## 3. Technologies Used

| Technology | Purpose |
|---|---|
| Microsoft Sentinel | SIEM and analytics rule platform |
| KQL | Detection query development |
| Microsoft Defender XDR | Endpoint process telemetry source |
| DeviceProcessEvents | Process creation telemetry |
| MITRE ATT&CK | Adversary behavior mapping |
| GitHub | Project documentation and version control |

**Telemetry requirement:** `DeviceProcessEvents` is a Microsoft Defender XDR Advanced Hunting table. 

## 4. Detection Use Cases

### 4.1 Suspicious PowerShell Execution

Identifies PowerShell process execution with potentially suspicious command-line characteristics.

### 4.2 Encoded PowerShell Commands

Identifies PowerShell execution using parameters such as:

- `-EncodedCommand`
- `-enc`

Encoded commands may conceal the actual command content and require further analysis.

### 4.3 Execution Policy Bypass

Identifies PowerShell execution using parameters such as:

- `-ExecutionPolicy Bypass`
- `-ep Bypass`

Execution policy bypass is suspicious in some contexts but is not proof of malicious activity.

### 4.4 Hidden PowerShell Execution

Identifies PowerShell execution using parameters such as:

- `-WindowStyle Hidden`
- `-w Hidden`

Hidden execution can be associated with stealthy activity but may also occur in legitimate automation.

### 4.5 Combined Suspicious PowerShell Detection

Combines multiple indicators into one query:

- Encoded command execution
- Execution policy bypass
- Hidden-window execution

The query calculates an indicator count to help prioritize investigation.

The indicator count is a triage aid, not a malware verdict or a calibrated risk score.

## 5. Detection Logic

The detection uses the following endpoint telemetry fields:

| Field | Purpose |
|---|---|
| Timestamp | Process event time |
| DeviceName | Endpoint identification |
| AccountName | Account associated with execution |
| FileName | Process executable |
| ProcessCommandLine | PowerShell command-line arguments |
| InitiatingProcessFileName | Parent process name |
| InitiatingProcessCommandLine | Parent process command line |
| ProcessId | Process identification |

Both `powershell.exe` and `pwsh.exe` are considered.

Parent-process context is included to help investigate how PowerShell was launched.

## 6. MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|---|---|---|
| Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell execution |

Additional mappings should be applied only when supporting evidence demonstrates the relevant behavior.

Reference: https://attack.mitre.org/techniques/T1059/001/

## 7. False-Positive Analysis and Tuning

Potential legitimate activity includes:

- IT administration scripts
- Software deployment tools
- System maintenance automation
- Endpoint management agents
- Security administration tasks

The tuning strategy considers:

- Parent-process context
- Executing account
- Device baseline
- Command-line content
- Decoded command content
- Related process and network activity

Exclusions should be narrow, evidence-based, documented, and periodically reviewed.

## 8. Microsoft Sentinel Analytics Rule Design

Proposed initial configuration:

| Setting | Proposed value |
|---|---|
| Rule name | Suspicious PowerShell Execution |
| Severity | Medium |
| Query frequency | 5 minutes |
| Query lookback | 1 hour |
| Trigger | Greater than 0 results |
| Event grouping | Group all query results into one alert |
| Incident grouping | Group related alerts based on mapped entities |
| Suppression | Disabled initially |
| MITRE mapping | T1059.001 |

These are starting configuration choices, not universally optimal settings. They require validation and tuning in the target environment.

## 9. Investigation Workflow

When an alert is generated, the analyst should:

1. Review the PowerShell command line.
2. Decode encoded commands where applicable.
3. Investigate the initiating parent process.
4. Review the associated user account.
5. Examine related process execution.
6. Investigate file creation and modification activity.
7. Review network connections associated with the process.
8. Correlate findings with other endpoint and identity events.
9. Classify the activity based on available evidence.
10. Follow organizational incident response procedures.

## 10. Repository Structure

```text
Suspicious-PowerShell-Detection/
│
├── README.md
│
├── detections/
│   ├── suspicious-powershell-base.kql
│   ├── encoded-powershell.kql
│   ├── execution-policy-bypass.kql
│   ├── hidden-powershell.kql
│   └── suspicious-powershell-combined.kql
│
├── validation/
│   ├── telemetry-validation.kql
│   ├── test-cases.md
│   └── validation-results.md
│
├── tuning/
│   ├── false-positive-analysis.md
│   └── detection-tuning.md
│
├── mitre/
│   └── attack-mapping.md
│
├── sentinel-rule/
│   ├── analytics-rule-configuration.md
│   ├── entity-mapping.md
│   └── alert-grouping.md
│
├── investigation/
│   └── analyst-runbook.md
│
└── documentation/
    ├── architecture.md
    ├── deployment-guide.md
    └── interview-notes.md
```

## 11. Validation Status

Project validation should be documented honestly.

| Activity | Status |
|---|---|
| Detection logic development | Developed |
| Telemetry availability | Requires environment validation |
| Positive test cases | Designed |
| Negative test cases | Designed |
| False-positive analysis | Strategy documented |
| Production tuning | Pending validation |
| Sentinel rule deployment | Not yet confirmed |

Update this table as actual testing and deployment are completed.

## 12. Project Outcome

This project demonstrates practical detection engineering concepts, including:

- Endpoint telemetry analysis
- KQL detection development
- Suspicious command-line analysis
- Parent-process investigation
- Detection validation
- False-positive reduction
- MITRE ATT&CK mapping
- SIEM analytics rule design
- Alert investigation and documentation

---

**Disclaimer:** This is a defensive security research and portfolio project. Detection effectiveness depends on telemetry availability, query validation, environmental context, and continuous tuning.
