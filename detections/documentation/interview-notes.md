# Interview Notes — Suspicious PowerShell Detection

## 1. Project Overview

**Project:** Suspicious PowerShell Detection Using Microsoft Sentinel and KQL

**Objective:** Identify potentially suspicious PowerShell execution by analyzing endpoint process telemetry and detecting suspicious command-line parameters.

The detection focuses on:

- Encoded PowerShell execution.
- Execution policy bypass.
- Hidden PowerShell windows.
- Multiple suspicious indicators in a single process event.

The project demonstrates detection development, KQL usage, validation planning, false-positive analysis, tuning, MITRE ATT&CK mapping, and SOC investigation workflows.

## 2. Why Did You Build This Detection?

PowerShell is commonly used by administrators and IT teams for legitimate automation.

However, attackers can also abuse PowerShell to execute commands, run scripts, and perform malicious activities.

I built this detection to identify suspicious PowerShell execution patterns while preserving enough endpoint context for analysts to investigate the activity.

## 3. What Is the Data Source?

The detection uses:

`DeviceProcessEvents`

This is a Microsoft Defender XDR Advanced Hunting table containing process-related endpoint telemetry.

Important fields include:

- Timestamp
- DeviceName
- AccountName
- FileName
- ProcessCommandLine
- InitiatingProcessFileName
- InitiatingProcessCommandLine
- ProcessId

The table's availability in Microsoft Sentinel depends on the Defender XDR integration and data configuration.

## 4. What Behaviors Does the Detection Identify?

### Encoded PowerShell

Example:

```powershell
powershell.exe -EncodedCommand BASE64_VALUE
```

Attackers may encode commands to make their contents less immediately readable.

However, encoded PowerShell is not automatically malicious.

### Execution Policy Bypass

Example:

```powershell
powershell.exe -ExecutionPolicy Bypass -File script.ps1
```

This attempts to bypass the PowerShell execution policy for the process.

Execution policy is not a security boundary, and legitimate automation may use this parameter.

### Hidden PowerShell

Example:

```powershell
powershell.exe -WindowStyle Hidden -Command Get-Process
```

This starts PowerShell with a hidden window.

Hidden execution can be suspicious, but legitimate administrative tools may also use it.

## 5. Why Did You Create Individual and Combined Queries?

Individual queries make it easier to understand, test, and troubleshoot each detection behavior.

The combined query evaluates multiple indicators in one process event.

This provides a consolidated view and helps analysts prioritize investigation.

The indicator count is a triage aid, not a proven maliciousness score.

## 6. How Did You Approach False Positives?

I considered legitimate PowerShell activity from:

- System administrators.
- SCCM and endpoint management tools.
- Scheduled tasks.
- Backup software.
- IT automation scripts.
- Security products.

Rather than excluding entire applications or service accounts, I documented a context-based tuning approach.

The analyst should review:

- Device.
- User account.
- Parent process.
- Command line.
- Script path and purpose.
- Related activity.
- Approved business use.

## 7. How Would You Validate This Detection?

I designed positive, negative, and contextual test cases.

### Positive tests

- Encoded command.
- Execution policy bypass.
- Hidden window.
- Multiple indicators in one command line.

### Negative tests

- Normal PowerShell commands.
- Legitimate script execution.
- Standard PowerShell startup.

### Contextual tests

- SCCM launching PowerShell.
- Office application launching suspicious PowerShell.
- Administrative automation using encoded commands.

I would execute these tests in an authorized lab or representative environment, record the actual results, and tune the detection based on evidence.

**Important:** The repository documents the planned tests. Do not describe them as successfully executed unless actual validation results are available.

## 8. How Would You Deploy This in Microsoft Sentinel?

My proposed deployment workflow is:

1. Confirm the required endpoint telemetry is available.
2. Validate the KQL queries.
3. Execute positive and negative test cases.
4. Review false positives.
5. Tune the detection threshold.
6. Create a scheduled analytics rule.
7. Configure entity mapping.
8. Configure alert and incident grouping.
9. Validate alert generation.
10. Document the investigation workflow.

## 9. How Would You Improve This Detection?

Potential improvements include:

- Detecting suspicious PowerShell script-block activity.
- Analyzing decoded Base64 commands.
- Correlating PowerShell execution with network connections.
- Analyzing parent-child process relationships.
- Identifying suspicious download-and-execute behavior.
- Incorporating user and device baselines.
- Correlating endpoint alerts with authentication activity.

## 10. What Are the Current Limitations?

The current detection:

- Relies on process command-line telemetry.
- Does not prove malicious intent.
- Does not inspect the full contents of executed scripts.
- Does not independently detect all PowerShell abuse techniques.
- Does not implement complete process-tree correlation.
- Requires validation against parameter syntax variations.
- Depends on the availability of Defender XDR telemetry.

## 11. Important Interview Questions

### Q1. Does encoded PowerShell always indicate malicious activity?

No. Encoding can be used by legitimate administrative scripts. It is a suspicious indicator that requires contextual investigation.

### Q2. Why is parent-process information important?

It provides execution context. For example, PowerShell launched by an approved management agent may be expected, while PowerShell launched by an unusual Office process may deserve closer investigation.

### Q3. Why not alert on every PowerShell execution?

PowerShell is widely used for legitimate administration. Alerting on every execution would generate excessive noise and reduce the effectiveness of the SOC.

### Q4. What is the difference between brute force and password spraying?

Brute force typically attempts many passwords against one or a small number of accounts. Password spraying attempts a small number of common passwords across many accounts.

### Q5. Why use entity mapping?

Entity mapping connects alert information to entities such as users and devices, making incidents easier to investigate and correlate.

### Q6. What is the purpose of alert grouping?

It helps consolidate related alerts and reduce investigation noise. Poor grouping can also hide distinct suspicious events, so grouping must be validated.

### Q7. Is a higher indicator count always more dangerous?

No. Multiple indicators can increase investigative priority, but the count is not a calibrated risk score. Context and supporting evidence determine the assessment.

### Q8. What would you do if the detection generated too many false positives?

I would investigate recurring patterns, identify legitimate activity, document evidence, and apply narrow, justified exclusions or adjust thresholds. I would then validate that suspicious behavior remains detectable.

## 12. How to Present This Project in an Interview

A concise explanation:

"I developed a Suspicious PowerShell Detection project using Microsoft Sentinel and KQL. I focused on encoded PowerShell execution, execution policy bypass, and hidden PowerShell windows.

I created individual detection queries and a combined query that evaluates multiple suspicious indicators. I also documented positive and negative test cases, false-positive analysis, threshold tuning considerations, MITRE ATT&CK mapping, Sentinel analytics rule configuration, entity mapping, alert grouping, and an analyst investigation runbook.

My objective was to approach the problem as a detection engineer, covering not just query development but also validation, operationalization, and investigation."

## 13. Project Status

**Status: Portfolio documentation drafted.**

The repository contains the proposed detection logic and supporting engineering documentation.

Actual telemetry validation, tuning, analytics rule deployment, and end-to-end operational testing must be completed before claiming production readiness.
