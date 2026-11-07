# MITRE ATT&CK Mapping

## 1. Purpose

This document maps the Suspicious PowerShell Detection use cases to relevant MITRE ATT&CK techniques.

The mapping helps analysts understand the attacker behavior associated with suspicious PowerShell execution.

Mappings are based on observed behavior and detection logic. A matching command-line indicator alone does not confirm that an attack occurred.

## 2. Primary Technique

### T1059.001 — Command and Scripting Interpreter: PowerShell

**Tactic:** Execution

**Description:**

Adversaries may abuse PowerShell to execute commands, scripts, and other malicious activities on a compromised system.

**Detection relevance:**

This project monitors PowerShell process execution and identifies potentially suspicious command-line patterns.

**Relevant detection files:**

- `suspicious-powershell-base.kql`
- `encoded-powershell.kql`
- `execution-policy-bypass.kql`
- `hidden-powershell.kql`
- `suspicious-powershell-combined.kql`

**Detection indicators:**

- Encoded PowerShell commands
- Execution policy bypass parameters
- Hidden PowerShell windows
- Suspicious combinations of command-line indicators

## 3. Conditional Technique Mapping

### T1027 — Obfuscated Files or Information

**Tactic:** Defense Evasion

**Description:**

Adversaries may obfuscate files or information to make malicious activity harder to detect or analyze.

**Detection relevance:**

Encoded PowerShell commands may be associated with obfuscation, but Base64 encoding alone does not prove malicious intent or satisfy this technique in every case.

**Relevant detection file:**

- `encoded-powershell.kql`

**Mapping condition:**

Use this mapping when investigation or additional telemetry supports an obfuscation behavior. Do not automatically map every encoded command to T1027.

## 4. Detection-to-ATT&CK Mapping Table

| Detection use case | Technique | Technique ID | Mapping confidence |
|---|---|---|---|
| PowerShell process execution | PowerShell | T1059.001 | Direct behavioral coverage |
| Encoded PowerShell | PowerShell | T1059.001 | Direct behavioral coverage |
| Execution policy bypass | PowerShell | T1059.001 | Direct behavioral coverage |
| Hidden PowerShell window | PowerShell | T1059.001 | Direct behavioral coverage |
| Confirmed obfuscation behavior | Obfuscated Files or Information | T1027 | Conditional |

## 5. Important Detection Limitations

- PowerShell execution is not inherently malicious.
- Encoded commands may be used by legitimate administrative tools.
- Execution policy bypass does not automatically indicate malicious activity.
- Hidden PowerShell windows may be part of legitimate automation.
- Command-line telemetry alone may not reveal the complete behavior of a script.

Analysts should correlate process information with account, device, parent process, script, and other available security telemetry.

## 6. ATT&CK Mapping Validation

Before finalizing a mapping:

1. Identify the behavior actually observed.
2. Review the relevant MITRE ATT&CK technique description.
3. Confirm that the detection provides meaningful coverage of that behavior.
4. Avoid mapping techniques based only on superficial command-line similarities.
5. Document any conditional mappings and their evidence.

## 7. Validation Status

**Status: Initial ATT&CK mapping documented — operational coverage not yet validated.**

The project currently provides process and command-line based detection coverage for PowerShell execution. Additional telemetry and investigation evidence are required to establish broader adversary behavior coverage.
