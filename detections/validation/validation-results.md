# Suspicious PowerShell Detection — Validation Results

## 1. Objective

Document the validation of suspicious PowerShell detection queries, including positive tests, negative tests, detection gaps, and tuning observations.

## 2. Validation Environment

| Item | Details |
|---|---|
| SIEM | Microsoft Sentinel |
| Query language | KQL |
| Data source | DeviceProcessEvents |
| Detection | Suspicious PowerShell Execution |
| Test environment | Pending confirmation |
| Validation date | Pending |

## 3. Test Results

| Test ID | Scenario | Expected result | Actual result | Status |
|---|---|---|---|---|
| P01 | Encoded command | Match | Not tested | Pending |
| P02 | Encoded abbreviation | Match | Not tested | Pending |
| P03 | Execution policy bypass | Match | Not tested | Pending |
| P04 | Bypass abbreviation | Match | Not tested | Pending |
| P05 | Hidden window | Match | Not tested | Pending |
| P06 | Hidden abbreviation | Match | Not tested | Pending |
| P07 | Combined indicators | Match all indicators | Not tested | Pending |
| N01 | Normal Get-Process | No match | Not tested | Pending |
| N02 | Normal Get-Service | No match | Not tested | Pending |
| N03 | Normal Get-Date | No match | Not tested | Pending |

## 4. Detection Gaps Identified

| Gap | Potential impact | Planned improvement |
|---|---|---|
| Equals-separated parameter syntax | Possible missed encoded-command events | Test and refine regex |
| Alternate parameter abbreviations | Possible missed events | Test supported forms |
| Null command lines | Command-line indicators cannot be evaluated | Document telemetry limitation |
| Legitimate automation | Potential false positives | Add contextual analysis |

## 5. False-Positive Observations

Legitimate PowerShell activity may include:

- IT administration.
- Software deployment.
- System maintenance.
- Security automation.
- Endpoint management.

These activities must be evaluated using account, device, parent-process, command-line, and business context.

## 6. Validation Summary

| Category | Status |
|---|---|
| Positive test design | Completed |
| Negative test design | Completed |
| Query execution | Pending |
| Actual result verification | Pending |
| False-positive validation | Pending |
| Production readiness | Not established |

## 7. Conclusion

The project contains a candidate detection for suspicious PowerShell execution using encoded commands, execution policy bypass, and hidden-window indicators.

The detection logic requires execution against representative telemetry, test-result verification, and environment-specific tuning before production deployment.

No unexecuted test is represented as passed.
