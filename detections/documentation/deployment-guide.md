# Deployment Guide — Suspicious PowerShell Detection

## 1. Purpose

This guide describes the prerequisites and deployment workflow for implementing the Suspicious PowerShell Detection in Microsoft Sentinel.

The project is designed to be reproducible in an environment with the required Defender XDR telemetry and Sentinel integration.

**Deployment status:** Documentation prepared. Actual deployment and validation are pending.

## 2. Architecture Overview

The proposed detection workflow is:

1. Endpoint generates PowerShell process activity.
2. Microsoft Defender for Endpoint collects process telemetry.
3. Defender XDR exposes the DeviceProcessEvents table.
4. Microsoft Sentinel accesses the available telemetry.
5. KQL detection queries identify suspicious PowerShell execution.
6. Scheduled analytics rules generate alerts.
7. Sentinel creates incidents according to the configured settings.
8. SOC analysts investigate using the analyst runbook.

## 3. Prerequisites

Before deployment, ensure the environment has:

- A Microsoft Sentinel workspace.
- Microsoft Defender for Endpoint telemetry.
- Defender XDR integration with Sentinel, where applicable.
- Access to the DeviceProcessEvents table.
- Permissions to create or modify Sentinel analytics rules.
- Permissions to investigate alerts and incidents.

### Important telemetry requirement

DeviceProcessEvents is a Defender XDR Advanced Hunting table.

Its availability in Sentinel depends on the integration and data configuration.

Do not assume that connecting Sentinel to an arbitrary workspace automatically makes this table available.

## 4. Repository Structure

```text
Suspicious-PowerShell-Detection/
│
├── README.md
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

## 5. Step 1 — Validate Telemetry

Confirm that DeviceProcessEvents is available and contains the required fields.

Example:

```kql
DeviceProcessEvents
| where Timestamp >= ago(24h)
| take 10
```

Inspect the schema:

```kql
DeviceProcessEvents
| getschema
```

Confirm that the following fields are available:

- Timestamp
- DeviceName
- AccountName
- FileName
- ProcessCommandLine
- InitiatingProcessFileName
- InitiatingProcessCommandLine
- ProcessId

If the table or fields are unavailable, investigate the telemetry integration before proceeding.

## 6. Step 2 — Deploy Detection Queries

Run the individual queries from the detections directory.

Recommended order:

1. suspicious-powershell-base.kql
2. encoded-powershell.kql
3. execution-policy-bypass.kql
4. hidden-powershell.kql
5. suspicious-powershell-combined.kql

Review the results and identify legitimate administrative activity.

## 7. Step 3 — Validate Detection Behavior

Use the test cases documented in:

`validation/test-cases.md`

Validate:

- Encoded PowerShell detection.
- Execution policy bypass detection.
- Hidden PowerShell detection.
- Multiple indicator detection.
- Normal PowerShell execution.
- Legitimate administrative activity.

Record actual results in:

`validation/validation-results.md`

Do not mark tests as passed unless they have actually been executed.

## 8. Step 4 — Tune Detection

Review:

- False-positive analysis.
- Candidate detection thresholds.
- Expected alert volume.
- Detection gaps.
- Legitimate automation behavior.

Document the final tuning decisions before enabling production alerting.

## 9. Step 5 — Configure Sentinel Analytics Rule

Follow:

`sentinel-rule/analytics-rule-configuration.md`

Configure:

- Scheduled query.
- Query frequency and lookback.
- Alert name and description.
- Severity.
- MITRE ATT&CK mapping.
- Entity mapping.
- Alert grouping.
- Incident grouping.

Validate the final configuration in the workspace.

## 10. Step 6 — Configure Investigation Workflow

Follow:

`investigation/analyst-runbook.md`

Ensure analysts understand:

- Initial alert review.
- Device and account investigation.
- PowerShell command-line analysis.
- Parent-process investigation.
- Correlation with surrounding activity.
- Investigation classification and escalation.

## 11. Deployment Validation Checklist

- [ ] Required telemetry is available.
- [ ] Required schema fields are confirmed.
- [ ] Baseline query executes successfully.
- [ ] Individual detection queries execute successfully.
- [ ] Combined detection query executes successfully.
- [ ] Positive test cases are validated.
- [ ] Negative test cases are validated.
- [ ] False positives are reviewed.
- [ ] Threshold is justified by evidence.
- [ ] Analytics rule is configured.
- [ ] Entity mapping is validated.
- [ ] Alert grouping is validated.
- [ ] Incident creation is validated.
- [ ] Analyst runbook is available.
- [ ] Deployment results are documented.

## 12. Rollback Considerations

If the detection generates unexpected alert volume or affects SOC operations:

1. Review the recent query and configuration changes.
2. Disable the analytics rule if necessary, following operational approval.
3. Preserve relevant alert and investigation evidence.
4. Identify the cause of the unexpected behavior.
5. Correct and revalidate the detection.
6. Re-enable only after the required checks.

## 13. Current Deployment Status

**Status: Deployment guide drafted — actual deployment not yet confirmed.**

This repository currently documents the proposed detection architecture, KQL logic, validation approach, tuning strategy, Sentinel configuration, and investigation workflow.

Production readiness requires successful validation and deployment in an environment with the required telemetry.
