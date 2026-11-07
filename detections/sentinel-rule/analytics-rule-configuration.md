# Microsoft Sentinel Analytics Rule Configuration

## 1. Purpose

This document describes the proposed configuration for deploying the Suspicious PowerShell Detection as a scheduled analytics rule in Microsoft Sentinel.

The configuration is a starting point. Final settings must be validated against actual telemetry, detection performance, and alert volume.

## 2. Analytics Rule Overview

| Setting | Proposed value |
|---|---|
| Rule name | Suspicious PowerShell Execution |
| Rule type | Scheduled query rule |
| Data source | DeviceProcessEvents |
| Query file | suspicious-powershell-combined.kql |
| Query frequency | 5 minutes |
| Query lookback | 1 hour |
| Initial severity | Medium |
| MITRE technique | T1059.001 |
| Rule status | Proposed — not deployed |

## 3. Detection Query

The analytics rule should use the combined detection query maintained in:

`detections/suspicious-powershell-combined.kql`

Before deployment:

- Confirm that DeviceProcessEvents is available in the connected workspace.
- Confirm that the required columns exist.
- Execute the query against representative telemetry.
- Review false positives and detection gaps.
- Select a threshold based on validation evidence.

Do not deploy an unvalidated query as a production detection.

## 4. Query Scheduling

**Proposed configuration:**

- Run query every: 5 minutes
- Look up data from the last: 1 hour

The lookback window is longer than the query frequency to reduce the chance of missing events because of ingestion delays or scheduling differences.

However, overlapping query windows can produce duplicate results. Alert grouping and event deduplication should be considered during deployment.

## 5. Alert Threshold

The initial hunting query detects events where:

`SuspiciousIndicatorCount >= 1`

This is not automatically the recommended production alert threshold.

Evaluate candidate thresholds:

- `>= 1`: Greater visibility, potentially higher alert volume.
- `>= 2`: Requires multiple suspicious indicators.
- `>= 3`: Requires all three indicators and may miss relevant single-indicator activity.

Choose the final threshold using representative telemetry and documented tuning results.

## 6. Alert Details

Proposed alert configuration:

| Setting | Proposed value |
|---|---|
| Alert name | Suspicious PowerShell Execution Detected |
| Description | PowerShell process execution matched one or more suspicious command-line indicators. |
| Severity | Medium, subject to validation |
| Tactics | Execution |
| Technique | T1059.001 |

Severity should be adjusted according to the evidence, environment, and expected operational impact.

## 7. Entity Mapping

Map available query columns to relevant Sentinel entities.

| Entity type | Suggested identifier |
|---|---|
| Host | DeviceName |
| Account | AccountName |
| Process | ProcessId, where supported by the selected entity mapping |

Validate entity mapping against the actual query output and the entity identifiers supported by the Sentinel interface.

## 8. Event and Alert Grouping

Consider the following:

- Group related events when they belong to the same investigation.
- Avoid creating excessive alerts from repeated matching events.
- Review overlapping query windows.
- Choose grouping conditions based on available device, account, and process context.
- Verify that grouping does not hide distinct suspicious activity.

Initial proposal: evaluate grouping all matching events into one alert per query execution versus grouping related events over a defined period.

The final choice must be validated using actual event volume.

## 9. Incident Creation and Grouping

Recommended considerations:

- Enable incident creation for validated alerts.
- Group related alerts when they share reliable entities and investigation context.
- Avoid broad grouping that combines unrelated devices or users.
- Test the resulting incident behavior before production rollout.

## 10. Deployment Checklist

- [ ] Confirm DeviceProcessEvents availability.
- [ ] Validate required columns.
- [ ] Run the detection query successfully.
- [ ] Complete positive and negative test cases.
- [ ] Review false-positive observations.
- [ ] Document the final detection threshold.
- [ ] Configure alert details and severity.
- [ ] Configure and test entity mapping.
- [ ] Configure event grouping.
- [ ] Configure incident grouping.
- [ ] Validate alert generation.
- [ ] Document deployment results.

## 11. Current Status

**Status: Proposed configuration documented — deployment not completed.**

Actual workspace configuration, query validation, alert generation, entity mapping, and incident grouping remain pending.
