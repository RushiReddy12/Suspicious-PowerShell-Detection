# Detection Tuning Strategy

## 1. Purpose

This document describes the tuning strategy for the Suspicious PowerShell Detection.

The objective is to reduce false positives while maintaining visibility into potentially malicious PowerShell activity.

Tuning decisions should be based on observed telemetry, validation results, and investigation evidence rather than arbitrary thresholds.

## 2. Detection Indicators

The combined detection query currently evaluates three indicators:

| Indicator | Description |
|---|---|
| HasEncodedCommand | Detects encoded PowerShell command parameters |
| HasExecutionPolicyBypass | Detects execution policy bypass parameters |
| HasHiddenWindow | Detects hidden PowerShell window parameters |

The query calculates:

`SuspiciousIndicatorCount`

This represents the number of matching indicators in a process event.

**Important:** This count is a triage aid, not a calibrated risk score. A higher count does not automatically prove malicious activity.

## 3. Threshold Strategy

The following thresholds can be evaluated during validation:

| Threshold | Detection behavior | Consideration |
|---|---|---|
| >= 1 | Detects any matching indicator | Higher visibility, potentially more false positives |
| >= 2 | Requires at least two indicators | Reduces alert volume but may miss single-indicator activity |
| >= 3 | Requires all three indicators | More restrictive and may miss suspicious activity |

No threshold should be considered production-ready until it has been tested against representative telemetry.

## 4. Alerting Strategy

Different detection purposes may require different thresholds.

### Hunting query

- Surface PowerShell events containing any suspicious indicator.
- Use the results for investigation and baseline analysis.
- Avoid treating every matching event as malicious.

### Scheduled analytics rule

- Use a threshold justified by validation and observed event volume.
- Consider higher-confidence combinations and relevant process context.
- Select severity based on investigation evidence and organizational risk.
- Monitor alert volume after deployment.

A threshold of `>= 1` may be useful for initial hunting, but it should not automatically become the production alert threshold.

## 5. Contextual Risk Assessment

Review the following context before deciding whether an event is suspicious:

- Initiating process name and command line
- User account and device
- PowerShell command line
- Number and combination of suspicious indicators
- Script path and script content, where available
- Related process activity
- Network activity, where available
- Whether the activity is expected for the device or account

For example, PowerShell launched by an Office application with an encoded command and hidden window deserves closer investigation than an approved administrative script running in a known maintenance workflow.

Context increases investigative confidence but does not independently prove malicious activity.

## 6. Tuning Methodology

1. Collect representative PowerShell telemetry.
2. Run the detection query and record matching events.
3. Identify legitimate administrative and automation activity.
4. Review suspicious events and relevant process context.
5. Compare alert volumes across candidate thresholds.
6. Evaluate whether stricter thresholds introduce detection gaps.
7. Document every tuning decision and its supporting evidence.
8. Revalidate after making query changes.

## 7. Tuning Decision Record

Record tuning decisions using this format:

| Field | Details |
|---|---|
| Detection name | Suspicious PowerShell Detection |
| Tested threshold | Pending validation |
| Expected alert volume | Pending validation |
| Observed alert volume | Pending validation |
| False-positive observations | Pending validation |
| Detection gaps | Pending validation |
| Final threshold | Not decided |
| Supporting evidence | Pending validation |

## 8. Important Considerations

- Do not increase thresholds simply to reduce alert volume.
- Do not assume three indicators always mean malicious activity.
- Do not suppress events solely because they originate from a legitimate parent process.
- Preserve visibility into suspicious single-indicator events during hunting.
- Revisit thresholds when telemetry, scripts, administrative tools, or organizational behavior changes.

## 9. Validation Status

**Status: Documentation drafted — tuning not yet validated.**

Threshold selection and production deployment remain pending representative telemetry testing.
