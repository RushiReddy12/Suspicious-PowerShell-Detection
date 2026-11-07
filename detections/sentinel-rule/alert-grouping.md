# Microsoft Sentinel Alert Grouping Strategy

## 1. Purpose

This document describes the proposed alert and incident grouping strategy for the Suspicious PowerShell Detection.

The objective is to reduce duplicate alerts, improve investigation efficiency, and preserve visibility into distinct suspicious PowerShell executions.

## 2. Why Alert Grouping Matters

Consider this scenario:

A device executes PowerShell with an encoded command every five minutes.

Without appropriate grouping, repeated matching events may generate multiple alerts for the same ongoing activity.

This can create alert fatigue and make investigation more difficult.

However, grouping too aggressively can combine unrelated activities and hide important details.

## 3. Alert Grouping Strategy

Evaluate grouping based on the following context:

| Field | Grouping purpose |
|---|---|
| DeviceName | Identify activity from the same device |
| AccountName | Identify activity associated with the same account |
| FileName | Identify the PowerShell executable |
| ProcessId | Help distinguish process executions |
| Time window | Establish whether events are related |

Grouping should use stable and meaningful identifiers.

ProcessId alone is insufficient because process IDs can be reused and are not globally unique.

## 4. Proposed Strategy

For initial deployment:

- Preserve individual matching events in query results.
- Evaluate grouping events by relevant host and account context.
- Review whether repeated events represent the same activity.
- Avoid grouping unrelated devices or accounts into a single investigation.
- Verify that analysts can access the underlying event details.

The final grouping configuration should be selected using representative telemetry.

## 5. Overlapping Query Windows

The proposed analytics rule runs every five minutes and looks back one hour.

This means the same process event may appear in multiple query executions.

Potential impact:

- Repeated alert generation.
- Duplicate investigation workload.
- Increased incident volume.

Possible mitigations:

- Configure suitable alert grouping.
- Evaluate incident grouping.
- Review suppression behavior carefully.
- Consider query-level deduplication only when it preserves required investigation context.

Do not assume alert grouping alone eliminates every duplicate alert.

## 6. Incident Grouping Considerations

Incident grouping should consider:

- Shared host entities.
- Shared account entities.
- Related detection activity.
- Appropriate grouping time windows.
- Whether the events belong to the same investigation.

Avoid grouping alerts solely because they share a broad characteristic such as the same executable name.

## 7. Validation Scenarios

| Scenario | Expected behavior |
|---|---|
| Repeated matching events from the same host and account | Evaluate whether they belong in one investigation |
| Matching events from different hosts | Preserve separate device context |
| Matching events from different accounts | Preserve separate account context |
| Separate suspicious process executions | Ensure individual event evidence remains accessible |
| Same event returned in overlapping query windows | Evaluate duplicate alert behavior |

## 8. Deployment Checklist

- [ ] Review actual event volume.
- [ ] Select suitable alert grouping conditions.
- [ ] Configure incident grouping.
- [ ] Review grouping time window.
- [ ] Test repeated events.
- [ ] Test events from different hosts.
- [ ] Test events from different accounts.
- [ ] Confirm underlying event details remain available.
- [ ] Review duplicate alert behavior.

## 9. Current Status

**Status: Grouping strategy documented — configuration and validation pending.**

Final grouping settings must be tested in the Microsoft Sentinel workspace before production deployment.
