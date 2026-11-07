# Microsoft Sentinel Entity Mapping

## 1. Purpose

This document describes the proposed entity mapping for the Suspicious PowerShell Detection analytics rule.

Entity mapping helps Microsoft Sentinel associate detection alerts with identifiable entities such as hosts and accounts.

## 2. Available Detection Fields

The combined detection query currently returns:

| Field | Purpose |
|---|---|
| Timestamp | Process event time |
| DeviceName | Device where PowerShell executed |
| AccountName | Account associated with execution |
| FileName | PowerShell executable |
| ProcessCommandLine | Executed command line |
| InitiatingProcessFileName | Parent process |
| InitiatingProcessCommandLine | Parent process command line |
| ProcessId | Process identifier |
| SuspiciousIndicatorCount | Number of matched indicators |

## 3. Proposed Entity Mapping

### Host Entity

| Setting | Value |
|---|---|
| Entity type | Host |
| Identifier | HostName |
| Query column | DeviceName |

**Purpose:** Identifies the device where the suspicious PowerShell process executed.

### Account Entity

| Setting | Value |
|---|---|
| Entity type | Account |
| Identifier | Name |
| Query column | AccountName |

**Purpose:** Identifies the account associated with the process execution.

Validate whether the query returns the account format expected by the Sentinel mapping interface. If domain information is available, consider using the appropriate account identifiers.

### Process Context

ProcessId is useful investigation context, but it should not automatically be treated as a globally unique process identifier.

A process identifier is meaningful in combination with device and event-time context.

## 4. Entity Mapping Considerations

- Map only fields that are available and reliable.
- Confirm that field formats match Sentinel's supported entity identifiers.
- Avoid mapping missing or empty values.
- Include device and account context wherever available.
- Validate the resulting entities in generated alerts and incidents.

## 5. Investigation Benefits

Correct entity mapping helps analysts:

1. Identify the affected endpoint.
2. Identify the associated user account.
3. Pivot to related alerts and incidents.
4. Investigate other activity from the same device or account.
5. Build a clearer incident timeline.

## 6. Validation Checklist

- [ ] DeviceName is populated in detection results.
- [ ] AccountName is populated where available.
- [ ] Host entity mapping is configured.
- [ ] Account entity mapping is configured.
- [ ] Entity values are correctly displayed in generated alerts.
- [ ] Entity information is available in the resulting incident.
- [ ] Missing or malformed values have been reviewed.

## 7. Current Status

**Status: Proposed entity mapping documented — not yet configured or validated in Microsoft Sentinel.**
