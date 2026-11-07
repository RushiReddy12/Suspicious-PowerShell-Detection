# Suspicious PowerShell Detection — False-Positive Analysis

## 1. Objective

Identify legitimate PowerShell activity that may match suspicious execution indicators and define a safe, evidence-based tuning approach.

## 2. Potential False-Positive Sources

| Source | Potential legitimate activity | Investigation approach |
|---|---|---|
| SCCM agent | Software deployment and maintenance | Verify deployment, script and service account |
| IT administrator | Administrative automation | Verify user, device and command |
| Backup service | Scheduled backup scripts | Verify expected schedule and script |
| Security tools | Endpoint administration | Validate tool activity and process lineage |
| Scheduled tasks | Background PowerShell execution | Inspect task configuration and execution context |

## 3. Investigation Context

Before classifying a matching event, review:

- Executing account
- Device name
- Parent process
- Parent process command line
- PowerShell command line
- Script path and contents, where available
- Related process activity
- Network connections
- User and device baseline
- Business justification

## 4. Tuning Strategy

1. Identify repeated legitimate activity.
2. Confirm the account and device are expected.
3. Validate the script path and content.
4. Confirm the parent process and execution context.
5. Document the evidence.
6. Apply narrowly scoped exclusions only when justified.
7. Monitor excluded activity for changes or abuse.

## 5. Exclusion Principles

Avoid broad exclusions based only on:

- Parent process name
- Service account name
- Device name
- Management agent name
- Presence of a known executable

Legitimate tools and accounts can be abused.

## 6. Continuous Review

Review exclusions periodically and whenever:

- A script changes.
- An account's responsibilities change.
- A management tool is upgraded.
- New suspicious behavior is observed.
- The detection produces unexpected results.

## 7. Conclusion

False-positive reduction should improve detection quality without creating blind spots. Exclusions must be supported by investigation evidence and continuously reviewed.
