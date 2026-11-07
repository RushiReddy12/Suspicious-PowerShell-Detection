# Suspicious PowerShell Detection — Test Cases

## 1. Objective

Validate whether the suspicious PowerShell detection identifies the intended command-line indicators and avoids matching ordinary PowerShell activity.

## 2. Positive Test Cases

| ID | Test scenario | Example command-line arguments | Expected result |
|---|---|---|---|
| P01 | Encoded command | `-EncodedCommand BASE64_VALUE` | Match encoded indicator |
| P02 | Encoded abbreviation | `-enc BASE64_VALUE` | Match encoded indicator |
| P03 | Execution policy bypass | `-ExecutionPolicy Bypass -File script.ps1` | Match bypass indicator |
| P04 | Bypass abbreviation | `-ep Bypass -File script.ps1` | Match bypass indicator |
| P05 | Hidden window | `-WindowStyle Hidden -Command Get-Process` | Match hidden indicator |
| P06 | Hidden abbreviation | `-w Hidden -Command Get-Service` | Match hidden indicator |
| P07 | Combined indicators | Encoded + Bypass + Hidden | Match all three indicators |

## 3. Negative Test Cases

| ID | Test scenario | Example command-line arguments | Expected result |
|---|---|---|---|
| N01 | Normal process query | `-Command Get-Process` | No match |
| N02 | Normal service query | `-Command Get-Service` | No match |
| N03 | Normal date query | `-Command Get-Date` | No match |
| N04 | Normal script execution | `-File maintenance.ps1` | No match |
| N05 | Normal PowerShell startup | No suspicious parameters | No match |

## 4. Contextual Test Cases

| ID | Scenario | Expected analyst action |
|---|---|---|
| C01 | SCCM launches PowerShell with Bypass | Verify deployment and script |
| C02 | Word launches hidden encoded PowerShell | Prioritize investigation |
| C03 | Administrator runs encoded automation | Validate account and business context |

## 5. Validation Result Tracking

For every test, record:

- Test ID
- Test input
- Expected result
- Actual result
- Pass/Fail
- Notes and observations
These test cases are designed scenarios. They are not evidence that the queries have been executed or passed testing.

Update the validation status only after running the tests in an appropriate test environment.
