# Password Spray: Distributed Credential Testing

Detects password spray attacks by identifying distributed authentication failures across multiple accounts from overlapping IP ranges within a short time window. Standard brute force detection counts failures per account. Password spray spreads 1-2 attempts across hundreds of accounts. Each account sees minimal failures, but the pattern across accounts is unmistakable.

## ATT&CK

- **Technique:** T1110.003, Brute Force: Password Spraying
- **Tactic:** Credential Access

## Severity

**High.** Password spray is the most common initial access technique against Entra ID tenants (Microsoft Digital Defense Report 2025). A successful spray gives the attacker a valid credential for at least one account. If Smart Lockout or Conditional Access doesn't block it, the attacker is in.

## Data Sources

- Entra ID Sign-in Logs, `SigninLogs` table in Sentinel
- Both `SigninLogs` (interactive) and `AADNonInteractiveUserSignInLogs` (non-interactive/legacy auth)
- Requires: Entra ID P1 or P2 for complete sign-in telemetry

## Query: KQL (Sentinel)

```kql
let lookback = 1h;
let failure_threshold = 15;
let account_threshold = 10;
let success_within = 30m;
// Stage 1: Identify IPs with distributed failures
let sprayIPs = union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(lookback)
| where ResultType in ("50126", "50053", "50055", "50056", "530032")
    // 50126 = invalid password
    // 50053 = account locked
    // 50055 = expired password
    // 50056 = password doesn't exist
    // 530032 = blocked by security defaults
| summarize
    FailedAccounts = dcount(UserPrincipalName),
    TotalFailures = count(),
    AccountList = make_set(UserPrincipalName, 25),
    FailedApps = make_set(AppDisplayName, 5),
    FirstFailure = min(TimeGenerated),
    LastFailure = max(TimeGenerated)
    by IPAddress
| where TotalFailures >= failure_threshold
    and FailedAccounts >= account_threshold
| extend SprayDuration = datetime_diff('minute', LastFailure, FirstFailure)
| extend FailuresPerMinute = round(toreal(TotalFailures) / max_of(SprayDuration, 1), 1);
// Stage 2: Check if any sprayed account had a subsequent success
let sprayedAccounts = sprayIPs
| mv-expand AccountList to typeof(string)
| project IPAddress, TargetAccount = AccountList;
let successfulBreaches = union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(lookback + success_within)
| where ResultType == 0
| where UserPrincipalName in (sprayedAccounts | project TargetAccount)
| project
    SuccessTime = TimeGenerated,
    UserPrincipalName,
    SuccessIP = IPAddress,
    AppDisplayName,
    DeviceDetail,
    ConditionalAccessStatus;
// Final: Spray summary with breach indicators
sprayIPs
| join kind=leftouter (
    successfulBreaches
    | summarize
        BreachedAccounts = make_set(UserPrincipalName),
        BreachCount = dcount(UserPrincipalName)
        by SuccessIP
) on $left.IPAddress == $right.SuccessIP
| project
    FirstFailure,
    LastFailure,
    IPAddress,
    SprayDuration,
    FailedAccounts,
    TotalFailures,
    FailuresPerMinute,
    FailedApps,
    BreachedAccounts = coalesce(BreachedAccounts, dynamic([])),
    BreachCount = coalesce(BreachCount, 0),
    SampleAccounts = AccountList
| sort by BreachCount desc, TotalFailures desc
```

## Why This Detection Is Effective

Password spray is designed to evade per-account lockout thresholds. The attacker tries one password against 500 accounts, waits, tries the next password. Each account sees 1-3 failures. Well below Smart Lockout's threshold (typically 10). But across the tenant, 500 failures from one IP in 30 minutes is an obvious spray.

This detection works in two stages:
1. **Identify spray IPs**. IPs that failed authentication against 10+ distinct accounts within 1 hour
2. **Check for success**. Whether any sprayed account subsequently authenticated successfully, indicating the attacker found a valid credential

The success check is what separates this from a blocked spray (informational) and a successful breach (critical). A spray with 0 successes means your password policy held. A spray with 1+ success means the attacker has a credential and you need to respond immediately.

The query includes `AADNonInteractiveUserSignInLogs` because attackers increasingly target legacy authentication protocols (IMAP, SMTP, ActiveSync) that don't enforce MFA. These appear only in the non-interactive log.

## What Triggers This

1. Attacker obtains a list of valid email addresses (LinkedIn scraping, email harvesting, previous breaches)
2. Attacker runs a spray tool (MSOLSpray, Spray, Ruler, custom scripts) against the Entra ID login endpoint
3. Each account receives 1-2 password attempts with common passwords (Season+Year, Company+123, Welcome1!)
4. The detection aggregates failures across accounts and identifies the spray pattern
5. If any account authenticates successfully after being sprayed, the detection flags it as a breached account

## False Positives

1. **Misconfigured applications.** An app with an expired or wrong password attempting to authenticate for multiple users. Check the `FailedApps` field. A single application name across all failures is likely a misconfigured service, not a spray.
2. **Conditional Access policy testing.** Deploying a new CA policy may cause authentication failures for a group of users simultaneously. These show the same error code and application.
3. **Network-level NAT.** If your organization routes all outbound traffic through a single public IP, internal authentication failures aggregate on that IP. Exclude your known egress IPs.
4. **Pen testing.** Authorized penetration tests include credential testing. Coordinate with your pen test team and exclude their source IPs during the engagement window.

## Tuning Notes

- **Thresholds.** `failure_threshold = 15` and `account_threshold = 10` balance sensitivity and noise for a 500-user tenant. For larger tenants (5000+), increase to 50/25. For smaller tenants (100), decrease to 8/5.
- **Time window.** 1 hour catches most spray tools. Slow-and-low sprays that spread over 24+ hours require a separate detection with daily aggregation and higher thresholds.
- **Error code filtering.** `50126` (invalid password) is the primary spray signal. `50053` (locked) means Smart Lockout fired. `530032` (blocked by Security Defaults) means the spray was blocked. Include all for visibility but weight 50126 highest.
- **Sentinel deployment:** Scheduled rule, 15-minute frequency with 1-hour lookback (overlapping). Spray attacks are time-sensitive. The window between spray and exploitation is minutes. Entity mapping: `IPAddress` as IP. If `BreachCount > 0`, auto-elevate to Critical severity.

## Response

If `BreachCount > 0` (the spray found a valid credential):

1. **Reset the breached account's password immediately.** Don't wait for investigation.
2. **Revoke all sessions** for the breached account: `Revoke-MgUserSignInSession -UserId <UPN>`
3. **Check for post-compromise activity**. Inbox rules, OAuth consent grants, MFA method changes within the last hour
4. **Block the spray IP** in Conditional Access as a Named Location (blocked)
5. **Audit all accounts in the spray list** for weak passwords. The attacker's password list hit at least one account. Others may be vulnerable to the next spray

## References

- Microsoft Digital Defense Report 2025: Password spray as the dominant identity attack vector
- MITRE ATT&CK: [T1110.003](https://attack.mitre.org/techniques/T1110/003/)
- Microsoft: [Entra ID Smart Lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)

## Learn More

- [Entra ID Security: Authentication Threats](https://ridgelinecyber.com/training/courses/entra-id-security/). password spray detection, Smart Lockout configuration, and Entra ID Protection risk signals
- [Detection Engineering: Identity Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). statistical detection design for distributed attacks
- [Threat Hunting in Microsoft 365](https://ridgelinecyber.com/training/courses/threat-hunting-m365/). proactive hunting for credential attack patterns
