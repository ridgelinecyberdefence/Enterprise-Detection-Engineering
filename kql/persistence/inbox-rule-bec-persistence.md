# Inbox Rule Manipulation: BEC Persistence

Detects creation or modification of inbox rules that forward, redirect, or delete email. Attackers create these rules after compromising a mailbox to maintain access to email traffic, intercept MFA codes, and hide evidence of the compromise from the user.

## ATT&CK

- **Technique:** T1114.003. Email Collection: Email Forwarding Rule, T1564.008, Hide Artifacts: Email Hiding Rules
- **Tactic:** Collection, Persistence, Defense Evasion

## Severity

**High.** Inbox rules with forwarding or deletion actions created outside of normal business workflow are a primary indicator of Business Email Compromise. The rule gives the attacker persistent, silent access to the victim's email even after the password is reset.

## Data Sources

- Microsoft 365 Unified Audit Log, `OfficeActivity` table in Sentinel
- Requires: Exchange Online audit logging enabled (default in M365 E3/E5)

## Query: KQL (Sentinel)

```kql
OfficeActivity
| where TimeGenerated > ago(24h)
| where Operation in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox")
| extend RuleParams = tostring(Parameters)
| where RuleParams has_any (
    "ForwardTo",
    "ForwardAsAttachmentTo",
    "RedirectTo",
    "DeleteMessage",
    "MoveToFolder"
)
| extend ForwardTarget = extract(@'"ForwardTo"[^"]*"([^"]+)"', 1, RuleParams)
| extend RedirectTarget = extract(@'"RedirectTo"[^"]*"([^"]+)"', 1, RuleParams)
| extend DeleteAction = RuleParams has "DeleteMessage"
| project
    TimeGenerated,
    UserId,
    Operation,
    ForwardTarget,
    RedirectTarget,
    DeleteAction,
    ClientIP,
    RuleParams
| sort by TimeGenerated desc
```

## What Triggers This

After compromising a mailbox (typically through AiTM phishing or credential stuffing), the attacker creates inbox rules to:

1. **Forward email to an external address**. Copies all incoming email to an attacker-controlled mailbox. The user sees their email normally. The attacker reads everything silently.
2. **Redirect email**. Moves email to the attacker before it reaches the inbox. The user never sees the redirected messages.
3. **Delete specific messages**. Rules targeting keywords like "security alert," "password reset," or "suspicious sign-in" to hide security notifications from the victim.
4. **Move to obscure folders**. Moves email to RSS Feeds, Conversation History, or other folders the user never checks.

These rules persist across password resets. The attacker can lose session access but the forwarding rule continues sending them every email until someone finds and removes it.

## False Positives

1. **User-created forwarding rules.** Users legitimately create rules to forward email to personal accounts, shared mailboxes, or team distribution lists. Context matters. A rule forwarding to an internal DL is different from a rule forwarding to an external Gmail address created at 2 AM from an unfamiliar IP.
2. **IT automation.** Help desk automation and ticketing systems may modify mailbox rules programmatically. These typically operate from known service accounts and IP ranges.
3. **Mail flow rules vs inbox rules.** Exchange transport rules (organization-level) appear in different audit events. This detection covers user-level inbox rules only.

## Tuning Notes

- **External-only filter.** Add `| where ForwardTarget !endswith "@yourdomain.com"` to focus on external forwarding, which is almost always malicious in a BEC context. Internal forwarding is higher volume and lower risk.
- **Time-of-day correlation.** Rules created outside business hours from unfamiliar IPs have significantly higher true-positive rates. Consider a separate high-severity variant that adds time and GeoIP conditions.
- **Client IP enrichment.** Join with `SigninLogs` to check whether the IP that created the rule is consistent with the user's normal sign-in pattern.
- **Sentinel deployment:** NRT rule. Inbox rule creation is low volume and high impact. Entity mapping: `UserId` as Account, `ClientIP` as IP.

## Validation

1. Sign in as a test user to Outlook Web App
2. Create a new inbox rule: forward messages containing "test-detection" to a second test mailbox
3. Verify the detection fires with the correct user, operation, and forwarding target
4. Delete the test rule after validation

## Learn More

- [SOC Operations: Investigation Playbook Framework](https://ridgelinecyber.com/training/courses/m365-security-operations/). complete AiTM and BEC investigation playbook
- [Detection Engineering: Cloud & SaaS Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). email-based detection rule design
