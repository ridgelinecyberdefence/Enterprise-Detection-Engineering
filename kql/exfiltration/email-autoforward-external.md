# Email Auto-Forward to External Domain

Detects the creation or modification of email forwarding rules that send mail to external domains. This is the most common persistence and exfiltration mechanism in BEC attacks — the attacker sets up auto-forwarding to silently copy all incoming email to an attacker-controlled mailbox.

## ATT&CK

- **Technique:** T1114.003 — Email Collection: Email Forwarding Rule
- **Tactic:** Exfiltration, Collection

## Severity

**Critical.** External email forwarding from a compromised account means the attacker receives a copy of every inbound email in real time — including password resets, MFA notifications, and sensitive business communications. This persists even after the password is changed.

## Data Sources

- Microsoft 365 Unified Audit Log — `OfficeActivity` table
- Exchange Online transport rules and mailbox rules

## Query

```kql
let TimePeriod = 24h;
// Inbox rules with external forwarding
let InboxRuleForwarding = OfficeActivity
| where TimeGenerated > ago(TimePeriod)
| where OfficeWorkload == "Exchange"
| where Operation in ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule")
| where Parameters has "ForwardTo" or Parameters has "ForwardAsAttachmentTo"
    or Parameters has "RedirectTo"
| extend
    RuleName = tostring(parse_json(tostring(Parameters))[0].Value),
    ForwardTo = extract(@"(?:ForwardTo|ForwardAsAttachmentTo|RedirectTo)['""]?:\s*['""]?([^'""}\]]+)", 1, tostring(Parameters))
| where ForwardTo !endswith "@contoso.com"  // adjust to your domain
| where isnotempty(ForwardTo)
| project
    TimeGenerated,
    UserId,
    Operation,
    RuleName,
    ForwardTo,
    ClientIP,
    SessionId,
    "InboxRule" as ForwardType;
// SMTP forwarding at mailbox level
let SMTPForwarding = OfficeActivity
| where TimeGenerated > ago(TimePeriod)
| where OfficeWorkload == "Exchange"
| where Operation == "Set-Mailbox"
| where Parameters has "ForwardingSmtpAddress" or Parameters has "ForwardingAddress"
| extend
    ForwardTo = extract(@"(?:ForwardingSmtpAddress|ForwardingAddress)['""]?:\s*['""]?smtp:?([^'""}\]]+)", 1, tostring(Parameters))
| where isnotempty(ForwardTo)
| where ForwardTo !endswith "@contoso.com"
| project
    TimeGenerated,
    UserId,
    Operation,
    RuleName = "SMTP Forwarding",
    ForwardTo,
    ClientIP,
    SessionId,
    "SMTPForward" as ForwardType;
// Transport rule forwarding (admin-level)
let TransportRuleForwarding = OfficeActivity
| where TimeGenerated > ago(TimePeriod)
| where OfficeWorkload == "Exchange"
| where Operation in ("New-TransportRule", "Set-TransportRule")
| where Parameters has "RedirectMessageTo" or Parameters has "BlindCopyTo"
    or Parameters has "CopyTo"
| extend
    ForwardTo = extract(@"(?:RedirectMessageTo|BlindCopyTo|CopyTo)['""]?:\s*['""]?([^'""}\]]+)", 1, tostring(Parameters))
| where isnotempty(ForwardTo)
| project
    TimeGenerated,
    UserId,
    Operation,
    RuleName = "Transport Rule",
    ForwardTo,
    ClientIP,
    SessionId,
    "TransportRule" as ForwardType;
union InboxRuleForwarding, SMTPForwarding, TransportRuleForwarding
| sort by TimeGenerated desc
```

## What Triggers This

Any of three forwarding mechanisms pointing to an external domain:
1. **Inbox rules** — user-level rules with ForwardTo, ForwardAsAttachmentTo, or RedirectTo
2. **SMTP forwarding** — mailbox-level forwarding set via `Set-Mailbox`
3. **Transport rules** — organization-level rules with RedirectMessageTo, BlindCopyTo, or CopyTo

## False Positives

1. **Legitimate forwarding.** Users who forward to personal accounts or external partners. Validate with the user directly — this is a common policy violation even when not malicious.
2. **IT-configured forwarding.** Help desk or admin setting forwarding during migrations or leave coverage. Verify the admin session.
3. **Shared mailbox routing.** Shared mailboxes forwarding to external systems. Catalog and exclude.

## Tuning Notes

- Replace `@contoso.com` with all your organization's accepted domains
- Transport rule forwarding (`TransportRule` type) is the highest severity — it affects all matching mail, not just one mailbox
- Consider blocking external auto-forwarding at the transport rule level. Microsoft provides an anti-spam outbound policy setting for this.
- Deploy as NRT rule for immediate alerting

## Validation

1. Create a test inbox rule on a test account that forwards to an external test address
2. Verify the detection fires and captures the user, rule, and destination
3. Remove the test rule

## Learn More

- [Incident Triage and First Response — BEC Investigation](https://ridgelinecyber.com/training/courses/incident-triage-first-response/) — forwarding rule discovery and remediation
- [SOC Operations — Email Security Monitoring](https://ridgelinecyber.com/training/courses/m365-security-operations/) — email forwarding alerting and response
