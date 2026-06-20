# Malicious Mailbox Rule: Forwarding, Hiding, or Deleting Mail

Detects creation or modification of inbox rules that forward, redirect, delete, or move incoming mail, the hallmark of business email compromise. After taking a mailbox, an attacker plants a rule to siphon mail to an external address or to hide replies that would expose the fraud.

## ATT&CK

- **Technique:** T1114.003. Email Collection: Email Forwarding Rule, T1564.008, Hide Artifacts: Email Hiding Rules
- **Tactic:** Collection, Defense Evasion

## Severity

**High.** A forwarding rule is silent, persistent exfiltration of every relevant message; a hiding rule conceals the attacker's own activity from the victim. Both are core BEC tradecraft.

## Data Sources

- Microsoft 365 management activity via the Splunk Add-on for Microsoft 365, `sourcetype="o365:management:activity"`
- Requires: Exchange mailbox auditing enabled

## Query

```spl
sourcetype="o365:management:activity"
    Operation IN ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| eval suspicious=case(
    match(Parameters, "(?i)ForwardTo|RedirectTo|ForwardAsAttachmentTo"), "external_forward",
    match(Parameters, "(?i)DeleteMessage"), "auto_delete",
    match(Parameters, "(?i)MoveToFolder.*(RSS|Archive|Deleted|Conversation History)"), "hide_to_folder",
    match(Parameters, "(?i)MarkAsRead"), "mark_read_hide")
| where isnotnull(suspicious)
| stats values(suspicious) AS behaviors, values(Parameters) AS rule_detail, min(_time) AS first_seen
    by UserId, ClientIP, Operation
| sort - first_seen
```

## What Triggers This

A rule that moves mail out of the owner's sight:

- Forwarding or redirecting to an external address (`ForwardTo`, `RedirectTo`)
- Auto-deleting incoming mail or moving it to RSS, Archive, or Deleted Items
- Marking messages read to suppress notification, hiding the attacker's correspondence

## False Positives

1. **Legitimate forwarding.** Users forwarding to a personal or delegate address. Confirm the destination is expected and internal where policy requires.
2. **Organisational rules.** Helpdesk or shared-mailbox automation. Allowlist known service accounts and rule patterns.
3. **Email clients.** Some clients create housekeeping rules. Scope to the suspicious behaviours rather than all rule creation.

## Tuning Notes

- **Escalate external forwarding.** A `ForwardTo` or `RedirectTo` to an external domain is the highest-severity case; resolve the destination domain and alert immediately.
- **Correlate with sign-in.** Pair with a preceding risky or AiTM sign-in for the same user to confirm BEC rather than user housekeeping.
- **Allowlist service accounts.** Exclude shared-mailbox and helpdesk automation by `UserId`.

## Validation

1. In a test mailbox, create an inbox rule that forwards to an external test address.
2. Confirm the rule surfaces tagged `external_forward` with the parameters captured.

## Learn More

- [Splunk Detection and Incident Response: Identity Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/). BEC mailbox-rule detection and sign-in correlation
- [SOC Operations: Investigation Playbook Framework](https://ridgelinecyber.com/training/courses/m365-security-operations/). BEC investigation and response
