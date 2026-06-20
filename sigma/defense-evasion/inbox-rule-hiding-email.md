# Inbox Rule Deleting or Hiding Email

Detects inbox rules that delete messages or move them to obscure folders. Attackers create these rules to hide security notifications (password reset confirmations, suspicious sign-in alerts) from the compromised user, extending the window before discovery.

## ATT&CK

- **Technique:** T1564.008 — Hide Artifacts: Email Hiding Rules
- **Tactic:** Defense Evasion

## Severity

**High.** An inbox rule that deletes or hides security notifications is a strong indicator of account compromise. The attacker is actively managing the victim's mailbox to prevent discovery.

## Data Sources

- Microsoft 365 Unified Audit Log — `OfficeActivity` table
- Requires: Exchange Online audit logging enabled

## Query — Sigma

```yaml
title: Inbox Rule Deleting or Hiding Email
id: det-soc-009
status: production
description: |
  Detects inbox rules that delete emails or move them to
  obscure folders (RSS Feeds, Conversation History).
  Defense evasion — attacker hides evidence of BEC activity
  from the legitimate mailbox owner.
author: Ridgeline Cyber Detection Engineering
date: 2026/05/17
tags:
  - attack.defense_evasion
  - attack.t1564.008
logsource:
  product: m365
  service: exchange
detection:
  selection:
    Operation:
      - 'New-InboxRule'
      - 'Set-InboxRule'
  filter_delete:
    Parameters|contains:
      - 'DeleteMessage'
      - 'SoftDeleteMessage'
  filter_suspicious_move:
    Parameters|contains: 'MoveToFolder'
  condition: selection and (filter_delete or filter_suspicious_move)
falsepositives:
  - Newsletter management rules (move to folder)
  - Users auto-deleting notification emails from known senders
level: high
```

## What Triggers This

After compromising a mailbox, the attacker creates rules to:

- **Delete messages** matching keywords: "security alert," "password reset," "suspicious sign-in," "unusual activity," "MFA," "verification code"
- **Move messages to Deleted Items, RSS Feeds, or Conversation History** — folders the user never checks
- **Mark as read** — prevents unread count alerts on mobile devices

These rules run before the user sees the email. The compromised user never receives the security notification that would alert them to the compromise.

## False Positives

1. **User-created cleanup rules.** Users create rules to delete newsletters, notifications, and low-priority email. Context matters — a rule deleting "security alert" is different from a rule deleting "LinkedIn notifications."
2. **Mailbox migration rules.** During migrations, temporary rules may move email to archive folders.

## Tuning Notes

- **Keyword focus.** Prioritize rules targeting security-related keywords. A rule deleting messages containing "password reset" or "suspicious sign-in" is almost always malicious in the context of account compromise.
- **Creation time correlation.** Cross-reference rule creation time with sign-in anomalies. A hiding rule created within 30 minutes of an unfamiliar-IP sign-in is a strong BEC indicator.
- **Sentinel deployment:** NRT rule. These events are low volume and high fidelity when combined with keyword matching.

## Validation

1. Sign in as a test user to Outlook Web App
2. Create an inbox rule: delete messages containing "security alert"
3. Verify the detection fires with the rule action and keyword
4. Delete the test rule immediately

## Learn More

- [SOC Operations — Email & Collaboration Detection](https://ridgelinecyber.com/training/courses/m365-security-operations/) — inbox rule monitoring and BEC investigation
- [Incident Triage and First Response](https://ridgelinecyber.com/training/courses/incident-triage-first-response/) — BEC triage workflow
