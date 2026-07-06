# Transport Rule Manipulation: BCC, Redirect, or Header Removal

Detects creation or modification of Exchange transport rules that BCC, redirect, or strip headers from email. Transport rules operate at the organization level and affect all mail flow. A single malicious rule can silently copy every email in the tenant.

## ATT&CK

- **Technique:** T1114.003. Email Collection: Email Forwarding Rule, T1564.008, Hide Artifacts: Email Hiding Rules
- **Tactic:** Persistence, Collection

## Severity

**Critical.** Transport rules are organization-scoped. A BCC rule forwarding all email to an external address exfiltrates the entire tenant's email traffic. These rules are invisible to individual users and persist until an admin removes them.

## Data Sources

- Microsoft 365 Unified Audit Log. `OfficeActivity` or Exchange Admin audit logs
- Requires: Exchange Online audit logging enabled

## Query: Sigma

```yaml
title: Transport Rule Manipulation — BCC, Redirect, or Header Removal
id: det-soc-010
status: production
description: |
  Detects creation or modification of transport rules with
  BlindCopyTo, RedirectMessageTo, or RemoveHeader parameters.
  Organization-wide email interception. Requires Exchange Admin.
  CardinalOps contributed T1114.003 updates to ATT&CK v13 for
  this technique.
author: Ridgeline Cyber Detection Engineering
date: 2026/05/17
tags:
  - attack.collection
  - attack.t1114.003
  - attack.defense_evasion
  - attack.t1564.008
logsource:
  product: m365
  service: exchange
detection:
  selection:
    Operation:
      - 'New-TransportRule'
      - 'Set-TransportRule'
      - 'Enable-TransportRule'
    Parameters|contains:
      - 'BlindCopyTo'
      - 'RedirectMessageTo'
      - 'RemoveHeader'
  condition: selection
falsepositives:
  - Legitimate compliance journaling rules (BCC to compliance mailbox)
  - DLP transport rules that redirect to quarantine
  - Email disclaimer/signature rules
level: high
```

## What Triggers This

An attacker with Exchange admin privileges (or compromised admin credentials) creates a transport rule to:

- **BCC all email** to an external address. Silent copy of every message
- **Redirect specific email** matching keywords (invoice, payment, wire transfer) to an external recipient
- **Strip email headers** to remove security indicators or delivery notifications
- **Add disclaimers or modify subjects** to inject phishing content into legitimate email flow

Transport rules operate before inbox rules and affect all users in the organization. They are the highest-impact email persistence mechanism available to an attacker.

## False Positives

1. **Legitimate compliance rules.** Organizations create transport rules for regulatory BCC (legal hold), disclaimer insertion, and DLP. These should be pre-documented in your transport rule inventory.
2. **Email security products.** Some email security gateways create transport rules during setup. Validate the creating admin account.
3. **Signature management tools.** Products like Exclaimer and CodeTwo modify transport rules for email signatures.

## Tuning Notes

- **Baseline your transport rules.** Document every transport rule in production. Any new rule creation or modification is an alert. Transport rule changes should be rare and controlled through change management.
- **Admin account monitoring.** Cross-reference the admin who created the rule with sign-in logs. A transport rule created from an unfamiliar IP or after hours is high priority.
- **Sentinel deployment:** NRT rule. Transport rule changes are extremely rare in normal operations.

## Validation

1. In a test tenant, create a transport rule with a BCC action to a test mailbox
2. Verify the detection fires and captures the rule name, action, and creating admin
3. Delete the test rule immediately

## Learn More

- [SOC Operations: Email & Collaboration Detection](https://ridgelinecyber.com/training/courses/m365-security-operations/). transport rule monitoring and BEC investigation
- [Detection Engineering](https://ridgelinecyber.com/training/courses/detection-engineering/). email detection rule design
