# Conditional Access Policy Weakened

Detects modifications to Conditional Access policies that reduce their security posture. Disabling policies, adding broad exclusions, weakening grant controls, or changing from enforce to report-only mode.

## ATT&CK

- **Technique:** T1562.001. Impair Defenses: Disable or Modify Tools
- **Tactic:** Defense Evasion

## Severity

**High.** Conditional Access policies are the primary access control layer in Entra ID. Weakening a policy opens an authentication bypass the attacker can exploit immediately. A policy changed from "enforce" to "report-only" stops blocking threats but continues logging. The attacker's access works while the audit trail looks normal.

## Data Sources

- Entra ID Audit Logs, `AuditLogs` table in Sentinel
- Requires: Entra ID P1 or P2 for Conditional Access

## Query: Sigma

```yaml
title: Conditional Access Policy Weakened
id: det-soc-006
status: production
description: |
  Detects CA policy state changes from enabled to report-only
  or disabled, and CA policy deletions. Defense evasion —
  attacker removes MFA/device requirements to operate freely.
author: Ridgeline Cyber Detection Engineering
date: 2026/05/17
tags:
  - attack.defense_evasion
  - attack.t1562.001
logsource:
  product: azure
  service: auditlogs
detection:
  selection_update:
    OperationName: 'Update conditional access policy'
  selection_delete:
    OperationName: 'Delete conditional access policy'
  condition: selection_update or selection_delete
falsepositives:
  - Planned CA policy testing (switching to report-only during change window)
  - Policy cleanup during CA consolidation
  - Seasonal policy adjustments (e.g., relaxing location restrictions for company travel)
level: high
```

## What Triggers This

An attacker with sufficient privileges (Conditional Access Administrator, Security Administrator, or Global Administrator) modifies a CA policy to:

- **Disable the policy**. Changes state from "enabled" to "disabled" or "report-only"
- **Add exclusions**. Excludes a user, group, or application from the policy's scope
- **Weaken grant controls**. Changes from "require MFA" to "allow" or removes device compliance requirements
- **Modify session controls**. Removes sign-in frequency or persistent browser restrictions

## False Positives

1. **Planned policy changes.** CA policy modifications happen during security architecture changes, onboarding new applications, or responding to user experience issues. These should go through change management.
2. **PIM-activated changes.** An admin who activated a PIM role to make a planned change. Correlate with PIM activation logs.
3. **Break-glass account testing.** Periodic testing of emergency access accounts may temporarily modify CA policies.

## Tuning Notes

- **Change management correlation.** If your organization uses a change management system, correlate CA policy changes with approved change tickets. Unplanned changes are high priority.
- **Time-of-day analysis.** CA policy changes at 2 AM from an unfamiliar IP are almost certainly malicious. Normal changes happen during business hours by known admins.
- **Sentinel deployment:** NRT rule. CA policy changes should be rare and every one warrants review.

## Validation

1. In a test tenant, create a test CA policy in report-only mode
2. Change the policy to disabled
3. Verify the detection fires and captures the policy name, change type, and admin
4. Re-enable the test policy

## Learn More

- [Entra ID Security: Conditional Access](https://ridgelinecyber.com/training/courses/entra-id-security/). CA policy architecture, governance, and monitoring
- [Identity and Access Management](https://ridgelinecyber.com/training/courses/identity-access-management/). identity security controls and detection
