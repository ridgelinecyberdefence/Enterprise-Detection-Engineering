# Ridgeline Detection Library

Production-validated detection queries with the context you need to deploy and tune them. Every detection includes the query, what triggers it, known false positives, tuning guidance, and a link to the Ridgeline course that teaches the underlying concept.

## What makes this different

Other repos give you queries. This one gives you queries you can actually deploy.

Every detection in this library includes:

- **The query** — KQL, Sigma, SPL, PowerShell, or VQL
- **What triggers it** — the specific attacker behavior, not a vague description
- **False positives** — what legitimate activity matches and how to distinguish it
- **Tuning notes** — thresholds, exclusions, and environment-specific adjustments
- **Validation steps** — how to test that the detection works before relying on it
- **Learn more** — the Ridgeline training module that teaches the concept in depth

## Detections

### KQL — Microsoft Sentinel & Defender XDR

| Detection | Tactic | Severity |
|---|---|---|
| [AiTM Token Replay — User-Agent Similarity Analysis](kql/credential-access/aitm-token-replay-useragent-similarity.md) | Credential Access | Critical |
| [DCSync — Directory Replication Abuse](kql/credential-access/dcsync-directory-replication-abuse.md) | Credential Access | Critical |
| [LSASS Access Mask Monitoring](kql/credential-access/lsass-access-mask-monitoring.md) | Credential Access | High |
| [Service Principal Credential + Immediate API Activity](kql/lateral-movement/service-principal-credential-then-authenticate.md) | Lateral Movement, Persistence | Critical |
| [OAuth Illicit Consent Grant](kql/persistence/oauth-illicit-consent-grant.md) | Persistence | High |
| [Inbox Rule — BEC Persistence](kql/persistence/inbox-rule-bec-persistence.md) | Persistence, Collection | High |
| [BEC Outbound Email — Payment Keywords](kql/collection/bec-payment-keyword-outbound.md) | Impact | Critical |
| [Application Permission Escalation](kql/privilege-escalation/app-permission-escalation.md) | Privilege Escalation | High |

### Sigma — Vendor-Agnostic

| Detection | Tactic | Severity |
|---|---|---|
| [LOLBin Download or Decode](sigma/defense-evasion/lolbin-download-decode.md) | Defense Evasion, Execution | Medium |
| [Privileged Role Assignment Outside PIM](sigma/privilege-escalation/privileged-role-outside-pim.md) | Privilege Escalation | High |
| [PowerShell with Multiple Evasion Indicators](sigma/execution/powershell-evasion-indicators.md) | Execution, Defense Evasion | High |
| [Transport Rule Manipulation](sigma/persistence/transport-rule-manipulation.md) | Persistence, Collection | Critical |
| [Conditional Access Policy Weakened](sigma/defense-evasion/conditional-access-policy-weakened.md) | Defense Evasion | High |
| [Persistence via Scheduled Task, Run Key, or Service](sigma/persistence/scheduled-task-run-key-service.md) | Persistence | Medium |
| [Inbox Rule Deleting or Hiding Email](sigma/defense-evasion/inbox-rule-hiding-email.md) | Defense Evasion | High |

### PowerShell — Triage & Collection

| Script | Category | Use Case |
|---|---|---|
| [Volatile Evidence Collection](powershell/collection/volatile-evidence-collection.md) | Collection | First-responder script: network state, processes, persistence, DNS cache — before isolation destroys it |
| [Entra ID Compromise Assessment](powershell/investigation/entra-id-compromise-assessment.md) | Investigation | Post-incident audit: OAuth consent, inbox rules, CA policy changes, credential additions, role assignments |

### Velociraptor — Endpoint Investigation

| Artifact | Category | Use Case |
|---|---|---|
| [Rapid Endpoint Triage](velociraptor/collection/rapid-endpoint-triage.md) | Collection | Single-endpoint triage in 30-90 seconds: processes, connections, persistence, recent files, DNS cache |
| [Lateral Movement Fleet Hunt](velociraptor/hunting/lateral-movement-fleet-hunt.md) | Hunting | Fleet-wide lateral movement detection: remote logons, PsExec/WMI/WinRM, service installs, share access |

## Format

Every detection follows the [standard format](DETECTION-FORMAT.md). Contributions must include all required fields.

## Training

Every detection in this library maps to a module in the [Ridgeline Cyber training platform](https://training.ridgelinecyber.com). The detection gives you the query. The training gives you the capability to write, tune, and operate detections like these across your environment.

- [Detection Engineering](https://training.ridgelinecyber.com/courses/detection-engineering/) — rule architecture, threat modeling, detection lifecycle
- [SOC Operations](https://training.ridgelinecyber.com/courses/m365-security-operations/) — investigation playbooks, alert triage, response actions
- [Entra ID Security](https://training.ridgelinecyber.com/courses/entra-id-security/) — identity detection, Conditional Access, PIM governance
- [Endpoint Security](https://training.ridgelinecyber.com/courses/endpoint-security/) — endpoint detection, LSASS protection, ASR rules

Free modules on every course. No account required to start.

## Contributing

Pull requests welcome. Every submission must follow the [detection format](DETECTION-FORMAT.md) and include all required fields — query, false positives, tuning notes, and validation steps. Raw queries without context will not be merged.

## License

[Apache 2.0](LICENSE) — deploy these detections in your environment, modify them, share them.

---

Built by [Ridgeline Cyber](https://training.ridgelinecyber.com) — practitioners who build detections in production, then teach others to do the same.
