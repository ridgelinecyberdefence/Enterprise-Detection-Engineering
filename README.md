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
| [LSASS Access Mask Monitoring](kql/credential-access/lsass-access-mask-monitoring.md) | Credential Access | High |
| [OAuth Illicit Consent Grant](kql/persistence/oauth-illicit-consent-grant.md) | Persistence | High |
| [Inbox Rule — BEC Persistence](kql/persistence/inbox-rule-bec-persistence.md) | Persistence, Collection | High |

### Sigma — Vendor-Agnostic

| Detection | Tactic | Severity |
|---|---|---|
| [LOLBin Download or Decode](sigma/defense-evasion/lolbin-download-decode.md) | Defense Evasion, Execution | Medium |
| [Privileged Role Assignment Outside PIM](sigma/privilege-escalation/privileged-role-outside-pim.md) | Privilege Escalation | High |

### PowerShell — Triage & Collection

*Coming soon — triage scripts, evidence collection, and Graph API automation.*

### Velociraptor — Endpoint Investigation

*Coming soon — VQL collection artifacts and hunt queries.*

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
