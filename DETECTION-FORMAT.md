# Detection Document Format

Every detection in this repository follows this structure. The goal is deployable context. Not just the query, but everything you need to tune and operate it.

## Required Fields

| Field | Description |
|---|---|
| **Title** | What this detects, in plain language |
| **ATT&CK** | Technique ID(s) and tactic(s) |
| **Severity** | Recommended alert severity with reasoning |
| **Data Sources** | Which logs/tables must be enabled |
| **Query** | The detection query (KQL, Sigma, SPL, SQL/Athena, PowerShell, or VQL) |
| **What Triggers This** | The specific attacker behavior that fires the detection |
| **False Positives** | Known legitimate activity that matches, with tuning guidance |
| **Tuning Notes** | Environment-specific adjustments (thresholds, exclusions, scoping) |
| **Validation** | How to test that the detection works |
| **Learn More** | Link to the Ridgeline course section that teaches the concept |

## File Naming

`{tactic}-{short-description}.md`

Examples: `credential-access-lsass-access-mask.md`, `persistence-oauth-consent-grant.md`

## Contributing

Pull requests welcome. Every submission must include all required fields. Raw queries without context will not be merged.
