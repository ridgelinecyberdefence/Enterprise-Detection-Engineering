# Document Format

This repository holds two kinds of document and they carry different fields. A detection or rule states what fires it and what else it will match, because that is what you need before you deploy it. A script or collection artifact states what it gathers and what to run it against, because that is what you need before you run it.

## Detections and rules

Applies to everything in `kql/`, `sigma/`, `splunk/`, `athena/`, `yara/` and `suricata/`, which the README lists with a severity.

| Field | Description |
|---|---|
| **Title** | What this detects, in plain language |
| **ATT&CK** | Technique ID(s) and tactic(s) |
| **Severity** | Recommended alert severity with reasoning |
| **Data Sources** | Which logs, tables or telemetry must be enabled |
| **Query** | The detection query or rule (KQL, Sigma, SPL, SQL/Athena, YARA, Suricata) |
| **What Triggers This** | The specific attacker behavior that fires it |
| **False Positives** | Known legitimate activity that also matches, with how to tell them apart |
| **Tuning Notes** | Thresholds, exclusions, scoping, and conversion for your platform |
| **Learn More** | The Ridgeline course section that teaches the concept |

### On testing

Test every rule in your own environment before you deploy it. A detection that runs clean in one estate will bury a queue in another, because the false positives depend on your configuration: which agents write to disk, what your configuration management does on a schedule, how your build pipelines authenticate, which logging you have enabled and at what verbosity. None of that is knowable from outside.

The tuning notes give you the thresholds and exclusions to start from and tell you what each one is compensating for, so you can work out whether it applies to you.

## Scripts and collection artifacts

Applies to `powershell/`, `velociraptor/` and `osquery/`, which the README lists by use case rather than severity. These run on demand and produce evidence; they do not fire on activity, so triggers, false positives and severity do not apply to them.

| Field | Description |
|---|---|
| **Title** | What this collects or audits, in plain language |
| **Use Case** | When you would run it |
| **Requirements** | Module, permissions or agent needed |
| **Script** | The script or artifact |
| **What You Get** | The output, and what each field is good for |
| **Limitations** | What it does not capture, and where it will be slow or blocked |
| **Learn More** | The Ridgeline course section that teaches the concept |

## File Naming

`{tactic}-{short-description}.md`

Examples: `credential-access-lsass-access-mask.md`, `persistence-oauth-consent-grant.md`

## Contributing

Pull requests welcome. A detection needs every field in the first table; a script needs every field in the second. Validation steps are welcome where you have run them in a named environment, since a test that depends on your setup is only useful to a reader who knows what that setup was. A query on its own will not be merged, because the reader cannot tune what they cannot see the false positives for.
