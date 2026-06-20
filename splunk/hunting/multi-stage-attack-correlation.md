# Multi-Stage Attack: Kill-Chain Correlation on One Host

Detects a single host exhibiting several distinct attack stages in one window. Individual technique alerts can be dismissed in isolation; stacking the signatures turns a pile of medium alerts into one decisive finding that a host is compromised.

## ATT&CK

- **Technique:** Correlation across T1566.001, T1059.001, T1003.001, T1053.005, T1047, T1490, T1071
- **Tactic:** Multiple, kill-chain stacking

## Severity

**Critical.** A host showing two or more distinct attack stages is an intrusion in progress. The strength is breadth across the kill chain, not the volume of any one stage.

## Data Sources

- Sysmon Event ID 1 and 3, `sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`
- Requires: the component endpoint detections in place and a `threatintel` lookup for the C2 stage

## Query

```spl
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" earliest=-24h
| lookup threatintel indicator AS dest_ip OUTPUT threat_category
| eval sig=case(
    (parent_process_name="WINWORD.EXE" OR parent_process_name="EXCEL.EXE" OR parent_process_name="OUTLOOK.EXE")
        AND (process_name="powershell.exe" OR process_name="cmd.exe"), "office_shell",
    process_name="powershell.exe" AND (like(CommandLine,"%-enc%") OR like(CommandLine,"%-w hidden%")), "encoded_ps",
    process_name="rundll32.exe" AND like(CommandLine,"%comsvcs%"), "lsass_dump",
    process_name="schtasks.exe" AND like(CommandLine,"%/create%"), "persistence",
    process_name="wmic.exe" AND like(CommandLine,"%node:%"), "lateral",
    (process_name="vssadmin.exe" OR process_name="wbadmin.exe" OR process_name="bcdedit.exe"), "recovery_inhibition",
    isnotnull(threat_category), "c2")
| where isnotnull(sig)
| stats dc(sig) AS stages, values(sig) AS kill_chain, min(_time) AS first_seen, max(_time) AS last_seen by host
| where stages >= 2
| sort - stages
```

## What Triggers This

A host stacking distinct kill-chain stages:

- Two or more of execution, obfuscation, credential access, persistence, lateral movement, C2, or recovery inhibition
- All on one host within the window
- Breadth across stages rather than volume in any one

## False Positives

1. **Scripted admin hosts.** A heavily scripted administration or imaging host could stack benign matches. Allowlist those hosts.
2. **Tooling overlap.** Security tooling that mimics several behaviors. Tune each `sig` clause to your allowlists.
3. **Test systems.** Lab and validation hosts trigger multiple clauses. Exclude them.

## Tuning Notes

- **This is the prioritisation layer.** It ranks above the individual endpoint detections, not a replacement for them.
- **Tune each clause to allowlists.** Ensure a host does not stack stages from sanctioned automation.
- **Escalate on breadth.** Raise to immediate response at `stages >= 3` and feed the matched `kill_chain` into the investigation timeline.

## Validation

1. On an isolated test host, trigger two component behaviors (for example office_shell and encoded_ps) within the window.
2. Confirm the host surfaces with `stages >= 2` and both labels listed.

## Learn More

- [Splunk Detection and Incident Response: Threat Hunting](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/). kill-chain stacking and host-level correlation
- [Detection Engineering: Correlation and Risk-Based Alerting](https://ridgelinecyber.com/training/courses/detection-engineering/). combining signals into prioritised findings
