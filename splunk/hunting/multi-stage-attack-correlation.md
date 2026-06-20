# Multi-Stage Attack Correlation on a Single Host

**ATT&CK:** Correlation across T1566.001, T1059.001, T1003.001, T1053.005, T1047, T1490, and T1071. Tactic: multiple (kill-chain stacking).

**Severity:** Critical. Individual technique alerts can be dismissed in isolation. A single host exhibiting several distinct attack stages in one window is an intrusion in progress, and stacking the signatures turns a pile of medium alerts into one decisive finding.

**Data Sources:** Sysmon Event ID 1 and 3 (`sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`), enriched with the `threatintel` lookup.

**Query:**

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

**What Triggers This:** A host that exhibits two or more distinct attack stages (initial execution, obfuscation, credential access, persistence, lateral movement, C2, or recovery inhibition) within the window. The strength is breadth across the kill chain, not the volume of any one stage.

**False Positives:** Lower than the individual detections, because requiring multiple distinct stages on one host is inherently selective. A heavily scripted administration or imaging host could stack benign matches; allowlist those hosts.

**Tuning Notes:** Treat this as the prioritisation layer above the individual endpoint detections, not a replacement for them. Tune each `sig` clause to your allowlists so a host does not stack stages from sanctioned automation. Raise to immediate response at `stages >= 3`, and feed the matched `kill_chain` straight into the investigation timeline.

**Validation:** On an isolated test host, trigger two of the component behaviours (for example office_shell and encoded_ps) within the window; confirm the host surfaces with `stages >= 2` and both labels listed.

**Learn More:** [Splunk Detection and Incident Response: Threat Hunting](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/) covers kill-chain stacking and host-level correlation.
