# LOLBin Cluster Spawned from cmd.exe

**ATT&CK:** T1218 System Binary Proxy Execution. Tactics: Defense Evasion, Execution.

**Severity:** High. Any one signed Windows binary running is unremarkable. Several distinct living-off-the-land binaries spawned from the same `cmd.exe` in a short span is the texture of an operator working a host by hand.

**Data Sources:** Sysmon Event ID 1, `sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`.

**Query:**

```spl
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
    (process_name="rundll32.exe" OR process_name="wmic.exe" OR process_name="schtasks.exe"
     OR process_name="regsvr32.exe" OR process_name="mshta.exe" OR process_name="certutil.exe"
     OR process_name="vssadmin.exe" OR process_name="wbadmin.exe" OR process_name="bcdedit.exe"
     OR process_name="bitsadmin.exe")
    parent_process_name="cmd.exe"
| stats dc(process_name) AS distinct_lolbins, values(process_name) AS lolbins,
        values(CommandLine) AS command_lines, min(_time) AS first_seen by host, user
| where distinct_lolbins >= 2
| sort - distinct_lolbins
```

**What Triggers This:** Two or more distinct LOLBins launched from `cmd.exe` on one host. The fidelity comes from breadth: a single binary is common, but a cluster of distinct ones under an interactive shell is the working pattern of hands-on-keyboard activity.

**False Positives:** Administrative scripts, software installers, and imaging tooling chain several of these binaries legitimately. Distinguish by whether the host is in a maintenance window and whether the command lines match known scripts.

**Tuning Notes:** Allowlist known administrative and imaging scripts by command-line pattern or signed parent. Raise the `distinct_lolbins` floor in estates with heavy scripted administration. Weight destructive binaries (`vssadmin`, `wbadmin`, `bcdedit`) upward, since their presence in the cluster shifts intent toward impact.

**Validation:** On a test host, run two or more of the listed binaries from a single `cmd.exe` session and confirm the host surfaces with `distinct_lolbins >= 2`.

**Learn More:** [Splunk Detection and Incident Response: Endpoint Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/) covers LOLBin clustering and breadth-based fidelity.
