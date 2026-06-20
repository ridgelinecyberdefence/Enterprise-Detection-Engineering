# Office Application Spawning a Shell or Script Host

**ATT&CK:** T1059 Command and Scripting Interpreter; T1566.001 Phishing: Spearphishing Attachment. Tactic: Execution.

**Severity:** High. A Word, Excel, PowerPoint, or Outlook process launching PowerShell, cmd, or a script host is the classic macro or attachment execution chain. Office applications have no routine reason to spawn an interpreter.

**Data Sources:** Endpoint process telemetry mapped to the CIM Endpoint data model (Sysmon Event ID 1, EDR, or Windows 4688), accelerated for `tstats`.

**Query:**

```spl
| tstats summariesonly=t count, min(_time) AS first_seen, max(_time) AS last_seen
    from datamodel=Endpoint where nodename="Endpoint.Processes"
    (Endpoint.process_name="powershell.exe" OR Endpoint.process_name="cmd.exe"
     OR Endpoint.process_name="wscript.exe" OR Endpoint.process_name="cscript.exe"
     OR Endpoint.process_name="mshta.exe")
    (Endpoint.parent_process_name="WINWORD.EXE" OR Endpoint.parent_process_name="EXCEL.EXE"
     OR Endpoint.parent_process_name="POWERPNT.EXE" OR Endpoint.parent_process_name="OUTLOOK.EXE")
    by Endpoint.dest, Endpoint.user, Endpoint.parent_process_name, Endpoint.process_name
| lookup asset nt_host AS Endpoint.dest OUTPUT priority, is_internet_facing, owner
| sort - count
```

**What Triggers This:** An Office parent process spawning an interpreter child. This lineage is the execution stage of a document-borne attack and is rare enough in most estates that it is high-fidelity on its own.

**False Positives:** A handful of enterprise add-ins, document-automation tools, and templated reporting macros legitimately invoke scripting. Distinguish by the specific parent-child pair, the command line, and whether the host belongs to a team that runs sanctioned macros.

**Tuning Notes:** Build an allowlist of sanctioned parent-child-commandline combinations and exclude them by hash or signed publisher rather than dropping the whole lineage. Enrich with the `asset` lookup so internet-facing and high-priority hosts rank first. If running over raw Sysmon instead of the data model, filter `EventCode=1` with the same name lists.

**Validation:** On a test host, have Excel launch `cmd.exe /c whoami` via a benign macro; confirm the lineage surfaces with the expected parent and child.

**Learn More:** [Splunk Detection and Incident Response: Endpoint Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/) covers process-lineage detection over the Endpoint data model.
