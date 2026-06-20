# Office Application — Spawning a Shell or Script Host

Detects a Word, Excel, PowerPoint, or Outlook process launching PowerShell, cmd, or a script host. This lineage is the classic macro or attachment execution chain, and Office applications have no routine reason to spawn an interpreter.

## ATT&CK

- **Technique:** T1059 — Command and Scripting Interpreter, T1566.001 — Phishing: Spearphishing Attachment
- **Tactic:** Execution

## Severity

**High.** An Office parent spawning an interpreter is the execution stage of a document-borne attack and is rare enough in most estates to be high-fidelity on its own.

## Data Sources

- Endpoint process telemetry mapped to the CIM Endpoint data model — Sysmon Event ID 1, EDR, or Windows 4688
- Requires: parent process and command-line logging; data-model acceleration for `tstats`

## Query

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

## What Triggers This

An Office parent spawning an interpreter child:

- WINWORD, EXCEL, POWERPNT, or OUTLOOK as the parent process
- PowerShell, cmd, or a script host (wscript, cscript, mshta) as the child
- The pairing itself, which is the document-execution signature regardless of payload

## False Positives

1. **Enterprise add-ins.** A few signed add-ins and document-automation tools invoke scripting. Allowlist by specific parent-child-commandline or signed publisher.
2. **Templated reporting macros.** Sanctioned macros that shell out for data processing. Exclude by hash and scope to known teams.
3. **Outlook helpers.** Outlook generates more child processes through preview and link handling; consider a separate, higher-threshold treatment.

## Tuning Notes

- **Allowlist sanctioned combinations.** Exclude known parent-child-commandline patterns by hash or publisher, not by dropping the lineage.
- **Enrich with assets.** Use the `asset` lookup so internet-facing and high-priority hosts rank first.
- **Raw fallback.** Over raw Sysmon, filter `EventCode=1` with the same name lists.

## Validation

1. On a test host, have Excel launch `cmd.exe /c whoami` via a benign macro.
2. Confirm the lineage surfaces with the expected parent and child.

## Learn More

- [Splunk Detection and Incident Response — Endpoint Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/) — process-lineage detection over the Endpoint data model
- [Detection Engineering — Custom Endpoint Detections](https://ridgelinecyber.com/training/courses/detection-engineering/) — behavioral lineage detection
