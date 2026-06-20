# Rapid Endpoint Triage — Velociraptor Collection Artifact

Custom Velociraptor artifact that collects volatile and persistence evidence from a Windows endpoint in a single operation. Designed for initial triage when you need a fast answer: is this endpoint compromised, and if so, what is the attacker doing right now?

## Use Case

An alert fires. You need to triage the endpoint in minutes, not hours. This artifact collects the critical evidence categories in one collection — no need to run 6 separate built-in artifacts and correlate them manually. Results are structured for immediate analysis in the Velociraptor notebook.

## Requirements

- Velociraptor server 0.7.0+ with the endpoint enrolled as a client
- The artifact must be uploaded to the server before use (Server Artifacts → Add Artifact → paste YAML)
- Collection takes 30-90 seconds per endpoint depending on disk speed

## Artifact — VQL

```yaml
name: Custom.Triage.RapidEndpoint
description: |
  Rapid endpoint triage for incident response. Collects volatile
  state, persistence mechanisms, recent execution, and suspicious
  file activity in a single artifact. Results structured for
  notebook analysis.

  Ridgeline Cyber — https://ridgelinecyber.com/training

author: Ridgeline Cyber Detection Engineering

type: CLIENT

parameters:
  - name: SuspiciousPaths
    type: csv
    default: |
      Path
      C:\Users\*\AppData\Local\Temp\
      C:\Users\*\Downloads\
      C:\ProgramData\
      C:\Windows\Temp\
    description: Directories to scan for recently modified files.
  - name: DaysBack
    type: int
    default: 7
    description: How many days back to look for file modifications.

sources:
  - name: NetworkConnections
    description: Active TCP connections with process context.
    query: |
      SELECT Laddr.IP AS LocalIP,
             Laddr.Port AS LocalPort,
             Raddr.IP AS RemoteIP,
             Raddr.Port AS RemotePort,
             Status,
             Pid,
             process_tracker_get(id=Pid).Data.Name AS ProcessName,
             process_tracker_get(id=Pid).Data.Exe AS ProcessPath
      FROM connections()
      WHERE Status =~ "ESTABLISHED|LISTEN|CLOSE_WAIT"
        AND NOT RemoteIP =~ "^(127\\.0\\.0\\.1|::1|0\\.0\\.0\\.0)$"
      ORDER BY Status, RemoteIP

  - name: ProcessTree
    description: Running processes with parent chain and command line.
    query: |
      SELECT Pid, Ppid, Name, Exe, CommandLine, Username,
             process_tracker_callchain(id=Pid).Data.Name AS ParentChain,
             CreateTime
      FROM process_tracker_pslist()
      ORDER BY CreateTime DESC

  - name: SuspiciousProcesses
    description: Processes from user-writable paths or with encoded commands.
    query: |
      SELECT Pid, Name, Exe, CommandLine, Username, CreateTime
      FROM process_tracker_pslist()
      WHERE Exe =~ "(?i)(\\\\Temp\\\\|\\\\Downloads\\\\|\\\\AppData\\\\|\\\\ProgramData\\\\)"
         OR CommandLine =~ "(?i)(-enc|-encodedcommand|frombase64|downloadstring|iex|invoke-expression|hidden|bypass)"
         OR (Name =~ "(?i)(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)"
             AND Ppid != 0
             AND process_tracker_get(id=Ppid).Data.Name =~ "(?i)(winword|excel|outlook|powerpnt|onenote)")
      ORDER BY CreateTime DESC

  - name: ScheduledTasks
    description: Non-Microsoft scheduled tasks (persistence).
    query: |
      SELECT Name, Path, Enabled, LastRunTime, NextRunTime,
             Actions, Principal
      FROM Artifact.Windows.System.TaskScheduler()
      WHERE NOT Path =~ "^\\\\Microsoft\\\\"
        AND Enabled = true

  - name: RunKeys
    description: Registry Run/RunOnce persistence entries.
    query: |
      LET keys = (
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*",
        "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
        "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*"
      )
      SELECT Name, FullPath, Type,
             Data.value AS Value,
             Mtime AS LastModified
      FROM glob(globs=keys, accessor="registry")

  - name: Services
    description: Non-standard Windows services.
    query: |
      SELECT Name, DisplayName, Status, StartMode, PathName, ServiceDll
      FROM Artifact.Windows.System.Services()
      WHERE NOT PathName =~ "(?i)(\\\\Windows\\\\|\\\\Microsoft)"
        AND StartMode != "Disabled"
      ORDER BY Status DESC

  - name: RecentFiles
    description: Recently modified files in suspicious directories.
    query: |
      LET cutoff <= timestamp(epoch=now() - DaysBack * 86400)
      SELECT FullPath, Size,
             Mtime AS Modified,
             Ctime AS Created,
             hash(path=FullPath, hashselect="SHA256") AS SHA256
      FROM glob(globs=SuspiciousPaths.Path, accessor="auto")
      WHERE NOT IsDir
        AND Mtime > cutoff
        AND Size > 0
        AND NOT Name =~ "\\.(log|tmp|etl)$"
      ORDER BY Mtime DESC
      LIMIT 200

  - name: PrefetchRecent
    description: Recently executed applications (Prefetch).
    query: |
      SELECT Name, Executable, RunCount, LastRunTimes,
             PrefetchFileName, SourceFileName
      FROM Artifact.Windows.Forensics.Prefetch()
      ORDER BY LastRunTimes DESC
      LIMIT 50

  - name: DNSCache
    description: Current DNS resolver cache.
    query: |
      SELECT Name, Type, TTL, Data
      FROM Artifact.Windows.System.DnsCache()
      ORDER BY Name

  - name: UnsignedModules
    description: Unsigned DLLs loaded in running processes.
    query: |
      SELECT ProcessName, Pid, ModuleName, ExePath,
             authenticode(filename=ExePath).Trusted AS Trusted
      FROM modules(pid=0)
      WHERE NOT Trusted = "trusted"
        AND NOT ExePath =~ "(?i)(\\\\Windows\\\\|\\\\Microsoft)"
      ORDER BY ProcessName
      LIMIT 100
```

## What This Collects

| Source | Evidence | Triage value |
|---|---|---|
| **NetworkConnections** | Active TCP with process context | Active C2, lateral movement sessions, exfiltration |
| **ProcessTree** | All processes with parent chains | Full execution context for every running process |
| **SuspiciousProcesses** | Filtered: user-writable paths, encoded commands, Office child processes | High-confidence suspicious process list — investigate these first |
| **ScheduledTasks** | Non-Microsoft enabled tasks | Persistence — attacker tasks in user-writable paths |
| **RunKeys** | Registry Run/RunOnce entries | Persistence — code that executes on every logon |
| **Services** | Non-standard services | Persistence — attacker services at system startup |
| **RecentFiles** | Files modified in last 7 days in temp/downloads/ProgramData | Dropped tools, staged data, attacker artifacts |
| **PrefetchRecent** | Last 50 executed applications | What ran recently — catches deleted tools |
| **DNSCache** | Resolved domains | C2 domains, phishing infrastructure |
| **UnsignedModules** | Unsigned DLLs in running processes | DLL injection, side-loading |

## Triage Workflow in the Notebook

After the collection completes, open the notebook and run these analysis queries:

**1. C2 check — external connections from suspicious processes:**
```vql
SELECT * FROM source(source="NetworkConnections")
WHERE NOT RemoteIP =~ "^(10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|192\\.168\\.)"
  AND ProcessPath =~ "(?i)(Temp|Downloads|AppData|ProgramData)"
```

**2. Persistence installed in the last 7 days:**
```vql
SELECT * FROM chain(
  a={ SELECT "ScheduledTask" AS Type, Name, format(format="%v", args=Actions) AS Detail FROM source(source="ScheduledTasks") },
  b={ SELECT "RunKey" AS Type, Name, Value AS Detail FROM source(source="RunKeys") },
  c={ SELECT "Service" AS Type, Name, PathName AS Detail FROM source(source="Services") }
)
```

**3. Process parent chain anomalies (Office spawning shells):**
```vql
SELECT * FROM source(source="SuspiciousProcesses")
WHERE ParentChain =~ "(?i)(winword|excel|outlook)"
```

## Operational Notes

- **Deploy as a hunt for fleet-wide triage.** During a large-scale incident, run this as a hunt across all endpoints (or a labeled subset). Results aggregate in the hunt notebook for fleet-wide analysis — stacking, outlier detection, and IOC matching.
- **30-90 second collection time.** Fast enough to run on every endpoint in a 500-node fleet within a hunt timeout window.
- **Does not collect memory or disk images.** This is triage evidence for initial assessment. Full forensic collection (MFT, event logs, memory) follows on endpoints where triage confirms compromise.
- **Customise SuspiciousPaths.** Add organization-specific directories (staging directories, application paths) to the parameter CSV.

## Learn More

- [Velociraptor for Endpoint Investigation](https://ridgelinecyber.com/training/courses/velociraptor-endpoint-investigation/) — VQL fundamentals, artifact authoring, hunt operations, and fleet analysis
- [Incident Triage and First Response](https://ridgelinecyber.com/training/courses/incident-triage-first-response/) — triage decision framework and evidence collection methodology
- [Practical Incident Response](https://ridgelinecyber.com/training/courses/practical-ir/) — full investigation workflow from triage through containment
