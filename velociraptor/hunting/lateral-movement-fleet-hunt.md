# Lateral Movement Hunt: Fleet-Wide Detection

Velociraptor hunt artifact that detects lateral movement indicators across an entire endpoint fleet. Identifies anomalous remote logons, PsExec/WMI/WinRM execution, and remote service installation. Designed to run as a hunt. Results aggregate across all endpoints so you can identify the attacker's movement path through the network.

## Use Case

You've confirmed a compromise on one endpoint. The attacker likely moved laterally. Running this hunt across the fleet shows every endpoint where the attacker authenticated, every remote command they executed, and every persistence mechanism they installed. In one operation instead of checking endpoints one at a time.

## Requirements

- Velociraptor server 0.7.0+ with fleet-wide enrollment
- Sysmon installed with Event ID 1 (Process Create) and Event ID 3 (Network Connect) logging
- Windows Security Audit: Logon events (4624, 4625) with Logon Type tracking
- Hunt across all Windows clients or a labeled subset

## Artifact: VQL

```yaml
name: Custom.Hunt.LateralMovement
description: |
  Fleet-wide lateral movement detection. Identifies remote logons,
  remote execution tools (PsExec, WMI, WinRM, SMB), and remote
  service installations across all enrolled endpoints. Run as a
  hunt to map the attacker's movement path through the network.

  Results from all endpoints aggregate in the hunt notebook for
  cross-correlation and path reconstruction.

  Ridgeline Cyber — https://ridgelinecyber.com/training

author: Ridgeline Cyber Detection Engineering

type: CLIENT

parameters:
  - name: DaysBack
    type: int
    default: 14
    description: How many days of event log history to search.
  - name: ExcludedAccounts
    type: csv
    default: |
      Account
      SYSTEM
      LOCAL SERVICE
      NETWORK SERVICE
      DWM-1
      DWM-2
      UMFD-0
      UMFD-1
    description: Service accounts to exclude from logon analysis.
  - name: KnownAdminHosts
    type: csv
    default: |
      Hostname
    description: Known admin jump servers to reduce false positives.

sources:
  - name: RemoteLogons
    description: |
      Type 3 (network), Type 10 (RDP), and Type 3 with elevated
      token from non-machine accounts. The foundation of lateral
      movement detection — every technique requires authentication.
    query: |
      LET cutoff <= timestamp(epoch=now() - DaysBack * 86400)
      LET excluded <= ExcludedAccounts.Account
      SELECT EventTime, Computer,
             EventData.TargetUserName AS User,
             EventData.TargetDomainName AS Domain,
             EventData.LogonType AS LogonType,
             EventData.IpAddress AS SourceIP,
             EventData.WorkstationName AS SourceHost,
             EventData.LogonProcessName AS LogonProcess,
             EventData.AuthenticationPackageName AS AuthPackage,
             EventData.ElevatedToken AS ElevatedToken
      FROM Artifact.Windows.EventLogs.EvtxHunter(
        EvtxGlob="C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
        IdRegex="^4624$",
        DateAfter=cutoff
      )
      WHERE EventData.LogonType in ("3", "10")
        AND NOT EventData.TargetUserName in excluded
        AND NOT EventData.TargetUserName =~ "\\$$"
        AND EventData.IpAddress != "-"
        AND EventData.IpAddress != "127.0.0.1"
      ORDER BY EventTime DESC

  - name: RemoteExecution
    description: |
      Detects PsExec, WMI, WinRM, and SMB-based remote execution
      by identifying their characteristic process creation patterns.
    query: |
      LET cutoff <= timestamp(epoch=now() - DaysBack * 86400)
      SELECT EventTime, Computer,
             EventData.User AS User,
             EventData.ParentImage AS ParentProcess,
             EventData.Image AS Process,
             EventData.CommandLine AS CommandLine,
             EventData.ParentCommandLine AS ParentCommandLine
      FROM Artifact.Windows.EventLogs.EvtxHunter(
        EvtxGlob="C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
        IdRegex="^1$",
        DateAfter=cutoff
      )
      WHERE (
        // PsExec service-side execution
        EventData.ParentImage =~ "(?i)psexesvc\\.exe$"
        // WMI remote execution
        OR EventData.ParentImage =~ "(?i)wmiprvse\\.exe$"
        // WinRM remote execution
        OR EventData.ParentImage =~ "(?i)wsmprovhost\\.exe$"
        // SMB-delivered execution via service creation
        OR (EventData.ParentImage =~ "(?i)services\\.exe$"
            AND EventData.Image =~ "(?i)(cmd\\.exe|powershell\\.exe|pwsh\\.exe)")
        // DCOM-based execution
        OR EventData.ParentImage =~ "(?i)mmc\\.exe$"
           AND EventData.Image =~ "(?i)(cmd\\.exe|powershell\\.exe)"
      )
      ORDER BY EventTime DESC

  - name: RemoteServiceInstall
    description: |
      New service installations — the persistence step that often
      follows lateral movement. Event ID 7045 (System log).
    query: |
      LET cutoff <= timestamp(epoch=now() - DaysBack * 86400)
      SELECT EventTime, Computer,
             EventData.ServiceName AS ServiceName,
             EventData.ImagePath AS ServicePath,
             EventData.ServiceType AS ServiceType,
             EventData.StartType AS StartType,
             EventData.AccountName AS RunAs
      FROM Artifact.Windows.EventLogs.EvtxHunter(
        EvtxGlob="C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
        IdRegex="^7045$",
        DateAfter=cutoff
      )
      WHERE NOT EventData.ImagePath =~ "(?i)(\\\\Windows\\\\|\\\\Microsoft|\\\\Program Files)"
      ORDER BY EventTime DESC

  - name: FailedRemoteLogons
    description: |
      Failed network logons (Event 4625) — the attacker trying
      credentials that don't work. Shows where they attempted
      access before succeeding.
    query: |
      LET cutoff <= timestamp(epoch=now() - DaysBack * 86400)
      LET excluded <= ExcludedAccounts.Account
      SELECT EventTime, Computer,
             EventData.TargetUserName AS User,
             EventData.LogonType AS LogonType,
             EventData.IpAddress AS SourceIP,
             EventData.WorkstationName AS SourceHost,
             EventData.Status AS Status,
             EventData.SubStatus AS SubStatus,
             EventData.FailureReason AS FailureReason
      FROM Artifact.Windows.EventLogs.EvtxHunter(
        EvtxGlob="C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
        IdRegex="^4625$",
        DateAfter=cutoff
      )
      WHERE EventData.LogonType in ("3", "10")
        AND NOT EventData.TargetUserName in excluded
        AND NOT EventData.TargetUserName =~ "\\$$"
        AND EventData.IpAddress != "-"
      ORDER BY EventTime DESC

  - name: SMBShares
    description: |
      Network share access events — shows which shares the attacker
      accessed on this endpoint. Event ID 5140 (object access audit).
    query: |
      LET cutoff <= timestamp(epoch=now() - DaysBack * 86400)
      SELECT EventTime, Computer,
             EventData.SubjectUserName AS User,
             EventData.IpAddress AS SourceIP,
             EventData.ShareName AS ShareName,
             EventData.ShareLocalPath AS LocalPath,
             EventData.AccessMask AS AccessMask
      FROM Artifact.Windows.EventLogs.EvtxHunter(
        EvtxGlob="C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
        IdRegex="^5140$",
        DateAfter=cutoff
      )
      WHERE NOT EventData.SubjectUserName =~ "(SYSTEM|\\$$)"
        AND EventData.ShareName != "\\\\*\\IPC$"
      ORDER BY EventTime DESC
```

## What This Detects

| Source | Evidence | What it means |
|---|---|---|
| **RemoteLogons** | Type 3 and Type 10 logons from non-service accounts | Every lateral movement technique authenticates first. This shows every remote logon on every endpoint. |
| **RemoteExecution** | PsExec, WMI, WinRM, DCOM child processes | The attacker's remote execution. Parent process identifies the technique (psexesvc = PsExec, wmiprvse = WMI, wsmprovhost = WinRM). |
| **RemoteServiceInstall** | New services with binaries outside system directories | Persistence planted after moving to a new endpoint. Services in `C:\Windows\Temp\` or `C:\ProgramData\` are high confidence. |
| **FailedRemoteLogons** | Failed Type 3/10 authentication attempts | Where the attacker tried credentials that didn't work. Maps the attempted scope of movement, not just the successful scope. |
| **SMBShares** | File share access events | Shows what data the attacker accessed. Shares like `C$`, `ADMIN$` indicate admin-level access. Named shares indicate targeted data access. |

## Hunt Notebook Analysis

After the hunt completes, use these notebook queries to reconstruct the attacker's path:

**1. Build the movement graph. Source → destination by time:**
```vql
SELECT SourceIP, Computer AS Destination, User,
       min(EventTime) AS FirstSeen,
       max(EventTime) AS LastSeen,
       count() AS LogonCount
FROM source(source="RemoteLogons")
GROUP BY SourceIP, Computer, User
ORDER BY FirstSeen ASC
```

**2. Identify the pivot host. Endpoints that are both source and destination:**
```vql
LET destinations = SELECT Computer FROM source(source="RemoteLogons") GROUP BY Computer
LET sources = SELECT SourceIP FROM source(source="RemoteLogons") GROUP BY SourceIP
SELECT * FROM destinations WHERE Computer IN sources.SourceIP
```

**3. Timeline of remote execution across the fleet:**
```vql
SELECT EventTime, Computer, User, ParentProcess, Process, CommandLine
FROM source(source="RemoteExecution")
ORDER BY EventTime ASC
```

## Operational Notes

- **Run as a hunt, not a single collection.** The value is in aggregating results across the fleet. A single endpoint's logon events tell you who accessed that machine. Fleet-wide results tell you the complete attack path.
- **Scope with labels.** For large environments, scope the hunt to the network segment where the initial compromise was confirmed. Expand if the movement path crosses segments.
- **Time window.** 14 days default covers most incidents. Reduce to 3-7 days if you know the compromise window. Increase to 30 days for long-dwell investigations.
- **Performance.** Event log parsing on each endpoint takes 2-5 minutes depending on log volume. A 500-endpoint hunt completes in 10-15 minutes with default Velociraptor concurrency.
- **Combine with the triage artifact.** Run `Custom.Triage.RapidEndpoint` on endpoints identified as compromised by this hunt to collect full volatile evidence.

## Learn More

- [Velociraptor for Endpoint Investigation](https://ridgelinecyber.com/training/courses/velociraptor-endpoint-investigation/). hunt operations, fleet analysis, stacking, and VQL artifact authoring
- [Practical Incident Response](https://ridgelinecyber.com/training/courses/practical-ir/). lateral movement investigation methodology and containment decisions
- [Offensive Security for Defenders](https://ridgelinecyber.com/training/courses/offensive-security-for-defenders/). how attackers execute PsExec, WMI, WinRM, and what telemetry each produces
