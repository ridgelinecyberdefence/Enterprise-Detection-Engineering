# Forensic Timeline Construction

Builds a unified forensic timeline from multiple evidence sources on a single endpoint: MFT timestamps, event logs, Prefetch, Amcache, ShellBags, recent files, and browser history. Outputs a chronologically sorted timeline that shows exactly what happened on the endpoint during the investigation window.

## ATT&CK Coverage

Supports investigation across all tactics by providing temporal context for attacker activity.

## Artifact

```yaml
name: Custom.Windows.Investigation.TimelineBuilder
description: |
  Build a unified forensic timeline from multiple evidence sources.
  Merges MFT, event logs, Prefetch, Amcache, ShellBags, and browser
  history into a single chronological view.

type: CLIENT

parameters:
  - name: StartTime
    description: Timeline start (ISO format)
    type: timestamp
  - name: EndTime
    description: Timeline end (ISO format)
    type: timestamp
  - name: TargetUser
    description: Optional username to filter user-specific artifacts
    default: ""

sources:
  - name: UnifiedTimeline
    query: |
      LET EventLogEntries = SELECT
             System.TimeCreated.SystemTime AS Timestamp,
             "EventLog" AS Source,
             format(format="EventID %v: %v", args=[
               System.EventID.Value,
               if(condition=System.EventID.Value = 4624, then="Logon",
               if(condition=System.EventID.Value = 4625, then="Failed Logon",
               if(condition=System.EventID.Value = 4688, then="Process Created",
               if(condition=System.EventID.Value = 4672, then="Special Privileges",
               if(condition=System.EventID.Value = 7045, then="Service Installed",
               if(condition=System.EventID.Value = 1102, then="Log Cleared",
               str(str=System.EventID.Value)))))))
             ]) AS Description,
             EventData AS Detail
      FROM parse_evtx(
        filename="C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
      )
      WHERE System.EventID.Value IN (4624, 4625, 4634, 4648, 4672, 4688, 4697, 4698, 7045, 1102)
        AND System.TimeCreated.SystemTime >= StartTime
        AND System.TimeCreated.SystemTime <= EndTime

      LET PrefetchEntries = SELECT * FROM foreach(
        row={SELECT FullPath FROM glob(globs="C:\\Windows\\Prefetch\\*.pf")},
        query={
          SELECT LastRunTimes[0] AS Timestamp,
                 "Prefetch" AS Source,
                 format(format="Executed: %v (RunCount: %v)", args=[Executable, RunCount]) AS Description,
                 FullPath AS Detail
          FROM prefetch(filename=FullPath)
          WHERE LastRunTimes[0] >= StartTime
            AND LastRunTimes[0] <= EndTime
        }
      )

      LET AmcacheEntries = SELECT LastModified AS Timestamp,
             "Amcache" AS Source,
             format(format="Program: %v (Publisher: %v)", args=[FullPath, Publisher]) AS Description,
             SHA1 AS Detail
      FROM Artifact.Windows.Forensics.Amcache()
      WHERE LastModified >= StartTime
        AND LastModified <= EndTime

      LET SysmonEntries = SELECT
             System.TimeCreated.SystemTime AS Timestamp,
             "Sysmon" AS Source,
             format(format="EID %v: %v → %v", args=[
               System.EventID.Value,
               EventData.ParentImage,
               EventData.Image
             ]) AS Description,
             EventData.CommandLine AS Detail
      FROM parse_evtx(
        filename="C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx"
      )
      WHERE System.EventID.Value IN (1, 3, 7, 8, 11, 12, 13)
        AND System.TimeCreated.SystemTime >= StartTime
        AND System.TimeCreated.SystemTime <= EndTime

      SELECT * FROM chain(
        a=EventLogEntries,
        b=PrefetchEntries,
        c=AmcacheEntries,
        d=SysmonEntries
      )
      ORDER BY Timestamp
```

## Usage

```
velociraptor artifacts collect Custom.Windows.Investigation.TimelineBuilder \
  --args "StartTime=2025-05-20T00:00:00Z" \
  --args "EndTime=2025-05-22T00:00:00Z" \
  --output timeline.zip
```

## Learn More

- [Windows Forensics — Timeline Analysis](https://training.ridgelinecyber.com/courses/windows-forensics/) — super timeline construction and analysis
- [Incident Response — Timeline Methodology](https://training.ridgelinecyber.com/courses/practical-incident-response/) — building investigative timelines
