# Targeted Event Log Export

Collects and filters Windows Event Logs for security-relevant events within a specified time window. Rather than pulling entire log files (which can be gigabytes), this artifact queries specific Event IDs associated with attacker activity: authentication events, process creation, service installation, PowerShell execution, and security log manipulation.

## ATT&CK Coverage

Collects evidence across all tactics by targeting security-relevant Event IDs.

## Artifact

```yaml
name: Custom.Windows.Collection.EventLogExport
description: |
  Targeted event log collection filtering for security-relevant Event
  IDs across Security, Sysmon, PowerShell, and System logs. Time-bounded
  to reduce volume while capturing forensically relevant events.

type: CLIENT

parameters:
  - name: StartTime
    description: Collect events after this time (ISO format)
    type: timestamp
  - name: EndTime
    description: Collect events before this time (ISO format)
    type: timestamp

sources:
  - name: SecurityEvents
    description: Authentication, privilege use, and audit events
    query: |
      LET SecurityEventIDs = (
        4624, 4625, 4634, 4648, 4672,
        4720, 4722, 4723, 4724, 4728, 4732, 4756,
        4688, 4689,
        4697, 4698, 4699, 4702,
        1102,
        4657,
        5140, 5145
      )

      SELECT System.TimeCreated.SystemTime AS Timestamp,
             System.EventID.Value AS EventID,
             System.Computer AS Computer,
             EventData AS Data,
             Message
      FROM parse_evtx(
        filename="C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
      )
      WHERE System.EventID.Value IN SecurityEventIDs
        AND (NOT StartTime OR System.TimeCreated.SystemTime >= StartTime)
        AND (NOT EndTime OR System.TimeCreated.SystemTime <= EndTime)

  - name: SysmonEvents
    description: Process creation, network, file, and registry events
    query: |
      SELECT System.TimeCreated.SystemTime AS Timestamp,
             System.EventID.Value AS EventID,
             System.Computer AS Computer,
             EventData AS Data,
             Message
      FROM parse_evtx(
        filename="C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx"
      )
      WHERE (NOT StartTime OR System.TimeCreated.SystemTime >= StartTime)
        AND (NOT EndTime OR System.TimeCreated.SystemTime <= EndTime)

  - name: PowerShellEvents
    description: PowerShell script block logging and module logging
    query: |
      LET PSLogs = (
        "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx",
        "C:\\Windows\\System32\\winevt\\Logs\\Windows PowerShell.evtx"
      )

      SELECT * FROM foreach(
        row={SELECT FullPath FROM glob(globs=PSLogs)},
        query={
          SELECT System.TimeCreated.SystemTime AS Timestamp,
                 System.EventID.Value AS EventID,
                 EventData AS Data,
                 FullPath AS LogFile
          FROM parse_evtx(filename=FullPath)
          WHERE System.EventID.Value IN (4103, 4104, 400, 403, 600)
            AND (NOT StartTime OR System.TimeCreated.SystemTime >= StartTime)
            AND (NOT EndTime OR System.TimeCreated.SystemTime <= EndTime)
        }
      )

  - name: SystemServiceEvents
    description: Service installation and system events
    query: |
      SELECT System.TimeCreated.SystemTime AS Timestamp,
             System.EventID.Value AS EventID,
             System.Computer AS Computer,
             EventData AS Data,
             Message
      FROM parse_evtx(
        filename="C:\\Windows\\System32\\winevt\\Logs\\System.evtx"
      )
      WHERE System.EventID.Value IN (7034, 7035, 7036, 7040, 7045)
        AND (NOT StartTime OR System.TimeCreated.SystemTime >= StartTime)
        AND (NOT EndTime OR System.TimeCreated.SystemTime <= EndTime)
```

## Learn More

- [Windows Forensics: Event Log Analysis](https://ridgelinecyber.com/training/courses/windows-endpoint-investigation/). Event ID reference and log analysis methodology
- [Incident Response: Evidence Collection](https://ridgelinecyber.com/training/courses/practical-ir/). targeted log collection procedures
- [Velociraptor: EVTX Parsing](https://ridgelinecyber.com/training/courses/velociraptor-endpoint-investigation/). VQL event log queries
