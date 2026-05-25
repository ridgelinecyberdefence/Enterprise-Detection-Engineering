# Persistence Mechanism Stacking Hunt

Hunts across the fleet for endpoints with unusual persistence mechanism density. Rather than alerting on individual persistence items (which produces noise), this artifact counts persistence mechanisms per endpoint and flags statistical outliers. If most endpoints have 15-25 persistence entries and one has 47, that endpoint needs investigation.

## ATT&CK Coverage

- T1547 — Boot or Logon Autostart Execution
- T1053 — Scheduled Task/Job
- T1543 — Create or Modify System Process

## Artifact

```yaml
name: Custom.Windows.Hunting.PersistenceStacking
description: |
  Count persistence mechanisms per endpoint and flag outliers.
  Uses stacking analysis — endpoints with significantly more
  persistence entries than the fleet average warrant investigation.

type: CLIENT

sources:
  - name: PersistenceCount
    description: Count of each persistence type on this endpoint
    query: |
      LET RunKeys = SELECT count() AS C FROM glob(
        globs=(
          "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
          "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*",
          "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
          "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*"
        ), accessor="registry"
      )

      LET Tasks = SELECT count() AS C FROM Artifact.Windows.System.TaskScheduler()

      LET Services = SELECT count() AS C FROM Artifact.Windows.System.Services()
        WHERE StartMode = "Auto"

      LET WMI = SELECT count() AS C
        FROM Artifact.Windows.Persistence.PermanentWMIEvents()

      LET Startup = SELECT count() AS C FROM glob(
        globs=(
          "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\*",
          "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*"
        )
      ) WHERE NOT IsDir

      SELECT RunKeys[0].C AS RunKeyCount,
             Tasks[0].C AS ScheduledTaskCount,
             Services[0].C AS AutoStartServiceCount,
             WMI[0].C AS WMISubscriptionCount,
             Startup[0].C AS StartupFolderCount,
             RunKeys[0].C + Tasks[0].C + Services[0].C +
               WMI[0].C + Startup[0].C AS TotalPersistence
      FROM scope()

  - name: NewPersistence
    description: Persistence items created in the last 7 days
    query: |
      LET Cutoff = now() - 604800

      LET RecentRunKeys = SELECT Name, FullPath, Mtime,
             "Run Key" AS Type
      FROM glob(
        globs="HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
        accessor="registry"
      ) WHERE Mtime > Cutoff

      LET RecentStartup = SELECT Name, FullPath, Mtime,
             "Startup Folder" AS Type
      FROM glob(
        globs="C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\*"
      ) WHERE Mtime > Cutoff AND NOT IsDir

      SELECT * FROM chain(
        a=RecentRunKeys,
        b=RecentStartup
      )
```

## Stacking Analysis

After running this hunt across the fleet, export the results and stack:

1. Sort all endpoints by `TotalPersistence` descending
2. Calculate the fleet median and standard deviation
3. Investigate any endpoint more than 2 standard deviations above the median
4. Pay special attention to `WMISubscriptionCount` > 0 — most clean endpoints have zero WMI subscriptions

## Learn More

- [Threat Hunting in Microsoft 365 — Stacking Analysis](https://training.ridgelinecyber.com/courses/threat-hunting/) — statistical hunting methodology
- [Purple Team Operations — Persistence Validation](https://training.ridgelinecyber.com/courses/purple-team-operations/)
