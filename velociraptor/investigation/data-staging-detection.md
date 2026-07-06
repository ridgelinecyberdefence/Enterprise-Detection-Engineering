# Data Staging Detection

Identifies evidence of data staging for exfiltration by scanning for archive files in unusual locations, recently created large files, and directory structures that match staging patterns. Attackers typically collect target data into a staging directory, compress it, then exfiltrate. This artifact catches the staging phase.

## ATT&CK Coverage

- T1074.001 - Data Staged: Local Data Staging
- T1560.001 - Archive Collected Data: Archive via Utility
- T1005 - Data from Local System

## Artifact

```yaml
name: Custom.Windows.Investigation.DataStagingDetection
description: |
  Detect data staging for exfiltration by scanning for archive files
  in unusual locations, large file concentrations, and suspicious
  compression tool usage.

type: CLIENT

parameters:
  - name: MinArchiveSizeMB
    description: Minimum archive file size to flag (MB)
    type: int
    default: 50
  - name: LookbackDays
    description: How far back to search
    type: int
    default: 30

sources:
  - name: ArchivesInUnusualLocations
    description: Archive files in temp, user, and staging directories
    query: |
      LET SearchPaths = (
        "C:\\Users\\*\\Desktop\\*.{zip,rar,7z,tar,gz,cab}",
        "C:\\Users\\*\\Documents\\*.{zip,rar,7z,tar,gz,cab}",
        "C:\\Users\\*\\AppData\\Local\\Temp\\*.{zip,rar,7z,tar,gz,cab}",
        "C:\\Temp\\*.{zip,rar,7z,tar,gz,cab}",
        "C:\\Windows\\Temp\\*.{zip,rar,7z,tar,gz,cab}",
        "C:\\PerfLogs\\*.{zip,rar,7z,tar,gz,cab}",
        "C:\\Users\\Public\\*.{zip,rar,7z,tar,gz,cab}"
      )

      LET Cutoff = now() - (LookbackDays * 86400)
      LET MinSize = MinArchiveSizeMB * 1048576

      SELECT FullPath, Name, Size,
             format(format="%.1f MB", args=Size / 1048576.0) AS SizeMB,
             Mtime AS Modified,
             Ctime AS Created,
             hash(path=FullPath) AS Hash,
             "Archive in Unusual Location" AS Finding
      FROM glob(globs=SearchPaths)
      WHERE NOT IsDir
        AND Size > MinSize
        AND Ctime > Cutoff
      ORDER BY Size DESC

  - name: LargeRecentFiles
    description: Any large files created recently in user directories
    query: |
      LET Cutoff = now() - (LookbackDays * 86400)

      SELECT FullPath, Name, Size,
             format(format="%.1f MB", args=Size / 1048576.0) AS SizeMB,
             Ctime AS Created,
             "Large Recent File" AS Finding
      FROM glob(globs="C:\\Users\\**")
      WHERE NOT IsDir
        AND Size > 104857600
        AND Ctime > Cutoff
      ORDER BY Size DESC
      LIMIT 50

  - name: CompressionToolUsage
    description: Evidence of compression tool execution
    query: |
      LET ToolPatterns = "(?i)(7z|winrar|rar|tar|makecab|compact|compress)"

      LET PrefetchHits = SELECT Name, Mtime AS LastRun,
             "Prefetch" AS Source
      FROM glob(globs="C:\\Windows\\Prefetch\\*.pf")
      WHERE Name =~ ToolPatterns

      LET ProcessHits = SELECT Pid, Name, Exe, CommandLine,
             "Running" AS Source
      FROM pslist()
      WHERE Name =~ ToolPatterns
         OR CommandLine =~ ToolPatterns

      SELECT * FROM chain(a=PrefetchHits, b=ProcessHits)

  - name: StagingDirectories
    description: Directories with suspiciously concentrated recent file creation
    query: |
      LET Cutoff = now() - (LookbackDays * 86400)

      SELECT dirname(path=FullPath) AS Directory,
             count() AS FileCount,
             format(format="%.1f MB", args=sum(item=Size) / 1048576.0) AS TotalSize,
             min(item=Ctime) AS EarliestCreated,
             max(item=Ctime) AS LatestCreated
      FROM glob(globs="C:\\Users\\**")
      WHERE NOT IsDir
        AND Ctime > Cutoff
        AND NOT FullPath =~ "(?i)(AppData\\\\Local\\\\Microsoft|Cache|Logs)"
      GROUP BY Directory
      HAVING FileCount > 20
      ORDER BY FileCount DESC
      LIMIT 20
```

## Staging Indicators

Data staging leaves a predictable pattern:
- Many files created in a short window in a single directory
- Archive files in locations where users don't normally create them
- Compression tools executed around the same time
- Large files (hundreds of MB to GB) appearing in temp or user directories

## Learn More

- [Threat Hunting: Data Exfiltration](https://ridgelinecyber.com/training/courses/threat-hunting-m365/). hunting for data staging and exfiltration
- [Incident Response: Exfiltration Assessment](https://ridgelinecyber.com/training/courses/practical-ir/). scoping data loss
