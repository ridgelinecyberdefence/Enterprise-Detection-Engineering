# Prefetch File Analysis

Parses Windows Prefetch files to reconstruct program execution history. Prefetch records show which executables ran, when they last ran, how many times they've run, and which files they loaded — making it one of the most valuable evidence sources for determining what an attacker executed on an endpoint.

## ATT&CK Coverage

- T1059 — Command and Script Interpreter (execution evidence)
- T1204 — User Execution (initial access confirmation)
- T1036 — Masquerading (executable from unusual locations)

## Artifact

```yaml
name: Custom.Windows.Forensics.PrefetchAnalysis
description: |
  Parse Prefetch files from C:\Windows\Prefetch. Extracts execution
  timestamps, run count, loaded files list, and flags suspicious
  executables based on name and path patterns.

type: CLIENT

parameters:
  - name: SuspiciousPatterns
    description: Regex for suspicious executable names
    default: "(?i)(mimikatz|psexec|wce|procdump|lazagne|rubeus|sharphound|bloodhound|covenant|cobalt|beacon|meterpreter|nc\\.exe|ncat|certutil.*decode|bitsadmin.*transfer|wmic.*process.*call|mshta|regsvr32|rundll32.*javascript|cscript.*eval|powershell.*encoded)"

sources:
  - name: PrefetchFiles
    query: |
      LET PrefetchGlob = "C:\\Windows\\Prefetch\\*.pf"

      LET ParsedPrefetch = SELECT * FROM foreach(
        row={SELECT FullPath, Name, Mtime FROM glob(globs=PrefetchGlob)},
        query={
          SELECT Executable,
                 FileSize,
                 RunCount,
                 LastRunTimes,
                 FilesAccessed,
                 FullPath AS PrefetchPath,
                 Mtime AS PrefetchModified
          FROM prefetch(filename=FullPath)
        }
      )

      SELECT Executable,
             RunCount,
             LastRunTimes[0] AS LastRun,
             LastRunTimes[1] AS SecondLastRun,
             LastRunTimes[2] AS ThirdLastRun,
             FileSize,
             len(list=FilesAccessed) AS FilesLoadedCount,
             PrefetchPath,
             PrefetchModified,
             if(condition=Executable =~ SuspiciousPatterns,
                then="SUSPICIOUS",
                else="Normal") AS Verdict
      FROM ParsedPrefetch
      ORDER BY LastRun DESC

  - name: SuspiciousOnly
    description: Only Prefetch entries matching suspicious patterns
    query: |
      SELECT * FROM source(source="PrefetchFiles")
      WHERE Verdict = "SUSPICIOUS"

  - name: RecentExecution
    description: Executables run in the last 48 hours
    query: |
      SELECT * FROM source(source="PrefetchFiles")
      WHERE LastRun > now() - 172800
      ORDER BY LastRun DESC
```

## Key Indicators

| What to Look For | Why It Matters |
|-----------------|----------------|
| psexec, wmic, mstsc in Prefetch | Lateral movement tools were executed |
| powershell, cmd, cscript, wscript | Script interpreter execution (check if expected) |
| certutil, bitsadmin | Possible download/decode activity |
| Executable from `\Temp\`, `\Downloads\`, `\AppData\` | Running from user-writable directories |
| RunCount = 1 with recent LastRun | First-time execution — potentially attacker-dropped binary |
| mimikatz, rubeus, sharphound | Offensive tools (immediate escalation) |

## Learn More

- [Windows Forensics — Execution Artifacts](https://ridgelinecyber.com/training/courses/windows-endpoint-investigation/) — Prefetch, Amcache, ShimCache analysis
- [Incident Response — Timeline Construction](https://ridgelinecyber.com/training/courses/practical-ir/) — building execution timelines from Prefetch data
