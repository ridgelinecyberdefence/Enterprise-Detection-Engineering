# Process Injection Detection Hunt

Hunts across the fleet for signs of process injection by examining process memory characteristics: executable memory regions not backed by files on disk, suspicious thread start addresses, and hollowed processes where the in-memory image doesn't match the on-disk binary. Process injection is the technique attackers use to hide malicious code inside legitimate processes.

## ATT&CK Coverage

- T1055.001 - Process Injection: Dynamic-link Library Injection
- T1055.003 - Process Injection: Thread Execution Hijacking
- T1055.012 - Process Injection: Process Hollowing

## Artifact

```yaml
name: Custom.Windows.Hunting.ProcessInjection
description: |
  Hunt for process injection by examining process memory regions,
  thread start addresses, and image integrity. Flags processes with
  executable memory not backed by on-disk files.

type: CLIENT

parameters:
  - name: TargetProcessRegex
    description: Regex of processes to examine (leave empty for all)
    default: "(?i)(svchost|explorer|lsass|csrss|winlogon|services|spoolsv|searchindexer|taskhost|dllhost|msiexec|RuntimeBroker)"

sources:
  - name: SuspiciousMemoryRegions
    description: Executable memory regions not backed by files
    query: |
      SELECT * FROM foreach(
        row={
          SELECT Pid, Name, Exe, Username
          FROM pslist()
          WHERE Name =~ TargetProcessRegex
        },
        query={
          SELECT Pid, Name, Exe, Username,
                 Address, Size, Protection, Type,
                 MappedFilename,
                 if(condition=Protection =~ "x"
                    AND (NOT MappedFilename OR MappedFilename = ""),
                    then="SUSPICIOUS",
                    else="Normal") AS Verdict
          FROM vad(pid=Pid)
          WHERE Protection =~ "x"
            AND (NOT MappedFilename OR MappedFilename = "")
            AND Type = "Private"
            AND Size > 4096
        }
      )

  - name: UnusualParentChild
    description: Processes with suspicious parent-child relationships
    query: |
      LET SuspiciousRelationships = (
        ("svchost.exe", "cmd.exe"),
        ("svchost.exe", "powershell.exe"),
        ("services.exe", "cmd.exe"),
        ("lsass.exe", "cmd.exe"),
        ("explorer.exe", "mshta.exe"),
        ("winword.exe", "cmd.exe"),
        ("winword.exe", "powershell.exe"),
        ("excel.exe", "cmd.exe"),
        ("excel.exe", "powershell.exe"),
        ("outlook.exe", "cmd.exe"),
        ("outlook.exe", "powershell.exe")
      )

      SELECT Pid, Name AS ChildName, Exe AS ChildPath,
             CommandLine,
             Ppid, ParentName,
             Username, CreateTime
      FROM Artifact.Windows.System.Pslist()
      WHERE (ParentName =~ "(?i)svchost" AND Name =~ "(?i)(cmd|powershell)")
         OR (ParentName =~ "(?i)services\\.exe" AND Name =~ "(?i)cmd")
         OR (ParentName =~ "(?i)(winword|excel|outlook)" AND Name =~ "(?i)(cmd|powershell|mshta)")
         OR (ParentName =~ "(?i)lsass" AND NOT Name =~ "(?i)(svchost|lsaiso)")

  - name: LoadedDLLAnomalies
    description: DLLs loaded from unusual paths
    query: |
      SELECT * FROM foreach(
        row={
          SELECT Pid, Name FROM pslist()
          WHERE Name =~ TargetProcessRegex
        },
        query={
          SELECT Pid, Name, ModuleName, ExePath
          FROM modules(pid=Pid)
          WHERE ExePath =~ "(?i)(\\\\Temp\\\\|\\\\Downloads\\\\|\\\\AppData\\\\Local\\\\Temp|\\\\Users\\\\Public|\\\\PerfLogs)"
        }
      )
```

## Triage

Focus on:
- `SuspiciousMemoryRegions` with `Verdict = "SUSPICIOUS"`. Executable private memory with no backing file is a strong injection indicator
- `UnusualParentChild`. Svchost spawning cmd/PowerShell is almost always malicious or warrants investigation
- `LoadedDLLAnomalies`. Legitimate DLLs load from System32 or Program Files, not Temp or Downloads

## Learn More

- [Offensive Security for Defenders: Process Injection](https://ridgelinecyber.com/training/courses/offensive-security-for-defenders/). injection techniques and their telemetry
- [Memory Forensics: Memory Analysis](https://ridgelinecyber.com/training/courses/applied-memory-forensics/). volatile memory analysis for injection evidence
- [Detection Engineering: Process Behavior Rules](https://ridgelinecyber.com/training/courses/detection-engineering/). behavioral detection for injection
