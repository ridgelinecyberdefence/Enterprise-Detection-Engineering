# Credential Tool Detection Hunt

Hunts for the presence of credential harvesting tools across the fleet by checking Prefetch, file system, Amcache, and registry for known offensive tool signatures. Covers Mimikatz, LaZagne, Rubeus, SharpHound, CrackMapExec, Impacket tools, and other common credential theft utilities.

## ATT&CK Coverage

- T1003.001 - OS Credential Dumping: LSASS Memory
- T1003.002 - OS Credential Dumping: Security Account Manager
- T1003.003 - OS Credential Dumping: NTDS
- T1555 - Credentials from Password Stores
- T1558 - Steal or Forge Kerberos Tickets

## Artifact

```yaml
name: Custom.Windows.Hunting.CredentialTools
description: |
  Hunt for credential harvesting tools by checking file system,
  Prefetch, Amcache, and process memory for known tool signatures.

type: CLIENT

parameters:
  - name: ToolPatterns
    description: Regex matching known credential tool filenames
    default: "(?i)(mimikatz|mimi(katz|drv|lib)|sekurlsa|lazagne|rubeus|sharphound|bloodhound|crackmapexec|impacket|kekeo|safetykatz|pypykatz|procdump.*lsass|comsvcs.*minidump|nanodump|handlekatz|lsassy|dploot|certipy|coercer|petitpotam|printerbug|spoolsample|seatbelt|sharpup|winpeas|linpeas|powerup|invoke-mimikatz|invoke-kerberoast)"

sources:
  - name: FileSystemScan
    description: Credential tools on disk
    query: |
      LET SearchPaths = (
        "C:\\Users\\**",
        "C:\\Temp\\**",
        "C:\\Windows\\Temp\\**",
        "C:\\ProgramData\\**"
      )

      SELECT FullPath, Name, Size,
             Mtime AS Modified,
             hash(path=FullPath) AS Hash,
             authenticode(filename=FullPath) AS Signature,
             "File System" AS Source
      FROM glob(globs=SearchPaths)
      WHERE Name =~ ToolPatterns
        AND NOT IsDir

  - name: PrefetchEvidence
    description: Prefetch entries for credential tools (evidence of execution)
    query: |
      SELECT FullPath, Name, Mtime AS LastModified,
             "Prefetch (EXECUTED)" AS Source
      FROM glob(globs="C:\\Windows\\Prefetch\\*.pf")
      WHERE Name =~ ToolPatterns

  - name: AmcacheEvidence
    description: Amcache entries for credential tools (persists after deletion)
    query: |
      SELECT SHA1, FullPath, Publisher, LastModified,
             "Amcache (EXECUTED)" AS Source
      FROM Artifact.Windows.Forensics.Amcache()
      WHERE FullPath =~ ToolPatterns

  - name: ProcessMemoryScan
    description: Running processes with credential tool indicators
    query: |
      SELECT Pid, Name, Exe, CommandLine, Username,
             "Running Process" AS Source
      FROM pslist()
      WHERE Name =~ ToolPatterns
         OR CommandLine =~ ToolPatterns
         OR CommandLine =~ "(?i)(sekurlsa::logonpasswords|lsadump::dcsync|kerberos::golden|privilege::debug.*sekurlsa|comsvcs\\.dll.*MiniDump)"

  - name: LSASSDumpIndicators
    description: LSASS dump file artifacts
    query: |
      LET DumpPaths = (
        "C:\\Windows\\Temp\\*.dmp",
        "C:\\Temp\\*.dmp",
        "C:\\Users\\*\\*.dmp",
        "C:\\Users\\*\\AppData\\Local\\Temp\\*.dmp"
      )

      SELECT FullPath, Name, Size,
             Mtime AS Modified,
             "LSASS Dump File" AS Source
      FROM glob(globs=DumpPaths)
      WHERE Size > 10485760
```

## Severity

Any positive finding from this hunt is high severity. Credential tools have no legitimate use on production endpoints. Prefetch and Amcache matches are particularly significant because they prove the tool was executed, even if it's been deleted.

## Learn More

- [Offensive Security for Defenders: Credential Access](https://ridgelinecyber.com/training/courses/offensive-security-for-defenders/). understanding credential theft techniques
- [Incident Response: Credential Compromise](https://ridgelinecyber.com/training/courses/practical-ir/). scoping credential exposure
- [Memory Forensics: LSASS Analysis](https://ridgelinecyber.com/training/courses/applied-memory-forensics/). analyzing memory dumps for credentials
