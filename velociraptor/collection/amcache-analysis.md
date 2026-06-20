# Amcache Program Execution Analysis

Parses the Amcache.hve registry hive to extract program execution evidence, including SHA1 hashes of executed binaries, installation paths, publisher information, and execution timestamps. Amcache persists even after the binary is deleted — making it critical for detecting tools the attacker ran and then cleaned up.

## ATT&CK Coverage

- T1059 — Command and Script Interpreter
- T1036 — Masquerading (unsigned binaries, unusual paths)
- T1070.004 — Indicator Removal: File Deletion (binary deleted but Amcache entry persists)

## Artifact

```yaml
name: Custom.Windows.Forensics.AmcacheAnalysis
description: |
  Parse Amcache.hve for program execution history. Extracts SHA1 hashes,
  file paths, publisher info, and timestamps. Flags unsigned binaries
  and executables from suspicious directories.

type: CLIENT

parameters:
  - name: SuspiciousDirectories
    description: Regex for directories that shouldn't contain executables
    default: "(?i)(\\\\Temp\\\\|\\\\Downloads\\\\|\\\\AppData\\\\Local\\\\Temp|\\\\Users\\\\Public|\\\\PerfLogs|\\\\Recycle)"

sources:
  - name: AmcacheEntries
    query: |
      SELECT * FROM Artifact.Windows.Forensics.Amcache()

  - name: SuspiciousEntries
    description: Entries from unusual directories or without publisher info
    query: |
      SELECT * FROM Artifact.Windows.Forensics.Amcache()
      WHERE FullPath =~ SuspiciousDirectories
         OR Publisher = ""
         OR Publisher = NULL
      ORDER BY LastModified DESC

  - name: HashLookup
    description: Unique SHA1 hashes for threat intelligence lookups
    query: |
      SELECT SHA1,
             FullPath,
             Publisher,
             LastModified,
             count() AS Occurrences
      FROM Artifact.Windows.Forensics.Amcache()
      WHERE SHA1 != "" AND SHA1 != NULL
      GROUP BY SHA1
      ORDER BY LastModified DESC
```

## Triage Value

Amcache is particularly valuable when:
- The attacker deleted their tools after use — the Amcache entry and SHA1 hash persist
- You need file hashes for threat intelligence lookups but the binary is gone
- You're building a timeline of which programs were installed/executed and when
- Comparing execution history across multiple endpoints to identify attacker tool deployment

## Learn More

- [Windows Forensics — Amcache and ShimCache](https://ridgelinecyber.com/training/courses/windows-endpoint-investigation/) — program execution artifact analysis
- [Incident Response — Evidence Collection](https://ridgelinecyber.com/training/courses/practical-ir/) — Amcache in the forensic evidence hierarchy
