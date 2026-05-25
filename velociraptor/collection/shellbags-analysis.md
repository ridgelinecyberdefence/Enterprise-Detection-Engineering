# ShellBags Analysis

Parses Windows ShellBags to reconstruct folder access history, including folders on removable media, network shares, and deleted directories. ShellBags persist even after the folder is removed — if an attacker browsed to a staging directory or mounted a network share, the ShellBag entry survives cleanup.

## ATT&CK Coverage

- T1083 — File and Directory Discovery
- T1005 — Data from Local System
- T1039 — Data from Network Shared Drive

## Artifact

```yaml
name: Custom.Windows.Forensics.ShellBags
description: |
  Parse ShellBags from NTUSER.DAT and UsrClass.dat to reconstruct
  folder browsing history. Identifies accessed network shares,
  removable media paths, and deleted directories.

type: CLIENT

sources:
  - name: ShellBagEntries
    query: |
      SELECT * FROM Artifact.Windows.Forensics.Shellbags()

  - name: NetworkPaths
    description: ShellBag entries for network shares and UNC paths
    query: |
      SELECT * FROM Artifact.Windows.Forensics.Shellbags()
      WHERE FullPath =~ "^\\\\\\\\|^//"
      ORDER BY ModifiedTime DESC

  - name: RemovableMedia
    description: ShellBag entries for removable drives
    query: |
      SELECT * FROM Artifact.Windows.Forensics.Shellbags()
      WHERE FullPath =~ "(?i)^[D-Z]:\\\\"
         AND NOT FullPath =~ "(?i)^C:\\\\"
      ORDER BY ModifiedTime DESC

  - name: SuspiciousPaths
    description: Folders in temp, staging, or unusual locations
    query: |
      SELECT * FROM Artifact.Windows.Forensics.Shellbags()
      WHERE FullPath =~ "(?i)(Temp|tmp|staging|exfil|upload|dump|out|loot|Tools)"
      ORDER BY ModifiedTime DESC
```

## Learn More

- [Windows Forensics — ShellBag Analysis](https://training.ridgelinecyber.com/courses/windows-forensics/) — ShellBag forensics for folder access reconstruction
