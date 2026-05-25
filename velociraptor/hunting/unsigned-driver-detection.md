# Unsigned Driver Fleet Hunt

Hunts for unsigned or suspiciously signed kernel drivers across the fleet. Vulnerable and malicious drivers are a growing attack vector — "Bring Your Own Vulnerable Driver" (BYOVD) attacks use legitimate but vulnerable signed drivers to disable security tools or gain kernel access.

## ATT&CK Coverage

- T1014 — Rootkit
- T1068 — Exploitation for Privilege Escalation
- T1562.001 — Impair Defenses: Disable or Modify Tools (via BYOVD)

## Artifact

```yaml
name: Custom.Windows.Hunting.UnsignedDrivers
description: |
  Fleet hunt for unsigned, expired, or suspiciously signed kernel
  drivers. Cross-references loaded drivers against known BYOVD
  driver hashes.

type: CLIENT

parameters:
  - name: KnownVulnerableHashes
    description: |
      Comma-separated SHA256 hashes of known vulnerable drivers.
      Populate from loldrivers.io or your threat intel.
    default: ""

sources:
  - name: LoadedDrivers
    description: Currently loaded kernel drivers with signature status
    query: |
      SELECT * FROM foreach(
        row={
          SELECT ModuleName, ExePath
          FROM modules(pid=4)
          WHERE ExePath
        },
        query={
          SELECT ModuleName, ExePath,
                 hash(path=ExePath) AS Hash,
                 authenticode(filename=ExePath) AS Signature,
                 stat(filename=ExePath) AS FileInfo
          FROM scope()
        }
      )

  - name: UnsignedDrivers
    description: Loaded drivers without valid signatures
    query: |
      SELECT ModuleName, ExePath,
             Hash.SHA256 AS SHA256,
             Signature.Trusted AS Trusted,
             Signature.SubjectName AS Signer,
             Signature.IssuerName AS Issuer,
             FileInfo.Mtime AS FileModified,
             "Unsigned/Invalid" AS Flag
      FROM source(source="LoadedDrivers")
      WHERE NOT Signature.Trusted
         OR Signature.Trusted = NULL

  - name: DriversFromUnusualPaths
    description: Drivers loaded from non-standard locations
    query: |
      SELECT ModuleName, ExePath,
             Hash.SHA256 AS SHA256,
             Signature.SubjectName AS Signer,
             "Unusual Path" AS Flag
      FROM source(source="LoadedDrivers")
      WHERE NOT ExePath =~ "(?i)(\\\\Windows\\\\System32\\\\drivers|\\\\Windows\\\\System32\\\\DriverStore|\\\\Program Files)"

  - name: RecentlyInstalledDrivers
    description: Driver files modified in the last 7 days
    query: |
      SELECT ModuleName, ExePath,
             Hash.SHA256 AS SHA256,
             Signature.SubjectName AS Signer,
             FileInfo.Mtime AS FileModified,
             "Recently Modified" AS Flag
      FROM source(source="LoadedDrivers")
      WHERE FileInfo.Mtime > now() - 604800

  - name: RegistryDriverServices
    description: All registered driver services (including not currently loaded)
    query: |
      SELECT Name,
             Data.value AS ImagePath,
             Mtime AS RegistryModified
      FROM glob(
        globs="HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\*\\ImagePath",
        accessor="registry"
      )
      WHERE Data.value =~ "(?i)\\.sys"
```

## Hunting with LOLDrivers

For maximum coverage, download the known-vulnerable driver hash list from [loldrivers.io](https://www.loldrivers.io/) and populate the `KnownVulnerableHashes` parameter. Any match is a BYOVD candidate requiring immediate investigation.

## Learn More

- [Offensive Security for Defenders — BYOVD Attacks](https://training.ridgelinecyber.com/courses/offensive-security-defenders/) — understanding vulnerable driver exploitation
- [Purple Team Operations — Defense Evasion](https://training.ridgelinecyber.com/courses/purple-team-operations/) — driver-based defense evasion techniques
