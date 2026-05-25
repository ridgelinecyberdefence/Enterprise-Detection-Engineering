# Unauthorized Software Fleet Hunt

Hunts across all endpoints for installed software not on an approved whitelist. Checks both traditional installer registrations (Add/Remove Programs) and running processes against a configurable allow list. Surfaces shadow IT, attacker-installed tools, and policy violations at fleet scale.

## ATT&CK Coverage

- T1072 — Software Deployment Tools
- T1036 — Masquerading (rogue executables disguised as legitimate software)

## Artifact

```yaml
name: Custom.Windows.Hunting.UnauthorizedSoftware
description: |
  Fleet-wide hunt for software not on an approved whitelist.
  Checks installed programs (registry) and running processes.
  Returns only items NOT matching the allow list.

type: CLIENT

parameters:
  - name: AllowListRegex
    description: |
      Regex of approved software publishers/names. Anything NOT
      matching is flagged. Default covers Microsoft, common enterprise tools.
    default: "(?i)(Microsoft|Google|Mozilla|Adobe|Cisco|CrowdStrike|SentinelOne|Palo Alto|Fortinet|Splunk|Elastic|Zoom|Slack|1Password|LastPass|Okta)"

sources:
  - name: InstalledPrograms
    description: Installed software not matching the allow list
    query: |
      LET InstallPaths = (
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
        "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*"
      )

      SELECT
        parse_string_with_regex(string=FullPath, regex="Uninstall\\\\(?P<Key>[^\\\\]+)$").Key AS ProgramKey,
        DisplayName,
        DisplayVersion,
        Publisher,
        InstallDate,
        InstallLocation,
        EstimatedSize,
        FullPath AS RegistryPath
      FROM foreach(
        row={SELECT FullPath FROM glob(globs=InstallPaths, accessor="registry")},
        query={
          SELECT FullPath,
                 read_reg_key(globs=FullPath + "\\DisplayName", accessor="registry").Data.value AS DisplayName,
                 read_reg_key(globs=FullPath + "\\DisplayVersion", accessor="registry").Data.value AS DisplayVersion,
                 read_reg_key(globs=FullPath + "\\Publisher", accessor="registry").Data.value AS Publisher,
                 read_reg_key(globs=FullPath + "\\InstallDate", accessor="registry").Data.value AS InstallDate,
                 read_reg_key(globs=FullPath + "\\InstallLocation", accessor="registry").Data.value AS InstallLocation,
                 read_reg_key(globs=FullPath + "\\EstimatedSize", accessor="registry").Data.value AS EstimatedSize
          FROM scope()
        }
      )
      WHERE DisplayName
        AND NOT Publisher =~ AllowListRegex
        AND NOT DisplayName =~ AllowListRegex

  - name: RunningUnauthorized
    description: Running processes from publishers not on the allow list
    query: |
      SELECT Name,
             Exe,
             CommandLine,
             Pid,
             Username,
             hash(path=Exe) AS Hash,
             authenticode(filename=Exe) AS Signature
      FROM pslist()
      WHERE Exe
        AND NOT authenticode(filename=Exe).SubjectName =~ AllowListRegex
        AND NOT Name =~ "(?i)(svchost|csrss|lsass|services|smss|wininit|winlogon|dwm|conhost|System)"
```

## Usage

Customize the `AllowListRegex` to match your organization's approved software list. Run as a hunt across all endpoints. The results show every installed program and running process not from an approved publisher.

## Learn More

- [SOC Operations — Asset and Software Inventory](https://training.ridgelinecyber.com/courses/m365-security-operations/)
- [Velociraptor — Fleet Hunting](https://training.ridgelinecyber.com/short-courses/velociraptor/)
