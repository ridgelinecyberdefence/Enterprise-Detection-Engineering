# USB Device History Collection

Enumerates every USB storage device that has ever been connected to the endpoint by parsing USBSTOR registry keys, SetupAPI logs, and mount point associations. Produces a timeline of device connections with serial numbers, manufacturer information, and first/last connection timestamps. Essential for insider threat investigations and data exfiltration analysis.

## ATT&CK Coverage

- T1052.001 — Exfiltration Over Physical Medium: Exfiltration over USB
- T1200 — Hardware Additions
- T1091 — Replication Through Removable Media

## Artifact

```yaml
name: Custom.Windows.Forensics.USBHistory
description: |
  Reconstruct USB storage device connection history from registry
  (USBSTOR), SetupAPI logs, and mount points. Produces a device
  inventory with connection timestamps and serial numbers.

type: CLIENT

sources:
  - name: USBSTORDevices
    description: USB storage devices from USBSTOR registry key
    query: |
      LET USBEntries = SELECT FullPath, Name, Mtime
      FROM glob(
        globs="HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\*\\*",
        accessor="registry"
      )

      SELECT Name AS SerialNumber,
             FullPath AS RegistryPath,
             parse_string_with_regex(
               string=FullPath,
               regex="USBSTOR\\\\(?P<Type>[^\\\\]+)\\\\").Type AS DeviceType,
             Mtime AS LastConnected,
             "USBSTOR" AS Source
      FROM USBEntries

  - name: MountedDevices
    description: Drive letter and volume GUID associations
    query: |
      SELECT Name AS MountPoint,
             Data.value AS DeviceData,
             Mtime AS Timestamp
      FROM glob(
        globs="HKEY_LOCAL_MACHINE\\SYSTEM\\MountedDevices\\*",
        accessor="registry"
      )
      WHERE Name =~ "DosDevices" OR Name =~ "Volume"

  - name: USBSetupLog
    description: USB device install timestamps from SetupAPI logs
    query: |
      LET SetupLogs = (
        "C:\\Windows\\INF\\setupapi.dev.log",
        "C:\\Windows\\setupapi.log"
      )

      SELECT * FROM foreach(
        row={SELECT FullPath FROM glob(globs=SetupLogs)},
        query={
          SELECT Line,
                 FullPath AS LogFile
          FROM parse_lines(filename=FullPath)
          WHERE Line =~ "(?i)USBSTOR|Device Install"
        }
      )
```

## Learn More

- [Windows Forensics — Removable Media Analysis](https://training.ridgelinecyber.com/courses/windows-forensics/) — USB forensics and data exfiltration timelines
- [Incident Response — Insider Threat Investigation](https://training.ridgelinecyber.com/courses/practical-incident-response/) — USB device analysis in insider cases
