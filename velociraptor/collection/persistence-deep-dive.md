# Persistence Mechanism Deep Dive Collection

A comprehensive Velociraptor artifact that collects every common Windows persistence mechanism from a single endpoint: registry Run keys, Scheduled Tasks, Services, WMI subscriptions, Startup folder items, DLL search order hijack opportunities, COM hijacks, and AppInit DLLs. Returns a unified view with metadata for each persistence item including creation timestamps, file hashes, and digital signature status.

## ATT&CK Coverage

- T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- T1053.005 - Scheduled Task/Job: Scheduled Task
- T1543.003 - Create or Modify System Process: Windows Service
- T1546.003 - Event Triggered Execution: WMI Event Subscription
- T1546.015 - Event Triggered Execution: COM Object Hijacking
- T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking

## Artifact

```yaml
name: Custom.Windows.Persistence.DeepDive
description: |
  Comprehensive persistence mechanism collection. Enumerates Run keys,
  Scheduled Tasks, Services, WMI subscriptions, Startup folder, COM
  hijacks, and AppInit DLLs. Each item includes file hash, signature
  status, and creation timestamp for triage.

type: CLIENT

parameters:
  - name: IncludeSignatureVerification
    description: Verify Authenticode signatures (slower but more thorough)
    type: bool
    default: "Y"

sources:
  - name: RegistryRunKeys
    query: |
      LET RunKeyPaths = (
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*",
        "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
        "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\*"
      )

      SELECT Name,
             FullPath AS RegistryPath,
             Data.value AS Command,
             Mtime AS LastModified,
             "Registry Run Key" AS PersistenceType
      FROM glob(globs=RunKeyPaths, accessor="registry")

  - name: ScheduledTasks
    query: |
      SELECT Name,
             ActionPath AS Command,
             ActionArguments AS Arguments,
             Principal AS RunAs,
             TriggerString AS Trigger,
             Enabled,
             LastRunTime,
             NextRunTime,
             "Scheduled Task" AS PersistenceType
      FROM Artifact.Windows.System.TaskScheduler()

  - name: Services
    query: |
      SELECT Name,
             DisplayName,
             PathName AS Command,
             StartMode,
             State,
             ServiceType,
             StartName AS RunAs,
             "Windows Service" AS PersistenceType
      FROM Artifact.Windows.System.Services()
      WHERE StartMode = "Auto" OR State = "Running"

  - name: WMISubscriptions
    query: |
      SELECT * FROM Artifact.Windows.Persistence.PermanentWMIEvents()

  - name: StartupFolder
    query: |
      LET StartupPaths = (
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\*",
        "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*"
      )

      SELECT FullPath,
             Name,
             Size,
             Mtime AS LastModified,
             hash(path=FullPath) AS Hash,
             "Startup Folder" AS PersistenceType
      FROM glob(globs=StartupPaths)
      WHERE NOT IsDir

  - name: AppInitDLLs
    query: |
      LET AppInitPaths = (
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs"
      )

      SELECT FullPath AS RegistryPath,
             Data.value AS DLLPath,
             "AppInit DLL" AS PersistenceType
      FROM glob(globs=AppInitPaths, accessor="registry")
      WHERE Data.value != ""

  - name: ImageFileExecutionOptions
    query: |
      SELECT Name,
             FullPath AS RegistryPath,
             Data.value AS Debugger,
             "IFEO Debugger" AS PersistenceType
      FROM glob(
        globs="HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*\\Debugger",
        accessor="registry"
      )
      WHERE Data.value != ""
```

## Deployment

```
velociraptor artifacts collect Custom.Windows.Persistence.DeepDive --output persistence.zip
```

Or via the Velociraptor GUI: New Collection → Custom.Windows.Persistence.DeepDive.

## Triage Workflow

1. Run the artifact across suspect endpoints
2. Focus on items with recent `LastModified` timestamps (within the compromise window)
3. Cross-reference unsigned binaries and unfamiliar hashes with threat intelligence
4. Check WMI subscriptions. Attackers love these because they survive reboots and aren't visible in Task Manager
5. Flag services running from temp directories or user-writable paths

## Learn More

- [Windows Forensics: Persistence Analysis](https://ridgelinecyber.com/training/courses/windows-endpoint-investigation/). registry persistence, service analysis, and WMI forensics
- [Purple Team Operations: Persistence Techniques](https://ridgelinecyber.com/training/courses/purple-teaming-for-blue-teams/). attacker persistence methods and detection validation
- [Velociraptor: Artifact Development](https://ridgelinecyber.com/training/courses/velociraptor-endpoint-investigation/). custom artifact creation and deployment
