# User Activity Reconstruction

Reconstructs a specific user's activity on an endpoint by collecting their Recent Files, Jump Lists, UserAssist, browser history, PowerShell history, typed paths, and last accessed documents. Produces a comprehensive picture of what the user (or an attacker using their account) did on the machine.

## ATT&CK Coverage

Supports investigation of compromised accounts by reconstructing user-level activity.

## Artifact

```yaml
name: Custom.Windows.Investigation.UserActivityReconstruction
description: |
  Reconstruct a user's endpoint activity from Recent Files, Jump Lists,
  UserAssist, browser history, PowerShell console history, and typed
  paths. Scopes investigation to a specific user account.

type: CLIENT

parameters:
  - name: Username
    description: Target username (e.g., jsmith — no domain prefix)
    type: string
  - name: StartTime
    description: Optional time boundary for filtering
    type: timestamp

sources:
  - name: RecentFiles
    description: Recently accessed files (LNK files in Recent folder)
    query: |
      SELECT * FROM foreach(
        row={
          SELECT FullPath FROM glob(
            globs=format(format="C:\\Users\\%v\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*.lnk", args=[Username])
          )
        },
        query={
          SELECT FullPath, Name,
                 Mtime AS LastAccessed,
                 parse_lnk(filename=FullPath) AS LnkData,
                 "Recent Files" AS Source
          FROM scope()
        }
      )
      ORDER BY LastAccessed DESC

  - name: UserAssist
    description: GUI program execution history with run count
    query: |
      SELECT * FROM Artifact.Windows.Forensics.UserAssist()
      WHERE User =~ Username

  - name: PowerShellHistory
    description: PowerShell command history file
    query: |
      LET HistoryPath = format(
        format="C:\\Users\\%v\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
        args=[Username]
      )

      SELECT Line, count() AS LineNumber,
             "PowerShell History" AS Source
      FROM parse_lines(filename=HistoryPath)

  - name: BrowserHistory
    description: Chrome and Edge browsing history
    query: |
      LET ChromeHistory = format(
        format="C:\\Users\\%v\\AppData\\Local\\Google\\Chrome\\User Data\\*\\History",
        args=[Username]
      )
      LET EdgeHistory = format(
        format="C:\\Users\\%v\\AppData\\Local\\Microsoft\\Edge\\User Data\\*\\History",
        args=[Username]
      )

      SELECT * FROM foreach(
        row={SELECT FullPath FROM glob(globs=(ChromeHistory, EdgeHistory))},
        query={
          SELECT url AS URL,
                 title AS Title,
                 visit_count AS Visits,
                 timestamp(winfiletime=last_visit_time * 10) AS LastVisit,
                 "Browser History" AS Source
          FROM sqlite(file=FullPath,
            query="SELECT * FROM urls ORDER BY last_visit_time DESC LIMIT 500")
        }
      )

  - name: TypedPaths
    description: Explorer address bar typed paths
    query: |
      SELECT Name AS TypedPath,
             Data.value AS Path,
             Mtime AS Timestamp,
             "Typed Path" AS Source
      FROM glob(
        globs=format(
          format="HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths\\*",
          args=[]
        ),
        accessor="registry"
      )

  - name: DownloadedFiles
    description: Files in the user's Downloads folder
    query: |
      SELECT Name, FullPath, Size,
             Mtime AS Modified,
             Ctime AS Created,
             hash(path=FullPath) AS Hash,
             "Downloads" AS Source
      FROM glob(
        globs=format(format="C:\\Users\\%v\\Downloads\\*", args=[Username])
      )
      WHERE NOT IsDir
      ORDER BY Created DESC
      LIMIT 100
```

## Learn More

- [Windows Forensics: User Activity Analysis](https://ridgelinecyber.com/training/courses/windows-endpoint-investigation/). user artifact analysis methodology
- [Incident Response: Account Compromise Investigation](https://ridgelinecyber.com/training/courses/practical-ir/). reconstructing compromised account activity
