# Browser Artifact Collection — History, Downloads, and Credentials

Collects browser history, download records, bookmarks, and cached credentials from Chrome, Edge, and Firefox on the local or remote system. Critical for investigating data exfiltration, phishing click-through, and unauthorized access to cloud services.

## Category

Collection — Browser forensic evidence.

## Requirements

- Administrative access, PowerShell 5.1+
- Browsers must not be running during SQLite database access (or use Volume Shadow Copy)

## Script

```powershell
[CmdletBinding()]
param(
    [string]$UserProfile = $env:USERPROFILE,
    [string]$OutputPath = ".\Browser-Artifacts"
)

$ts = Get-Date -Format "yyyy-MM-dd_HHmmss"
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$browsers = @{
    Chrome = @{
        History  = "$UserProfile\AppData\Local\Google\Chrome\User Data\Default\History"
        Bookmarks = "$UserProfile\AppData\Local\Google\Chrome\User Data\Default\Bookmarks"
        LoginData = "$UserProfile\AppData\Local\Google\Chrome\User Data\Default\Login Data"
        Downloads = "$UserProfile\AppData\Local\Google\Chrome\User Data\Default\History"
    }
    Edge = @{
        History  = "$UserProfile\AppData\Local\Microsoft\Edge\User Data\Default\History"
        Bookmarks = "$UserProfile\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks"
        LoginData = "$UserProfile\AppData\Local\Microsoft\Edge\User Data\Default\Login Data"
    }
    Firefox = @{
        ProfilePath = "$UserProfile\AppData\Roaming\Mozilla\Firefox\Profiles"
    }
}

foreach ($browser in $browsers.Keys) {
    Write-Host "[*] Collecting $browser artifacts..." -ForegroundColor Cyan
    $destDir = Join-Path $OutputPath "$browser`_$ts"
    New-Item -ItemType Directory -Path $destDir -Force | Out-Null

    foreach ($artifact in $browsers[$browser].Keys) {
        $sourcePath = $browsers[$browser][$artifact]
        if ($artifact -eq 'ProfilePath') {
            # Firefox: copy all profile databases
            if (Test-Path $sourcePath) {
                $profiles = Get-ChildItem $sourcePath -Directory
                foreach ($profile in $profiles) {
                    $dbFiles = Get-ChildItem $profile.FullName -Filter "*.sqlite" -ErrorAction SilentlyContinue
                    foreach ($db in $dbFiles) {
                        Copy-Item $db.FullName (Join-Path $destDir "$($profile.Name)_$($db.Name)") -ErrorAction SilentlyContinue
                    }
                }
            }
        } elseif (Test-Path $sourcePath) {
            $destFile = Join-Path $destDir "$artifact`_$(Split-Path $sourcePath -Leaf)"
            Copy-Item $sourcePath $destFile -ErrorAction SilentlyContinue
            Write-Host "  [+] $artifact collected" -ForegroundColor Green
        } else {
            Write-Host "  [-] $artifact not found" -ForegroundColor Yellow
        }
    }
}

Write-Host "`n[*] Browser artifacts collected to $OutputPath" -ForegroundColor Cyan
Write-Host "[!] SQLite databases require DB Browser or sqlite3 for analysis" -ForegroundColor Yellow
```

## What This Collects

Chrome and Edge: History (URLs, visits, timestamps), bookmarks, login data databases, download records. Firefox: All SQLite databases from every profile (places.sqlite for history, logins.json for credentials). Files are copied for offline analysis — the script does not parse SQLite directly to avoid dependency requirements.

## Learn More

- [Windows Forensics](https://ridgelinecyber.com/training/courses/windows-endpoint-investigation/) — browser artifact analysis
- [Incident Response](https://ridgelinecyber.com/training/courses/practical-ir/) — user activity reconstruction
