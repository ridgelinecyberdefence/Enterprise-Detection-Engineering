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
