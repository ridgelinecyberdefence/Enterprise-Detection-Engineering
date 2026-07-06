[CmdletBinding()]
param(
    [string]$OutputPath = ".",
    [int]$ExpiringInDays = 30
)

$ErrorActionPreference = 'Stop'
Connect-MgGraph -Scopes @("Application.Read.All", "Directory.Read.All") -NoWelcome

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportDir = Join-Path $OutputPath "SPCredentialAudit_$timestamp"
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null

Write-Host "[*] Auditing service principal credentials..." -ForegroundColor Cyan

$apps = Get-MgApplication -All -Property Id, DisplayName, AppId, PasswordCredentials, KeyCredentials, CreatedDateTime
$findings = @()
$now = Get-Date

foreach ($app in $apps) {
    $allCreds = @()

    foreach ($pwd in $app.PasswordCredentials) {
        $allCreds += [PSCustomObject]@{
            AppName     = $app.DisplayName
            AppId       = $app.AppId
            CredType    = "Secret"
            KeyId       = $pwd.KeyId
            DisplayName = $pwd.DisplayName
            StartDate   = $pwd.StartDateTime
            EndDate     = $pwd.EndDateTime
            LifetimeDays = if ($pwd.EndDateTime -and $pwd.StartDateTime) {
                [math]::Round(($pwd.EndDateTime - $pwd.StartDateTime).TotalDays)
            } else { $null }
            DaysUntilExpiry = if ($pwd.EndDateTime) {
                [math]::Round(($pwd.EndDateTime - $now).TotalDays)
            } else { $null }
            Status      = if (-not $pwd.EndDateTime) { "No expiry" }
                          elseif ($pwd.EndDateTime -lt $now) { "Expired" }
                          elseif (($pwd.EndDateTime - $now).TotalDays -le $ExpiringInDays) { "Expiring soon" }
                          else { "Active" }
        }
    }

    foreach ($key in $app.KeyCredentials) {
        $allCreds += [PSCustomObject]@{
            AppName     = $app.DisplayName
            AppId       = $app.AppId
            CredType    = "Certificate"
            KeyId       = $key.KeyId
            DisplayName = $key.DisplayName
            StartDate   = $key.StartDateTime
            EndDate     = $key.EndDateTime
            LifetimeDays = if ($key.EndDateTime -and $key.StartDateTime) {
                [math]::Round(($key.EndDateTime - $key.StartDateTime).TotalDays)
            } else { $null }
            DaysUntilExpiry = if ($key.EndDateTime) {
                [math]::Round(($key.EndDateTime - $now).TotalDays)
            } else { $null }
            Status      = if (-not $key.EndDateTime) { "No expiry" }
                          elseif ($key.EndDateTime -lt $now) { "Expired" }
                          elseif (($key.EndDateTime - $now).TotalDays -le $ExpiringInDays) { "Expiring soon" }
                          else { "Active" }
        }
    }

    $findings += $allCreds

    # Flag: multiple active credentials on same app
    $activeCreds = $allCreds | Where-Object { $_.Status -eq "Active" }
    if ($activeCreds.Count -gt 2) {
        Write-Host "  [!] $($app.DisplayName) has $($activeCreds.Count) active credentials" -ForegroundColor Red
    }

    # Flag: credentials with excessive lifetime (> 2 years)
    $longLived = $allCreds | Where-Object { $_.LifetimeDays -gt 730 -and $_.Status -eq "Active" }
    if ($longLived) {
        Write-Host "  [!] $($app.DisplayName) has credentials with >2yr lifetime" -ForegroundColor Yellow
    }
}

# Output
$csvPath = Join-Path $reportDir "sp_credentials.csv"
$findings | Export-Csv -Path $csvPath -NoTypeInformation

$active = ($findings | Where-Object Status -eq "Active").Count
$expired = ($findings | Where-Object Status -eq "Expired").Count
$expiring = ($findings | Where-Object Status -eq "Expiring soon").Count
$noExpiry = ($findings | Where-Object Status -eq "No expiry").Count
$multiCred = ($findings | Where-Object Status -eq "Active" |
    Group-Object AppId | Where-Object Count -gt 2).Count

Write-Host "`n[✓] Audit complete" -ForegroundColor Green
Write-Host "  Total credentials: $($findings.Count)"
Write-Host "  Active: $active | Expired: $expired | Expiring (<$ExpiringInDays days): $expiring | No expiry: $noExpiry"
Write-Host "  Apps with 3+ active creds: $multiCred"
Write-Host "  Report: $csvPath"
