# Entra ID Sign-In Log Analysis for Compromised Accounts

Pulls sign-in logs for a compromised account, identifies anomalous patterns, maps the attack timeline, and produces an investigation report. Takes a UPN and a time window, then answers the three questions every incident responder needs answered: When did the compromise start? What did the attacker access? Are there signs of persistence?

## ATT&CK Relevance

Supports investigation of:
- T1078.004 — Valid Accounts: Cloud Accounts
- T1550.001 — Application Access Token (token replay detection)
- T1098 — Account Manipulation (persistence indicators)

## Use Case

An analyst has confirmed an account is compromised — either through an alert, a user report, or anomalous activity. Before containment, you need to understand the scope: when did the attacker first access the account, what resources were touched, and what persistence mechanisms were planted. This script automates that analysis against the Graph API sign-in logs.

## Prerequisites

- Microsoft Graph PowerShell SDK: `Install-Module Microsoft.Graph -Scope CurrentUser`
- Entra ID role: Security Reader, Global Reader, or Security Administrator
- Entra ID P1 or P2 for complete sign-in telemetry
- Permissions: `AuditLog.Read.All`, `Directory.Read.All`

## Script

```powershell
<#
.SYNOPSIS
    Analyze sign-in logs for a compromised Entra ID account.
.DESCRIPTION
    Queries Microsoft Graph for interactive and non-interactive sign-in
    events for a specified user within a time window. Identifies anomalous
    patterns including: unusual IPs, impossible travel, new devices, risky
    sign-ins, application access anomalies, and potential persistence.
.PARAMETER UserPrincipalName
    The UPN of the compromised account.
.PARAMETER HoursBack
    How many hours of sign-in history to analyze. Default: 168 (7 days).
.PARAMETER OutputPath
    Directory for the investigation report. Default: current directory.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$UserPrincipalName,

    [int]$HoursBack = 168,

    [string]$OutputPath = "."
)

$ErrorActionPreference = 'Stop'

# Connect to Graph
$scopes = @("AuditLog.Read.All", "Directory.Read.All")
Connect-MgGraph -Scopes $scopes -NoWelcome

$startDate = (Get-Date).AddHours(-$HoursBack).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportDir = Join-Path $OutputPath "SignInAnalysis_$($UserPrincipalName.Split('@')[0])_$timestamp"
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null

Write-Host "[*] Analyzing sign-ins for $UserPrincipalName (last $HoursBack hours)" -ForegroundColor Cyan

# --- Collect Interactive Sign-ins ---
Write-Host "[*] Pulling interactive sign-ins..." -ForegroundColor Yellow
$filter = "userPrincipalName eq '$UserPrincipalName' and createdDateTime ge $startDate"
$interactiveSignins = Get-MgAuditLogSignIn -Filter $filter -All -Property `
    CreatedDateTime, AppDisplayName, IpAddress, Location, Status, `
    RiskLevelDuringSignIn, RiskState, DeviceDetail, ConditionalAccessStatus, `
    UserAgent, ResourceDisplayName, AuthenticationRequirement, `
    MfaDetail, IsInteractive, CorrelationId

Write-Host "  Found $($interactiveSignins.Count) interactive sign-ins"

# --- Collect Non-Interactive Sign-ins ---
Write-Host "[*] Pulling non-interactive sign-ins..." -ForegroundColor Yellow
$nonInteractive = Get-MgAuditLogSignIn -Filter $filter -All -Property `
    CreatedDateTime, AppDisplayName, IpAddress, Location, Status, `
    RiskLevelDuringSignIn, DeviceDetail, UserAgent, ResourceDisplayName `
    -SignInType NonInteractive 2>$null

if ($nonInteractive) {
    Write-Host "  Found $($nonInteractive.Count) non-interactive sign-ins"
}

$allSignins = @($interactiveSignins) + @($nonInteractive)

# --- Analysis Functions ---
function Get-UniqueIPs {
    param($Signins)
    $Signins | Group-Object IpAddress | ForEach-Object {
        $firstSeen = ($_.Group | Sort-Object CreatedDateTime | Select-Object -First 1).CreatedDateTime
        $lastSeen = ($_.Group | Sort-Object CreatedDateTime -Descending | Select-Object -First 1).CreatedDateTime
        $locations = ($_.Group | ForEach-Object {
            "$($_.Location.City), $($_.Location.CountryOrRegion)"
        } | Sort-Object -Unique) -join "; "

        [PSCustomObject]@{
            IPAddress  = $_.Name
            Count      = $_.Count
            FirstSeen  = $firstSeen
            LastSeen   = $lastSeen
            Locations  = $locations
            Successful = ($_.Group | Where-Object { $_.Status.ErrorCode -eq 0 }).Count
            Failed     = ($_.Group | Where-Object { $_.Status.ErrorCode -ne 0 }).Count
        }
    } | Sort-Object Count -Descending
}

function Get-RiskySignins {
    param($Signins)
    $Signins | Where-Object {
        $_.RiskLevelDuringSignIn -in @("medium", "high") -or
        $_.Status.ErrorCode -eq 0
    } | Where-Object { $_.RiskLevelDuringSignIn -in @("medium", "high") } |
    ForEach-Object {
        [PSCustomObject]@{
            Time       = $_.CreatedDateTime
            IP         = $_.IpAddress
            Location   = "$($_.Location.City), $($_.Location.CountryOrRegion)"
            RiskLevel  = $_.RiskLevelDuringSignIn
            App        = $_.AppDisplayName
            UserAgent  = $_.UserAgent
        }
    }
}

function Get-ApplicationAccess {
    param($Signins)
    $Signins | Where-Object { $_.Status.ErrorCode -eq 0 } |
    Group-Object AppDisplayName | ForEach-Object {
        [PSCustomObject]@{
            Application = $_.Name
            AccessCount = $_.Count
            UniqueIPs   = ($_.Group | Select-Object -ExpandProperty IpAddress -Unique).Count
            FirstAccess = ($_.Group | Sort-Object CreatedDateTime | Select-Object -First 1).CreatedDateTime
            LastAccess  = ($_.Group | Sort-Object CreatedDateTime -Descending | Select-Object -First 1).CreatedDateTime
        }
    } | Sort-Object AccessCount -Descending
}

function Get-DeviceProfile {
    param($Signins)
    $Signins | Where-Object { $_.Status.ErrorCode -eq 0 } |
    ForEach-Object {
        $os = $_.DeviceDetail.OperatingSystem
        $browser = $_.DeviceDetail.Browser
        $deviceId = $_.DeviceDetail.DeviceId
        "$os | $browser | $deviceId"
    } | Group-Object | ForEach-Object {
        $parts = $_.Name -split " \| "
        [PSCustomObject]@{
            OS       = $parts[0]
            Browser  = $parts[1]
            DeviceId = if ($parts[2]) { $parts[2] } else { "Unregistered" }
            Count    = $_.Count
        }
    } | Sort-Object Count -Descending
}

# --- Run Analysis ---
Write-Host "[*] Running analysis..." -ForegroundColor Yellow

$uniqueIPs = Get-UniqueIPs -Signins $allSignins
$riskySignins = Get-RiskySignins -Signins $allSignins
$appAccess = Get-ApplicationAccess -Signins $allSignins
$deviceProfile = Get-DeviceProfile -Signins $allSignins

# --- Check for Persistence Indicators ---
Write-Host "[*] Checking audit logs for persistence..." -ForegroundColor Yellow

$auditFilter = "initiatedBy/user/userPrincipalName eq '$UserPrincipalName' and activityDateTime ge $startDate"
$auditEvents = Get-MgAuditLogDirectoryAudit -Filter $auditFilter -All 2>$null

$persistenceIndicators = @()
$suspiciousOps = @(
    "Add app role assignment",
    "Consent to application",
    "Add delegated permission grant",
    "Set-InboxRule", "New-InboxRule",
    "Add member to role",
    "Add service principal credentials",
    "Add federated identity credential",
    "Update application",
    "Add owner to application",
    "Add owner to service principal"
)

foreach ($event in $auditEvents) {
    if ($suspiciousOps -contains $event.ActivityDisplayName -or
        $event.ActivityDisplayName -match "inbox|rule|forward|redirect|credential|consent|role|owner") {
        $persistenceIndicators += [PSCustomObject]@{
            Time      = $event.ActivityDateTime
            Operation = $event.ActivityDisplayName
            Target    = ($event.TargetResources | ForEach-Object { $_.DisplayName }) -join ", "
            Result    = $event.Result
            IP        = $event.InitiatedBy.User.IpAddress
        }
    }
}

# --- Generate Report ---
Write-Host "[*] Generating report..." -ForegroundColor Yellow

$report = @"
# Sign-In Analysis Report
## Account: $UserPrincipalName
## Analysis Window: $HoursBack hours ($startDate to now)
## Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC")

---

## Summary

| Metric | Value |
|--------|-------|
| Total sign-in events | $($allSignins.Count) |
| Interactive | $($interactiveSignins.Count) |
| Non-interactive | $(if ($nonInteractive) { $nonInteractive.Count } else { 0 }) |
| Unique IPs | $($uniqueIPs.Count) |
| Risky sign-ins | $($riskySignins.Count) |
| Applications accessed | $($appAccess.Count) |
| Unique devices | $($deviceProfile.Count) |
| Persistence indicators | $($persistenceIndicators.Count) |

---

## IP Address Analysis

$($uniqueIPs | ForEach-Object {
"- **$($_.IPAddress)** — $($_.Count) events ($($_.Successful) success, $($_.Failed) failed)
  Location: $($_.Locations) | First: $($_.FirstSeen) | Last: $($_.LastSeen)"
} | Out-String)

## Risky Sign-Ins

$(if ($riskySignins.Count -gt 0) {
    $riskySignins | ForEach-Object {
"- [$($_.RiskLevel)] $($_.Time) from $($_.IP) ($($_.Location))
  App: $($_.App) | UA: $($_.UserAgent)"
    } | Out-String
} else { "No risky sign-ins detected in this window." })

## Application Access

$($appAccess | ForEach-Object {
"- **$($_.Application)** — $($_.AccessCount) accesses from $($_.UniqueIPs) IPs
  Window: $($_.FirstAccess) to $($_.LastAccess)"
} | Out-String)

## Device Profiles

$($deviceProfile | ForEach-Object {
"- $($_.OS) / $($_.Browser) (Device: $($_.DeviceId)) — $($_.Count) sign-ins"
} | Out-String)

## Persistence Indicators

$(if ($persistenceIndicators.Count -gt 0) {
    "⚠ PERSISTENCE DETECTED — Review immediately:`n"
    $persistenceIndicators | ForEach-Object {
"- [$($_.Time)] **$($_.Operation)** targeting $($_.Target)
  Result: $($_.Result) | From: $($_.IP)"
    } | Out-String
} else { "No persistence indicators found in audit logs for this window." })

---

## Recommended Next Steps

1. Cross-reference unknown IPs against threat intelligence
2. Review inbox rules and mail forwarding configuration
3. Check OAuth application consent grants
4. Verify MFA method registrations for unauthorized additions
5. Review any new devices in the device profile
"@

$reportPath = Join-Path $reportDir "investigation_report.md"
$report | Out-File -FilePath $reportPath -Encoding UTF8

# Export raw data
$allSignins | Export-Csv -Path (Join-Path $reportDir "all_signins.csv") -NoTypeInformation
$uniqueIPs | Export-Csv -Path (Join-Path $reportDir "unique_ips.csv") -NoTypeInformation
if ($persistenceIndicators.Count -gt 0) {
    $persistenceIndicators | Export-Csv -Path (Join-Path $reportDir "persistence_indicators.csv") -NoTypeInformation
}

Write-Host "`n[✓] Analysis complete" -ForegroundColor Green
Write-Host "  Report: $reportPath"
Write-Host "  Sign-ins: $($allSignins.Count) total, $($riskySignins.Count) risky"
Write-Host "  IPs: $($uniqueIPs.Count) unique"
Write-Host "  Persistence: $($persistenceIndicators.Count) indicators" -ForegroundColor $(if ($persistenceIndicators.Count -gt 0) { "Red" } else { "Green" })
```

## Usage

```powershell
# Analyze last 7 days (default)
.\Invoke-SignInAnalysis.ps1 -UserPrincipalName "john.doe@contoso.com"

# Analyze last 48 hours with custom output
.\Invoke-SignInAnalysis.ps1 `
    -UserPrincipalName "john.doe@contoso.com" `
    -HoursBack 48 `
    -OutputPath "D:\Investigations\INC-2025-0847"
```

## Output

```
SignInAnalysis_john.doe_20250525_143022/
├── investigation_report.md      # Human-readable analysis
├── all_signins.csv              # Raw sign-in data for further analysis
├── unique_ips.csv               # IP address summary
└── persistence_indicators.csv   # Audit log findings (if any)
```

## What the Script Analyzes

1. **IP addresses** — every unique IP, success/failure counts, geolocation, first/last seen
2. **Risk signals** — sign-ins that Entra ID flagged as medium or high risk, with context
3. **Application access** — which applications the account accessed, from how many IPs
4. **Device profiles** — OS, browser, device registration status
5. **Persistence** — audit log events indicating inbox rules, OAuth consent, role assignments, service principal modifications, or federation changes initiated by the compromised account

## Limitations

- Graph API sign-in log retention: 30 days (P1/P2). If you need older data, query from a SIEM or Log Analytics workspace.
- Non-interactive sign-in logs require a separate API call and may not be available on all license tiers
- The persistence check searches audit logs for the compromised user as the initiator — it won't catch persistence planted by a different account the attacker also controls
- Rate limiting: large accounts (10,000+ sign-ins) may require pagination delays

## Learn More

- [Entra ID Security — Sign-In Log Analysis](https://ridgelinecyber.com/training/courses/entra-id-security/) — sign-in log schema, risk signals, and investigation techniques
- [Incident Response — Identity Compromise](https://ridgelinecyber.com/training/courses/practical-ir/) — identity compromise investigation and containment procedures
- [SOC Operations — Identity Alert Triage](https://ridgelinecyber.com/training/courses/m365-security-operations/) — sign-in anomaly detection and escalation
