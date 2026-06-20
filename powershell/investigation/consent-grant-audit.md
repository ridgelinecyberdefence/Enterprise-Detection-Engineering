# OAuth Application Consent Grant Audit

Enumerates all OAuth consent grants in the tenant, identifies overprivileged applications, flags suspicious consent patterns, and produces a risk-scored report. Consent grants are the persistence mechanism attackers love because they survive password resets and MFA changes — the application retains access until the consent is explicitly revoked.

## ATT&CK Relevance

Supports investigation of:
- T1098.003 — Account Manipulation: Additional Cloud Credentials
- T1550.001 — Application Access Token
- T1528 — Steal Application Access Token

## Use Case

Post-incident: you've contained the compromised account (password reset, session revocation, MFA re-registration). But the attacker granted OAuth consent to a malicious application during the compromise window. That application still has access to the user's mailbox, files, and contacts — your containment actions didn't touch it. This script finds every consent grant in the tenant and flags the ones that need investigation.

## Prerequisites

- Microsoft Graph PowerShell SDK: `Install-Module Microsoft.Graph -Scope CurrentUser`
- Entra ID role: Global Reader, Application Administrator, or Cloud Application Administrator
- Permissions: `Application.Read.All`, `DelegatedPermissionGrant.Read.All`, `Directory.Read.All`

## Script

```powershell
<#
.SYNOPSIS
    Audit all OAuth consent grants in the tenant for overprivileged or suspicious apps.
.DESCRIPTION
    Pulls delegated and application permission grants, scores each by risk based
    on permission scope, consent type, publisher verification, and creation timing.
    Produces a risk-scored CSV and summary report.
.PARAMETER OutputPath
    Directory for the audit report. Default: current directory.
.PARAMETER HighRiskOnly
    If set, only output grants with risk score >= 7.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = ".",
    [switch]$HighRiskOnly
)

$ErrorActionPreference = 'Stop'

Connect-MgGraph -Scopes @(
    "Application.Read.All",
    "DelegatedPermissionGrant.Read.All",
    "Directory.Read.All"
) -NoWelcome

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportDir = Join-Path $OutputPath "ConsentAudit_$timestamp"
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null

Write-Host "[*] Auditing OAuth consent grants..." -ForegroundColor Cyan

# High-risk permission scopes
$highRiskDelegated = @(
    "Mail.ReadWrite", "Mail.Read", "Mail.Send",
    "Files.ReadWrite.All", "Files.Read.All",
    "User.ReadWrite.All", "Directory.ReadWrite.All",
    "MailboxSettings.ReadWrite",
    "Contacts.ReadWrite", "Calendars.ReadWrite",
    "Sites.ReadWrite.All", "Notes.ReadWrite.All",
    "Chat.ReadWrite", "Team.ReadBasic.All"
)

$criticalAppPerms = @(
    "Mail.ReadWrite", "Mail.Read", "Mail.Send",
    "Files.ReadWrite.All", "User.ReadWrite.All",
    "Directory.ReadWrite.All", "Application.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All",
    "Domain.ReadWrite.All", "Policy.ReadWrite.ConditionalAccess"
)

# --- Delegated Permission Grants ---
Write-Host "[*] Pulling delegated permission grants..." -ForegroundColor Yellow
$delegatedGrants = Get-MgOauth2PermissionGrant -All

$delegatedResults = foreach ($grant in $delegatedGrants) {
    $sp = Get-MgServicePrincipal -ServicePrincipalId $grant.ClientId -ErrorAction SilentlyContinue
    $scopes = $grant.Scope -split " " | Where-Object { $_ }

    $riskScore = 0
    $riskReasons = @()

    # Score by permission sensitivity
    foreach ($scope in $scopes) {
        if ($scope -in $highRiskDelegated) {
            $riskScore += 3
            $riskReasons += "High-risk scope: $scope"
        }
    }

    # Score by consent type
    if ($grant.ConsentType -eq "AllPrincipals") {
        $riskScore += 3
        $riskReasons += "Admin consent (all users)"
    }

    # Score by publisher verification
    if ($sp -and -not $sp.VerifiedPublisher.DisplayName) {
        $riskScore += 2
        $riskReasons += "Unverified publisher"
    }

    # Score by app origin
    if ($sp -and $sp.AppOwnerOrganizationId -and
        $sp.AppOwnerOrganizationId -ne (Get-MgOrganization).Id) {
        $riskScore += 1
        $riskReasons += "External (multi-tenant) app"
    }

    [PSCustomObject]@{
        GrantType     = "Delegated"
        AppName       = if ($sp) { $sp.DisplayName } else { "Unknown ($($grant.ClientId))" }
        AppId         = if ($sp) { $sp.AppId } else { $grant.ClientId }
        Publisher     = if ($sp) { $sp.VerifiedPublisher.DisplayName } else { "Unknown" }
        ConsentType   = $grant.ConsentType
        ConsentedBy   = if ($grant.PrincipalId) { $grant.PrincipalId } else { "Admin (all users)" }
        Scopes        = $grant.Scope
        ScopeCount    = $scopes.Count
        RiskScore     = [math]::Min($riskScore, 10)
        RiskReasons   = ($riskReasons | Select-Object -Unique) -join "; "
    }
}

# --- Application Permission Grants ---
Write-Host "[*] Pulling application permission grants..." -ForegroundColor Yellow
$servicePrincipals = Get-MgServicePrincipal -All -Property Id, DisplayName, AppId, AppRoleAssignments, VerifiedPublisher, AppOwnerOrganizationId

$appResults = foreach ($sp in $servicePrincipals) {
    $roleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue

    foreach ($assignment in $roleAssignments) {
        $resourceSP = Get-MgServicePrincipal -ServicePrincipalId $assignment.ResourceId -ErrorAction SilentlyContinue
        $roleName = "Unknown"

        if ($resourceSP) {
            $role = $resourceSP.AppRoles | Where-Object { $_.Id -eq $assignment.AppRoleId }
            $roleName = if ($role) { $role.Value } else { "Role:$($assignment.AppRoleId)" }
        }

        $riskScore = 0
        $riskReasons = @()

        if ($roleName -in $criticalAppPerms) {
            $riskScore += 4
            $riskReasons += "Critical app permission: $roleName"
        }

        if (-not $sp.VerifiedPublisher.DisplayName) {
            $riskScore += 2
            $riskReasons += "Unverified publisher"
        }

        if ($sp.AppOwnerOrganizationId -and
            $sp.AppOwnerOrganizationId -ne (Get-MgOrganization).Id) {
            $riskScore += 1
            $riskReasons += "External app"
        }

        [PSCustomObject]@{
            GrantType     = "Application"
            AppName       = $sp.DisplayName
            AppId         = $sp.AppId
            Publisher     = if ($sp.VerifiedPublisher.DisplayName) { $sp.VerifiedPublisher.DisplayName } else { "Unverified" }
            ConsentType   = "Application"
            ConsentedBy   = "Admin"
            Scopes        = $roleName
            ScopeCount    = 1
            RiskScore     = [math]::Min($riskScore, 10)
            RiskReasons   = ($riskReasons | Select-Object -Unique) -join "; "
        }
    }
}

# --- Combine and Filter ---
$allGrants = @($delegatedResults) + @($appResults) | Sort-Object RiskScore -Descending

if ($HighRiskOnly) {
    $allGrants = $allGrants | Where-Object { $_.RiskScore -ge 7 }
}

# --- Output ---
$csvPath = Join-Path $reportDir "consent_grants.csv"
$allGrants | Export-Csv -Path $csvPath -NoTypeInformation

# Summary
$critical = ($allGrants | Where-Object { $_.RiskScore -ge 7 }).Count
$high = ($allGrants | Where-Object { $_.RiskScore -ge 4 -and $_.RiskScore -lt 7 }).Count
$medium = ($allGrants | Where-Object { $_.RiskScore -ge 2 -and $_.RiskScore -lt 4 }).Count
$low = ($allGrants | Where-Object { $_.RiskScore -lt 2 }).Count

$summary = @"
# OAuth Consent Grant Audit
## Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

| Risk Level | Count |
|------------|-------|
| Critical (7-10) | $critical |
| High (4-6) | $high |
| Medium (2-3) | $medium |
| Low (0-1) | $low |
| **Total** | **$($allGrants.Count)** |

## Critical and High Risk Grants

$($allGrants | Where-Object { $_.RiskScore -ge 4 } | ForEach-Object {
"- [$($_.RiskScore)/10] **$($_.AppName)** ($($_.GrantType))
  Scopes: $($_.Scopes)
  Publisher: $($_.Publisher)
  Risk: $($_.RiskReasons)"
} | Out-String)

## Recommended Actions

1. Review all Critical (7+) grants immediately — these have dangerous permission combinations
2. Verify publisher for all unverified apps with high-risk scopes
3. Remove consent for any app not recognized by the business
4. Implement admin consent workflow to prevent future user-consented high-risk grants
"@

$summaryPath = Join-Path $reportDir "audit_summary.md"
$summary | Out-File -FilePath $summaryPath -Encoding UTF8

Write-Host "`n[✓] Audit complete" -ForegroundColor Green
Write-Host "  Total grants: $($allGrants.Count)"
Write-Host "  Critical: $critical | High: $high | Medium: $medium | Low: $low"
Write-Host "  Report: $summaryPath"
Write-Host "  Data: $csvPath"
```

## Usage

```powershell
# Full audit
.\Invoke-ConsentGrantAudit.ps1 -OutputPath "D:\Investigations"

# High risk only
.\Invoke-ConsentGrantAudit.ps1 -HighRiskOnly
```

## Risk Scoring

| Factor | Points | Rationale |
|--------|--------|-----------|
| Critical app permission (Mail.ReadWrite, Directory.ReadWrite.All, etc.) | +4 | Application permissions with these scopes can access every user's data |
| High-risk delegated scope (Mail.Read, Files.ReadWrite.All, etc.) | +3 per scope | Delegated scopes that access sensitive data |
| Admin consent (AllPrincipals) | +3 | Consent applies to every user — one grant exposes the entire tenant |
| Unverified publisher | +2 | No verified publisher identity — could be attacker-registered |
| External (multi-tenant) app | +1 | App registered in a different tenant |

A score of 7+ warrants immediate investigation. The combination of unverified publisher + admin consent + Mail.ReadWrite is a textbook illicit consent grant.

## Limitations

- Does not check when consent was granted (Graph doesn't expose consent timestamps directly — correlate with AuditLogs for "Consent to application" events)
- Application permission enumeration is slow for large tenants (1000+ service principals). Consider filtering by `AppOwnerOrganizationId` for external apps only.
- The script requires Global Reader or equivalent. Application Administrator can also run it but has write permissions you may not want to use in an investigation context.

## Learn More

- [Entra ID Security — Application Governance](https://ridgelinecyber.com/training/courses/entra-id-security/) — consent framework, app governance, and illicit consent attack detection
- [Identity and Access Management — Non-Human Identities](https://ridgelinecyber.com/training/courses/identity-access-management/) — service principal governance and workload identity security
- [Incident Response — Cloud Identity Investigation](https://ridgelinecyber.com/training/courses/practical-ir/) — post-compromise consent audit procedures
