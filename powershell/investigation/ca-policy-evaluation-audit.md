# Conditional Access Policy Evaluation Audit

Pulls every Conditional Access policy via Graph API, evaluates each against a security baseline, identifies gaps, and produces a prioritized remediation report. The script doesn't just list policies — it analyzes the logical coverage: which scenarios are unprotected, which policies have exceptions that create bypass paths, and which grant controls are weaker than they should be.

## ATT&CK Relevance

Supports defense against:
- T1078.004 — Valid Accounts: Cloud Accounts (policy gaps allow credential abuse)
- T1556 — Modify Authentication Process (weak MFA requirements)
- T1562.001 — Impair Defenses: Disable or Modify Tools (CA policy manipulation)

## Use Case

Your CISO asks: "Are we covered?" You have 47 Conditional Access policies accumulated over three years. Some overlap, some conflict, some have exceptions that weren't documented. This script evaluates the actual policy state against a defined security baseline and tells you exactly where the gaps are.

## Prerequisites

- Microsoft Graph PowerShell SDK: `Install-Module Microsoft.Graph -Scope CurrentUser`
- Entra ID role: Security Reader, Conditional Access Administrator, or Global Reader
- Permissions: `Policy.Read.All`, `Directory.Read.All`
- Entra ID P1 or P2 (required for Conditional Access)

## Script

```powershell
<#
.SYNOPSIS
    Evaluate Conditional Access policies against a security baseline.
.DESCRIPTION
    Retrieves all CA policies, analyzes coverage gaps, exception risks,
    and grant control strength. Produces a prioritized remediation report.
.PARAMETER OutputPath
    Directory for the audit output. Default: current directory.
.PARAMETER IncludeDisabled
    If set, includes disabled and report-only policies in the analysis.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = ".",
    [switch]$IncludeDisabled
)

$ErrorActionPreference = 'Stop'

Connect-MgGraph -Scopes @("Policy.Read.All", "Directory.Read.All") -NoWelcome

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportDir = Join-Path $OutputPath "CA_Audit_$timestamp"
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null

Write-Host "[*] Retrieving Conditional Access policies..." -ForegroundColor Cyan
$policies = Get-MgIdentityConditionalAccessPolicy -All

$enabledPolicies = $policies | Where-Object { $_.State -eq "enabled" }
$reportOnlyPolicies = $policies | Where-Object { $_.State -eq "enabledForReportingButNotEnforced" }
$disabledPolicies = $policies | Where-Object { $_.State -eq "disabled" }

Write-Host "  Total: $($policies.Count) | Enabled: $($enabledPolicies.Count) | Report-only: $($reportOnlyPolicies.Count) | Disabled: $($disabledPolicies.Count)"

$analysisSet = if ($IncludeDisabled) { $policies } else { $enabledPolicies }

# --- Baseline Checks ---
$findings = @()

function Add-Finding {
    param(
        [string]$Category,
        [string]$Severity,
        [string]$PolicyName,
        [string]$Finding,
        [string]$Recommendation
    )
    $script:findings += [PSCustomObject]@{
        Category       = $Category
        Severity       = $Severity
        PolicyName     = $PolicyName
        Finding        = $Finding
        Recommendation = $Recommendation
    }
}

foreach ($policy in $analysisSet) {
    $name = $policy.DisplayName
    $conditions = $policy.Conditions
    $grantControls = $policy.GrantControls
    $sessionControls = $policy.SessionControls

    # --- Grant Control Analysis ---

    # Check for MFA requirement
    $requiresMFA = $grantControls.BuiltInControls -contains "mfa"
    $requiresCompliantDevice = $grantControls.BuiltInControls -contains "compliantDevice"
    $requiresDomainJoined = $grantControls.BuiltInControls -contains "domainJoinedDevice"
    $requiresAuthStrength = $null -ne $grantControls.AuthenticationStrength

    if (-not $requiresMFA -and -not $requiresCompliantDevice -and
        -not $requiresDomainJoined -and -not $requiresAuthStrength) {
        if ($grantControls.Operator -ne "Block") {
            Add-Finding -Category "Grant Controls" -Severity "High" `
                -PolicyName $name `
                -Finding "Policy grants access without MFA, device compliance, or authentication strength" `
                -Recommendation "Add MFA or authentication strength requirement"
        }
    }

    # Check for authentication strength vs legacy MFA
    if ($requiresMFA -and -not $requiresAuthStrength) {
        Add-Finding -Category "Grant Controls" -Severity "Medium" `
            -PolicyName $name `
            -Finding "Uses legacy MFA requirement instead of authentication strength" `
            -Recommendation "Migrate to authentication strength policy (phishing-resistant MFA)"
    }

    # --- Exception Analysis ---

    # Excluded users
    $excludedUsers = $conditions.Users.ExcludeUsers
    if ($excludedUsers -and $excludedUsers.Count -gt 2) {
        Add-Finding -Category "Exceptions" -Severity "High" `
            -PolicyName $name `
            -Finding "$($excludedUsers.Count) users excluded — creates bypass path" `
            -Recommendation "Review exclusions. Use a break-glass group, not individual exclusions."
    }

    # Excluded groups
    $excludedGroups = $conditions.Users.ExcludeGroups
    if ($excludedGroups -and $excludedGroups.Count -gt 0) {
        Add-Finding -Category "Exceptions" -Severity "Medium" `
            -PolicyName $name `
            -Finding "$($excludedGroups.Count) groups excluded from policy" `
            -Recommendation "Audit group membership. Excluded groups should be monitored for unauthorized additions."
    }

    # Excluded applications
    $excludedApps = $conditions.Applications.ExcludeApplications
    if ($excludedApps -and $excludedApps.Count -gt 0) {
        Add-Finding -Category "Exceptions" -Severity "Medium" `
            -PolicyName $name `
            -Finding "$($excludedApps.Count) applications excluded" `
            -Recommendation "Verify each excluded app. Attackers target apps excluded from MFA."
    }

    # --- Scope Analysis ---

    # All users check
    $includesAllUsers = $conditions.Users.IncludeUsers -contains "All"
    $includesAllApps = $conditions.Applications.IncludeApplications -contains "All"

    if (-not $includesAllUsers -and -not $conditions.Users.IncludeGroups) {
        Add-Finding -Category "Coverage" -Severity "Info" `
            -PolicyName $name `
            -Finding "Policy scoped to specific users/groups, not All Users" `
            -Recommendation "Verify intended scope — new users may not be covered"
    }

    # --- Platform and Location ---

    # No platform condition (applies to all platforms)
    $platforms = $conditions.Platforms
    if (-not $platforms -or (-not $platforms.IncludePlatforms -and -not $platforms.ExcludePlatforms)) {
        # No platform restriction is actually fine for most policies
    }

    # No location condition on sensitive policies
    $locations = $conditions.Locations
    if ($requiresMFA -and (-not $locations -or -not $locations.IncludeLocations)) {
        # MFA for all locations is the most secure configuration
    }

    # --- Session Controls ---
    $signInFrequency = $sessionControls.SignInFrequency
    $persistentBrowser = $sessionControls.PersistentBrowser

    if ($persistentBrowser -and $persistentBrowser.Mode -eq "always") {
        Add-Finding -Category "Session Controls" -Severity "Medium" `
            -PolicyName $name `
            -Finding "Persistent browser session enabled — tokens persist across browser closes" `
            -Recommendation "Set to 'never' for sensitive applications or use sign-in frequency instead"
    }
}

# --- Coverage Gap Analysis ---
Write-Host "[*] Analyzing coverage gaps..." -ForegroundColor Yellow

# Check: Is there a policy requiring MFA for all users + all apps?
$universalMFA = $enabledPolicies | Where-Object {
    $_.Conditions.Users.IncludeUsers -contains "All" -and
    $_.Conditions.Applications.IncludeApplications -contains "All" -and
    ($_.GrantControls.BuiltInControls -contains "mfa" -or $_.GrantControls.AuthenticationStrength)
}
if (-not $universalMFA) {
    Add-Finding -Category "Coverage Gap" -Severity "Critical" `
        -PolicyName "(Missing Policy)" `
        -Finding "No policy requires MFA for All Users + All Cloud Apps" `
        -Recommendation "Create a baseline MFA policy covering all users and all applications"
}

# Check: Is there a policy blocking legacy authentication?
$legacyBlock = $enabledPolicies | Where-Object {
    $_.Conditions.ClientAppTypes -contains "exchangeActiveSync" -or
    $_.Conditions.ClientAppTypes -contains "other"
} | Where-Object { $_.GrantControls.Operator -eq "Block" }
if (-not $legacyBlock) {
    Add-Finding -Category "Coverage Gap" -Severity "Critical" `
        -PolicyName "(Missing Policy)" `
        -Finding "No policy blocks legacy authentication protocols" `
        -Recommendation "Block legacy auth (Exchange ActiveSync, other clients) for all users"
}

# Check: Is there a block for high-risk sign-ins?
$riskBlock = $enabledPolicies | Where-Object {
    $_.Conditions.SignInRiskLevels -contains "high" -and
    $_.GrantControls.Operator -eq "Block"
}
if (-not $riskBlock) {
    Add-Finding -Category "Coverage Gap" -Severity "High" `
        -PolicyName "(Missing Policy)" `
        -Finding "No policy blocks high-risk sign-ins" `
        -Recommendation "Create policy: When sign-in risk = High → Block. Requires Entra ID P2."
}

# --- Report ---
$findings = $findings | Sort-Object @{Expression = {
    switch ($_.Severity) {
        "Critical" { 0 }
        "High"     { 1 }
        "Medium"   { 2 }
        "Low"      { 3 }
        "Info"     { 4 }
    }
}}

$csvPath = Join-Path $reportDir "ca_findings.csv"
$findings | Export-Csv -Path $csvPath -NoTypeInformation

$critCount = ($findings | Where-Object Severity -eq "Critical").Count
$highCount = ($findings | Where-Object Severity -eq "High").Count
$medCount = ($findings | Where-Object Severity -eq "Medium").Count

$report = @"
# Conditional Access Policy Audit
## Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

## Policy Inventory

| State | Count |
|-------|-------|
| Enabled | $($enabledPolicies.Count) |
| Report-only | $($reportOnlyPolicies.Count) |
| Disabled | $($disabledPolicies.Count) |
| **Total** | **$($policies.Count)** |

## Findings Summary

| Severity | Count |
|----------|-------|
| Critical | $critCount |
| High | $highCount |
| Medium | $medCount |
| Total | $($findings.Count) |

## Critical and High Findings

$($findings | Where-Object { $_.Severity -in @("Critical", "High") } | ForEach-Object {
"### [$($_.Severity)] $($_.PolicyName)
**Category:** $($_.Category)
**Finding:** $($_.Finding)
**Recommendation:** $($_.Recommendation)
"
} | Out-String)

## All Policies Analyzed

$($analysisSet | ForEach-Object {
"- **$($_.DisplayName)** [$($_.State)]
  Users: $(if ($_.Conditions.Users.IncludeUsers -contains 'All') { 'All Users' } else { 'Scoped' })
  Apps: $(if ($_.Conditions.Applications.IncludeApplications -contains 'All') { 'All Apps' } else { 'Scoped' })
  Grant: $($_.GrantControls.BuiltInControls -join ', ')$(if ($_.GrantControls.Operator -eq 'Block') { ' [BLOCK]' })"
} | Out-String)
"@

$reportPath = Join-Path $reportDir "audit_report.md"
$report | Out-File -FilePath $reportPath -Encoding UTF8

# Export raw policy data
$policies | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $reportDir "raw_policies.json") -Encoding UTF8

Write-Host "`n[✓] Audit complete" -ForegroundColor Green
Write-Host "  Findings: $critCount critical, $highCount high, $medCount medium"
Write-Host "  Report: $reportPath"
Write-Host "  Data: $csvPath"
```

## Usage

```powershell
# Standard audit (enabled policies only)
.\Invoke-CAPolicyAudit.ps1 -OutputPath "D:\Audits"

# Include disabled and report-only policies
.\Invoke-CAPolicyAudit.ps1 -OutputPath "D:\Audits" -IncludeDisabled
```

## What the Script Checks

| Check | Category | Severity |
|-------|----------|----------|
| No MFA/device compliance/auth strength on grant controls | Grant Controls | High |
| Legacy MFA instead of authentication strength | Grant Controls | Medium |
| More than 2 individually excluded users | Exceptions | High |
| Excluded groups | Exceptions | Medium |
| Excluded applications | Exceptions | Medium |
| Persistent browser session enabled | Session Controls | Medium |
| No universal MFA policy (All Users + All Apps) | Coverage Gap | Critical |
| No legacy authentication block | Coverage Gap | Critical |
| No high-risk sign-in block | Coverage Gap | High |

## Limitations

- The script evaluates policy configuration, not policy evaluation results. A well-configured policy that's scoped incorrectly still protects no one. Cross-reference with sign-in logs (`CAStatus` field) for actual enforcement data.
- Named Locations are referenced by ID, not resolved to names. For a complete audit, map location IDs to location names via `Get-MgIdentityConditionalAccessNamedLocation`.
- Authentication strength policies are detected but not deeply analyzed (which specific methods are required).

## Learn More

- [Entra ID Security — Conditional Access Design](https://training.ridgelinecyber.com/courses/entra-id-security/) — CA policy architecture, authentication strength, and exception governance
- [M365 Security Architecture](https://training.ridgelinecyber.com/courses/m365-security-architecture/) — zero-trust Conditional Access framework design
- [Identity and Access Management](https://training.ridgelinecyber.com/courses/identity-access-management/) — CA policy lifecycle management and governance
