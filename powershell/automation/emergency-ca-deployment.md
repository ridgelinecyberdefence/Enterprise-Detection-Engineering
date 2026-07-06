# Emergency Conditional Access Policy Deployment

Deploys pre-defined emergency Conditional Access policies during active incidents. These are the policies you wish you had before the breach: block all non-compliant device access, enforce phishing-resistant MFA for admins, block legacy authentication, and restrict access to trusted locations only. Deploy in report-only first, then switch to enforced when validated.

## ATT&CK Relevance

Emergency defense against:
- T1078 - Valid Accounts (enforce MFA + device compliance)
- T1556 - Modify Authentication Process (enforce authentication strength)
- T1110 - Brute Force (legacy auth block + location restriction)

## Prerequisites

- Microsoft Graph PowerShell SDK
- Permissions: `Policy.ReadWrite.ConditionalAccess`, `Directory.Read.All`
- Entra ID role: Conditional Access Administrator or Security Administrator
- Entra ID P1 (P2 for risk-based policies)

## Script

```powershell
<#
.SYNOPSIS
    Deploy emergency Conditional Access policies.
.PARAMETER PolicySet
    Which emergency policy to deploy: BlockLegacyAuth, RequireMFAAdmins,
    RequireCompliantDevice, BlockExceptTrustedLocations, or All.
.PARAMETER Mode
    Deployment mode: ReportOnly (default, safe to deploy immediately) or Enabled.
.PARAMETER BreakGlassGroupId
    Object ID of the break-glass account group to exclude from all policies.
    If not provided, prompts for confirmation.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateSet("BlockLegacyAuth", "RequireMFAAdmins", "RequireCompliantDevice",
                 "BlockExceptTrustedLocations", "All")]
    [string]$PolicySet,

    [ValidateSet("ReportOnly", "Enabled")]
    [string]$Mode = "ReportOnly",

    [string]$BreakGlassGroupId
)

$ErrorActionPreference = 'Stop'
Connect-MgGraph -Scopes @("Policy.ReadWrite.ConditionalAccess", "Directory.Read.All") -NoWelcome

$state = if ($Mode -eq "Enabled") { "enabled" } else { "enabledForReportingButNotEnforced" }
$prefix = "[IR Emergency]"

if (-not $BreakGlassGroupId) {
    Write-Host "[!] No break-glass group specified. Emergency policies will apply to ALL users." -ForegroundColor Red
    $confirm = Read-Host "Continue without break-glass exclusion? (yes/no)"
    if ($confirm -ne "yes") { return }
}

$excludeGroups = if ($BreakGlassGroupId) { @($BreakGlassGroupId) } else { @() }

function Deploy-Policy {
    param([hashtable]$PolicyParams)
    try {
        $existing = Get-MgIdentityConditionalAccessPolicy -All |
            Where-Object { $_.DisplayName -eq $PolicyParams.DisplayName }
        if ($existing) {
            Write-Host "  [!] Policy already exists: $($PolicyParams.DisplayName) — skipping" -ForegroundColor Yellow
            return
        }
        New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicyParams
        Write-Host "  [✓] Deployed: $($PolicyParams.DisplayName) [$Mode]" -ForegroundColor Green
    } catch {
        Write-Host "  [✗] Failed: $($PolicyParams.DisplayName) — $($_.Exception.Message)" -ForegroundColor Red
    }
}

$policiesToDeploy = @()

# --- Block Legacy Authentication ---
if ($PolicySet -in @("BlockLegacyAuth", "All")) {
    $policiesToDeploy += @{
        DisplayName = "$prefix Block Legacy Authentication"
        State       = $state
        Conditions  = @{
            Users           = @{
                IncludeUsers  = @("All")
                ExcludeGroups = $excludeGroups
            }
            Applications    = @{ IncludeApplications = @("All") }
            ClientAppTypes  = @("exchangeActiveSync", "other")
        }
        GrantControls = @{
            Operator        = "Block"
            BuiltInControls = @("block")
        }
    }
}

# --- Require MFA for All Admins ---
if ($PolicySet -in @("RequireMFAAdmins", "All")) {
    $adminRoleIds = @(
        "62e90394-69f5-4237-9190-012177145e10"  # Global Administrator
        "e8611ab8-c189-46e8-94e1-60213ab1f814"  # Privileged Role Administrator
        "194ae4cb-b126-40b2-bd5b-6091b380977d"  # Security Administrator
        "f28a1f94-e044-4c04-991c-e8fea1e63d3e"  # SharePoint Administrator
        "29232cdf-9323-42fd-ade2-1d097af3e4de"  # Exchange Administrator
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"  # Application Administrator
        "158c047a-c907-4556-b7ef-446551a6b5f7"  # Cloud Application Administrator
    )

    $policiesToDeploy += @{
        DisplayName = "$prefix Require MFA for Admins"
        State       = $state
        Conditions  = @{
            Users           = @{
                IncludeRoles  = $adminRoleIds
                ExcludeGroups = $excludeGroups
            }
            Applications    = @{ IncludeApplications = @("All") }
        }
        GrantControls = @{
            Operator        = "OR"
            BuiltInControls = @("mfa")
        }
    }
}

# --- Require Compliant Device ---
if ($PolicySet -in @("RequireCompliantDevice", "All")) {
    $policiesToDeploy += @{
        DisplayName = "$prefix Require Compliant Device"
        State       = $state
        Conditions  = @{
            Users           = @{
                IncludeUsers  = @("All")
                ExcludeGroups = $excludeGroups
            }
            Applications    = @{ IncludeApplications = @("All") }
            Platforms       = @{
                IncludePlatforms = @("all")
            }
        }
        GrantControls = @{
            Operator        = "OR"
            BuiltInControls = @("compliantDevice")
        }
    }
}

# --- Block Except Trusted Locations ---
if ($PolicySet -in @("BlockExceptTrustedLocations", "All")) {
    $policiesToDeploy += @{
        DisplayName = "$prefix Block Except Trusted Locations"
        State       = $state
        Conditions  = @{
            Users           = @{
                IncludeUsers  = @("All")
                ExcludeGroups = $excludeGroups
            }
            Applications    = @{ IncludeApplications = @("All") }
            Locations       = @{
                IncludeLocations = @("All")
                ExcludeLocations = @("AllTrusted")
            }
        }
        GrantControls = @{
            Operator        = "Block"
            BuiltInControls = @("block")
        }
    }
}

Write-Host "`n[*] Deploying $($policiesToDeploy.Count) emergency policies in $Mode mode..." -ForegroundColor Cyan

foreach ($policy in $policiesToDeploy) {
    Deploy-Policy -PolicyParams $policy
}

Write-Host "`n[✓] Deployment complete" -ForegroundColor Green
if ($Mode -eq "ReportOnly") {
    Write-Host "  Policies are in REPORT-ONLY mode. Monitor sign-in logs for impact before enabling." -ForegroundColor Yellow
    Write-Host "  To enable: Set-MgIdentityConditionalAccessPolicy -CondtionalAccessPolicyId <id> -State 'enabled'" -ForegroundColor Yellow
}
```

## Usage

```powershell
# Deploy all policies in report-only (recommended first step)
.\Deploy-EmergencyCA.ps1 -PolicySet All -Mode ReportOnly -BreakGlassGroupId "abc123-..."

# Deploy and enforce legacy auth block immediately
.\Deploy-EmergencyCA.ps1 -PolicySet BlockLegacyAuth -Mode Enabled -BreakGlassGroupId "abc123-..."

# Deploy all and enforce (active incident, validated impact)
.\Deploy-EmergencyCA.ps1 -PolicySet All -Mode Enabled -BreakGlassGroupId "abc123-..."
```

## Emergency Policy Inventory

| Policy | What It Does | Impact | Deploy First? |
|--------|-------------|--------|---------------|
| Block Legacy Auth | Blocks ActiveSync, POP, IMAP, older Outlook | Low (most tenants already have this) | Yes |
| Require MFA Admins | MFA for 7 critical admin roles | Medium (admins only) | Yes |
| Require Compliant Device | Only Intune-compliant devices can access | High (blocks BYOD/personal devices) | Report-only first |
| Block Except Trusted | Only trusted Named Locations can access | Very high (locks out remote workers) | Report-only first |

## Learn More

- [Entra ID Security: Emergency Conditional Access](https://ridgelinecyber.com/training/courses/entra-id-security/)
- [M365 Security Architecture: Zero Trust Policy Framework](https://ridgelinecyber.com/training/courses/m365-security-architecture/)
