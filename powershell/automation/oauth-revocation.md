# Bulk OAuth Application Consent Revocation

Revokes OAuth consent grants for specified applications across the tenant or for a specific user. After you've identified malicious or overprivileged applications via the consent grant audit, this script removes the grants — which is the only way to cut off an application's access. Password resets and session revocations don't affect OAuth grants.

## ATT&CK Relevance

Remediation for:
- T1098.003 — Account Manipulation: Additional Cloud Credentials
- T1550.001 — Application Access Token

## Prerequisites

- Microsoft Graph PowerShell SDK
- Permissions: `DelegatedPermissionGrant.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`, `Application.ReadWrite.All`
- Entra ID role: Cloud Application Administrator or Application Administrator

## Script

```powershell
<#
.SYNOPSIS
    Revoke OAuth consent grants for specified applications.
.PARAMETER AppIds
    Array of Application (client) IDs to revoke.
.PARAMETER TargetUser
    Optional: revoke only for a specific user (UPN). If not specified, revokes
    tenant-wide (admin consent and all user consent grants).
.PARAMETER DryRun
    Show what would be revoked without making changes.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string[]]$AppIds,

    [string]$TargetUser,

    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

Connect-MgGraph -Scopes @(
    "DelegatedPermissionGrant.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All"
) -NoWelcome

$revokedCount = 0

foreach ($appId in $AppIds) {
    Write-Host "`n[*] Processing AppId: $appId" -ForegroundColor Cyan

    # Find the service principal
    $sp = Get-MgServicePrincipal -Filter "appId eq '$appId'" -ErrorAction SilentlyContinue
    if (-not $sp) {
        Write-Host "  [!] No service principal found for $appId — skipping" -ForegroundColor Yellow
        continue
    }

    Write-Host "  App: $($sp.DisplayName)"

    # Revoke delegated permission grants (OAuth2PermissionGrants)
    $grants = Get-MgOauth2PermissionGrant -Filter "clientId eq '$($sp.Id)'" -All

    if ($TargetUser) {
        $user = Get-MgUser -UserId $TargetUser
        $grants = $grants | Where-Object { $_.PrincipalId -eq $user.Id }
    }

    foreach ($grant in $grants) {
        $label = "Delegated grant: $($grant.Scope) [$(if ($grant.ConsentType -eq 'AllPrincipals') { 'Admin' } else { 'User' })]"

        if ($DryRun) {
            Write-Host "  [DRY RUN] Would revoke: $label" -ForegroundColor Yellow
        } else {
            try {
                Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $grant.Id
                Write-Host "  [✓] Revoked: $label" -ForegroundColor Green
                $revokedCount++
            } catch {
                Write-Host "  [✗] Failed: $label — $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }

    # Revoke application permission grants (AppRoleAssignments)
    $appRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All

    foreach ($role in $appRoles) {
        $label = "App permission: $($role.ResourceDisplayName) — $($role.AppRoleId)"

        if ($DryRun) {
            Write-Host "  [DRY RUN] Would revoke: $label" -ForegroundColor Yellow
        } else {
            try {
                Remove-MgServicePrincipalAppRoleAssignment `
                    -ServicePrincipalId $sp.Id `
                    -AppRoleAssignmentId $role.Id
                Write-Host "  [✓] Revoked: $label" -ForegroundColor Green
                $revokedCount++
            } catch {
                Write-Host "  [✗] Failed: $label — $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
}

$action = if ($DryRun) { "identified for revocation" } else { "revoked" }
Write-Host "`n[✓] $revokedCount grants $action" -ForegroundColor Green
```

## Usage

```powershell
# Dry run first
.\Invoke-OAuthRevocation.ps1 `
    -AppIds "a1b2c3d4-e5f6-7890-abcd-ef1234567890" `
    -DryRun

# Revoke for specific user
.\Invoke-OAuthRevocation.ps1 `
    -AppIds "a1b2c3d4-e5f6-7890-abcd-ef1234567890" `
    -TargetUser "compromised.user@contoso.com"

# Revoke tenant-wide for multiple apps
.\Invoke-OAuthRevocation.ps1 `
    -AppIds "app-id-1","app-id-2","app-id-3"
```

## Workflow

1. Run `Invoke-ConsentGrantAudit.ps1` to identify suspicious grants
2. Review the risk-scored output — focus on score >= 7
3. Run this script with `-DryRun` to confirm scope
4. Execute the revocation
5. Verify by re-running the consent audit

## Learn More

- [Entra ID Security — Application Governance](https://training.ridgelinecyber.com/courses/entra-id-security/)
- [Incident Response — Post-Compromise Remediation](https://training.ridgelinecyber.com/courses/practical-incident-response/)
