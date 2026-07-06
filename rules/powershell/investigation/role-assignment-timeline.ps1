[CmdletBinding()]
param(
    [string]$OutputPath = "."
)

$ErrorActionPreference = 'Stop'
Connect-MgGraph -Scopes @("RoleManagement.Read.Directory", "Directory.Read.All") -NoWelcome

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportDir = Join-Path $OutputPath "RoleAudit_$timestamp"
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null

Write-Host "[*] Auditing directory role assignments..." -ForegroundColor Cyan

# Get role definitions
$roleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All
$roleMap = @{}
foreach ($role in $roleDefinitions) {
    $roleMap[$role.Id] = $role.DisplayName
}

# Critical roles that warrant extra scrutiny
$criticalRoles = @(
    "Global Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Intune Administrator",
    "Security Administrator",
    "Conditional Access Administrator",
    "Partner Tier1 Support",
    "Partner Tier2 Support"
)

$allAssignments = @()

# Active (permanent) assignments
Write-Host "[*] Pulling active role assignments..." -ForegroundColor Yellow
$activeAssignments = Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal

foreach ($assignment in $activeAssignments) {
    $roleName = $roleMap[$assignment.RoleDefinitionId]
    $principal = $assignment.Principal

    $allAssignments += [PSCustomObject]@{
        PrincipalName = $principal.AdditionalProperties.displayName
        PrincipalId   = $assignment.PrincipalId
        PrincipalType = $principal.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.', ''
        RoleName      = $roleName
        AssignmentType = "Active (Permanent)"
        IsCritical    = $roleName -in $criticalRoles
        RoleDefinitionId = $assignment.RoleDefinitionId
    }
}

# PIM-eligible assignments (requires P2)
Write-Host "[*] Pulling PIM-eligible assignments..." -ForegroundColor Yellow
try {
    $eligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ExpandProperty Principal

    foreach ($assignment in $eligibleAssignments) {
        $roleName = $roleMap[$assignment.RoleDefinitionId]
        $principal = $assignment.Principal

        $allAssignments += [PSCustomObject]@{
            PrincipalName = $principal.AdditionalProperties.displayName
            PrincipalId   = $assignment.PrincipalId
            PrincipalType = $principal.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.', ''
            RoleName      = $roleName
            AssignmentType = "Eligible (PIM)"
            IsCritical    = $roleName -in $criticalRoles
            RoleDefinitionId = $assignment.RoleDefinitionId
        }
    }
} catch {
    Write-Host "  PIM data unavailable (requires Entra ID P2)" -ForegroundColor Yellow
}

# Analysis
$csvPath = Join-Path $reportDir "role_assignments.csv"
$allAssignments | Export-Csv -Path $csvPath -NoTypeInformation

$permanentAdmins = $allAssignments | Where-Object {
    $_.AssignmentType -eq "Active (Permanent)" -and $_.IsCritical
}
$eligibleAdmins = $allAssignments | Where-Object {
    $_.AssignmentType -eq "Eligible (PIM)" -and $_.IsCritical
}

# Users with multiple critical roles
$multiRole = $allAssignments | Where-Object IsCritical |
    Group-Object PrincipalId | Where-Object Count -gt 2

$report = @"
# Privileged Role Assignment Audit
## Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

## Summary
| Metric | Count |
|--------|-------|
| Total assignments | $($allAssignments.Count) |
| Permanent critical roles | $($permanentAdmins.Count) |
| PIM-eligible critical roles | $($eligibleAdmins.Count) |
| Users with 3+ critical roles | $($multiRole.Count) |

## Permanent Critical Role Assignments (Investigate)
$($permanentAdmins | ForEach-Object {
"- **$($_.PrincipalName)** — $($_.RoleName) [$($_.PrincipalType)]"
} | Out-String)

## Users with Multiple Critical Roles
$($multiRole | ForEach-Object {
    $user = $_.Name
    $roles = $allAssignments | Where-Object { $_.PrincipalId -eq $user -and $_.IsCritical }
"- **$($roles[0].PrincipalName)** ($($_.Count) roles): $(($roles | ForEach-Object { $_.RoleName }) -join ', ')"
} | Out-String)

## Recommendations
1. Convert permanent Global Admin assignments to PIM-eligible
2. Investigate users with 3+ critical roles — consolidate or separate duties
3. Review service principal role assignments (PrincipalType = servicePrincipal)
4. Ensure at least 2 (no more than 4) break-glass accounts with permanent Global Admin
"@

$reportPath = Join-Path $reportDir "role_audit_report.md"
$report | Out-File -FilePath $reportPath -Encoding UTF8

Write-Host "`n[✓] Audit complete" -ForegroundColor Green
Write-Host "  Permanent critical: $($permanentAdmins.Count) | PIM eligible: $($eligibleAdmins.Count)"
Write-Host "  Multi-role users: $($multiRole.Count)"
Write-Host "  Report: $reportPath"
