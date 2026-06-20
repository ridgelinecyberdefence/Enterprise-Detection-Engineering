# Entra ID Compromise Assessment — Post-Incident Audit

Comprehensive assessment of an Entra ID tenant after a suspected compromise. Checks for attacker persistence across OAuth applications, Conditional Access modifications, privileged role assignments, inbox rules, and service principal credentials. Run this after containing the initial incident to identify persistence mechanisms the attacker planted.

## Use Case

You've confirmed an account compromise (AiTM, credential stuffing, or token theft). The user's password is reset, sessions are revoked, MFA is re-enrolled. But attackers plant persistence before you respond — OAuth consent grants, service principal credentials, modified CA policies, inbox forwarding rules. This script finds all of them.

## Requirements

- PowerShell 7+ with Microsoft Graph PowerShell SDK (`Microsoft.Graph` module)
- Global Reader or Security Reader role (read-only — the script does not modify anything)
- Exchange Online Management module for inbox rule audit

## Script

```powershell
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Applications, ExchangeOnlineManagement

<#
.SYNOPSIS
    Post-compromise assessment for Entra ID tenant.
    Read-only audit — does not modify any configuration.
.PARAMETER CompromisedUser
    UPN of the compromised user account.
.PARAMETER DaysBack
    Number of days to look back for suspicious activity. Default: 30.
.NOTES
    Ridgeline Cyber — https://ridgelinecyber.com/training
#>

param(
    [Parameter(Mandatory)]
    [string]$CompromisedUser,
    [int]$DaysBack = 30
)

$ErrorActionPreference = 'Stop'
$lookback = (Get-Date).AddDays(-$DaysBack)

# --- Connect ---
Write-Host "`n[*] Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All", "Application.Read.All", "User.Read.All" -NoWelcome
Write-Host "[*] Connecting to Exchange Online..." -ForegroundColor Cyan
Connect-ExchangeOnline -ShowBanner:$false

$findings = @()
function Add-Finding {
    param([string]$Category, [string]$Severity, [string]$Detail)
    $script:findings += [PSCustomObject]@{
        Category = $Category
        Severity = $Severity
        Detail   = $Detail
        Time     = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    }
    $color = switch ($Severity) { 'Critical' { 'Red' } 'High' { 'Yellow' } 'Medium' { 'Cyan' } default { 'Gray' } }
    Write-Host "  [$Severity] $Category: $Detail" -ForegroundColor $color
}

# === CHECK 1: OAuth Application Consent Grants ===
Write-Host "`n=== OAuth Consent Grants ===" -ForegroundColor White
$oauthGrants = Get-MgUserOauth2PermissionGrant -UserId $CompromisedUser -All
$riskyScopes = @('Mail.ReadWrite', 'Mail.Send', 'Files.ReadWrite.All',
    'Sites.ReadWrite.All', 'User.ReadWrite.All', 'Directory.ReadWrite.All',
    'Application.ReadWrite.All', 'RoleManagement.ReadWrite.Directory')

foreach ($grant in $oauthGrants) {
    $scopes = $grant.Scope -split ' '
    $riskyMatches = $scopes | Where-Object { $_ -in $riskyScopes }
    if ($riskyMatches) {
        $app = Get-MgServicePrincipal -ServicePrincipalId $grant.ClientId -ErrorAction SilentlyContinue
        $appName = if ($app) { $app.DisplayName } else { $grant.ClientId }
        Add-Finding "OAuth Consent" "Critical" "App '$appName' has risky scopes: $($riskyMatches -join ', ')"
    }
}
if (-not $oauthGrants) { Write-Host "  No OAuth grants found." -ForegroundColor Green }

# === CHECK 2: Inbox Rules (Forwarding, Deleting, Hiding) ===
Write-Host "`n=== Inbox Rules ===" -ForegroundColor White
$rules = Get-InboxRule -Mailbox $CompromisedUser -IncludeHidden

foreach ($rule in $rules) {
    if ($rule.ForwardTo -or $rule.ForwardAsAttachmentTo -or $rule.RedirectTo) {
        $target = ($rule.ForwardTo + $rule.ForwardAsAttachmentTo + $rule.RedirectTo) -join ', '
        Add-Finding "Inbox Rule" "Critical" "Rule '$($rule.Name)' forwards to: $target"
    }
    if ($rule.DeleteMessage) {
        Add-Finding "Inbox Rule" "High" "Rule '$($rule.Name)' deletes messages matching: $($rule.SubjectContainsWords -join ', ') $($rule.BodyContainsWords -join ', ')"
    }
    if ($rule.MoveToFolder -and $rule.MoveToFolder -in @('Deleted Items', 'RSS Feeds', 'Conversation History', 'Junk Email')) {
        Add-Finding "Inbox Rule" "High" "Rule '$($rule.Name)' moves to '$($rule.MoveToFolder)' (hiding)"
    }
}
if (-not $rules) { Write-Host "  No inbox rules found." -ForegroundColor Green }

# === CHECK 3: Transport Rules (Organization-Level) ===
Write-Host "`n=== Transport Rules (Org-Level) ===" -ForegroundColor White
$transportRules = Get-TransportRule | Where-Object {
    $_.State -eq 'Enabled' -and
    ($_.BlindCopyTo -or $_.RedirectMessageTo -or $_.RemoveHeader)
}
foreach ($tr in $transportRules) {
    Add-Finding "Transport Rule" "Critical" "Rule '$($tr.Name)' — BCC: $($tr.BlindCopyTo), Redirect: $($tr.RedirectMessageTo)"
}
if (-not $transportRules) { Write-Host "  No suspicious transport rules." -ForegroundColor Green }

# === CHECK 4: Privileged Role Assignments (Last N Days) ===
Write-Host "`n=== Recent Privileged Role Changes ===" -ForegroundColor White
$dangerousRoles = @('Global Administrator', 'Privileged Role Administrator',
    'Security Administrator', 'Exchange Administrator', 'Application Administrator',
    'Cloud Application Administrator', 'User Administrator')

$roleAssignments = Get-MgAuditLogDirectoryAudit -Filter "activityDateTime ge $($lookback.ToString('yyyy-MM-ddTHH:mm:ssZ')) and (activityDisplayName eq 'Add member to role' or activityDisplayName eq 'Add member to role outside of PIM')" -All

foreach ($event in $roleAssignments) {
    $roleName = $event.TargetResources[0].DisplayName
    if ($roleName -in $dangerousRoles) {
        $targetUser = $event.TargetResources | Where-Object { $_.Type -eq 'User' } | Select-Object -ExpandProperty UserPrincipalName -ErrorAction SilentlyContinue
        $initiator = $event.InitiatedBy.User.UserPrincipalName
        Add-Finding "Role Assignment" "Critical" "$roleName assigned to $targetUser by $initiator at $($event.ActivityDateTime)"
    }
}

# === CHECK 5: Application Credential Additions (Last N Days) ===
Write-Host "`n=== Recent App Credential Additions ===" -ForegroundColor White
$credEvents = Get-MgAuditLogDirectoryAudit -Filter "activityDateTime ge $($lookback.ToString('yyyy-MM-ddTHH:mm:ssZ')) and (activityDisplayName eq 'Add service principal credentials' or activityDisplayName eq 'Update application – Certificates and secrets management')" -All

foreach ($event in $credEvents) {
    $appName = $event.TargetResources[0].DisplayName
    $initiator = if ($event.InitiatedBy.User) { $event.InitiatedBy.User.UserPrincipalName } else { $event.InitiatedBy.App.DisplayName }
    Add-Finding "App Credential" "High" "Credential added to '$appName' by $initiator at $($event.ActivityDateTime)"
}

# === CHECK 6: Conditional Access Policy Changes (Last N Days) ===
Write-Host "`n=== CA Policy Changes ===" -ForegroundColor White
$caEvents = Get-MgAuditLogDirectoryAudit -Filter "activityDateTime ge $($lookback.ToString('yyyy-MM-ddTHH:mm:ssZ')) and activityDisplayName eq 'Update conditional access policy'" -All

foreach ($event in $caEvents) {
    $policyName = $event.TargetResources[0].DisplayName
    $initiator = $event.InitiatedBy.User.UserPrincipalName
    Add-Finding "CA Policy" "High" "Policy '$policyName' modified by $initiator at $($event.ActivityDateTime)"
}

# === CHECK 7: Mailbox Delegation ===
Write-Host "`n=== Mailbox Delegation ===" -ForegroundColor White
$delegates = Get-MailboxPermission -Identity $CompromisedUser |
    Where-Object { $_.User -ne 'NT AUTHORITY\SELF' -and $_.IsInherited -eq $false }

foreach ($d in $delegates) {
    Add-Finding "Mailbox Delegation" "High" "$($d.User) has $($d.AccessRights -join ', ') on $CompromisedUser mailbox"
}

$sendAs = Get-RecipientPermission -Identity $CompromisedUser |
    Where-Object { $_.Trustee -ne 'NT AUTHORITY\SELF' }

foreach ($s in $sendAs) {
    Add-Finding "Send-As Permission" "High" "$($s.Trustee) has SendAs on $CompromisedUser"
}

# === Summary ===
Write-Host "`n" + "=" * 60 -ForegroundColor White
Write-Host "ASSESSMENT COMPLETE — $CompromisedUser" -ForegroundColor White
Write-Host "=" * 60 -ForegroundColor White

$critical = ($findings | Where-Object { $_.Severity -eq 'Critical' }).Count
$high = ($findings | Where-Object { $_.Severity -eq 'High' }).Count
$medium = ($findings | Where-Object { $_.Severity -eq 'Medium' }).Count

Write-Host "  Critical: $critical" -ForegroundColor Red
Write-Host "  High:     $high" -ForegroundColor Yellow
Write-Host "  Medium:   $medium" -ForegroundColor Cyan
Write-Host "  Total:    $($findings.Count)" -ForegroundColor White

if ($findings.Count -gt 0) {
    $outFile = "EntraID-Assessment-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    $findings | Export-Csv -Path $outFile -NoTypeInformation
    Write-Host "`n  Findings exported to: $outFile" -ForegroundColor Cyan
}

Disconnect-MgGraph | Out-Null
Disconnect-ExchangeOnline -Confirm:$false | Out-Null
```

## What This Checks

| Check | What it finds | Attacker technique |
|---|---|---|
| OAuth consent grants | Applications with Mail.ReadWrite, Files.ReadWrite.All, Directory.ReadWrite.All | Consent phishing persistence (T1098.003) |
| Inbox rules | Forwarding, redirecting, or deleting email rules | BEC persistence, evidence hiding (T1114.003, T1564.008) |
| Transport rules | Organization-level BCC, redirect, or header manipulation | Tenant-wide email interception (T1114.003) |
| Privileged role assignments | Direct role assignments to dangerous roles (outside PIM) | Privilege escalation persistence (T1098) |
| Application credentials | Secrets or certificates added to service principals | Application-level persistence (T1098.001) |
| CA policy changes | Conditional Access policies weakened or disabled | Defense evasion (T1562.001) |
| Mailbox delegation | FullAccess, SendAs, or SendOnBehalf permissions | Persistent mailbox access (T1114) |

## When to Run This

1. **After confirming any account compromise.** Run against the compromised UPN before closing the incident. Attackers plant persistence in the first minutes of access.
2. **After an AiTM phishing campaign.** Run against every user who clicked the phishing link, not just the ones with confirmed sign-ins.
3. **Periodic tenant audit.** Run monthly against a list of privileged accounts to catch persistence that initial detection missed.

## Operational Notes

- **Read-only.** The script does not modify any configuration. It reads audit logs, inbox rules, permissions, and CA policies. Safe to run at any time.
- **Graph permissions required.** The connecting user needs `AuditLog.Read.All`, `Directory.Read.All`, `Application.Read.All`, `User.Read.All` — all read-only scopes. Global Reader role satisfies all of these.
- **Output.** Findings are printed to console with severity coloring and exported to CSV for inclusion in incident reports.

## Learn More

- [Entra ID Security](https://ridgelinecyber.com/training/courses/entra-id-security/) — application governance, consent framework, and identity threat detection
- [SOC Operations — Investigation Playbook Framework](https://ridgelinecyber.com/training/courses/m365-security-operations/) — post-compromise assessment methodology
- [Practical Incident Response](https://ridgelinecyber.com/training/courses/practical-ir/) — full incident response workflow including containment verification
