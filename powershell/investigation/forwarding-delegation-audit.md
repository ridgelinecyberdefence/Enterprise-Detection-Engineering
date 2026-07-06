# Mail Forwarding and Delegation Audit

Enumerates every mailbox forwarding rule, inbox rule with forwarding actions, mail flow transport rules, delegate permissions, and SMTP forwarding across the tenant. Forwarding is the BEC persistence mechanism that survives account remediation. The attacker's inbox rule silently copies every inbound email to an external address while you're busy resetting passwords.

## ATT&CK Relevance

Supports investigation of:
- T1114.003 - Email Collection: Email Forwarding Rule
- T1564.008 - Hide Artifacts: Email Hiding Rules
- T1098 - Account Manipulation (delegate access persistence)

## Use Case

Post-BEC containment. You've reset the compromised account's password and revoked sessions. But the attacker set up forwarding to an external mailbox during the first 10 minutes of access. Every email this user receives. Including password reset confirmations, MFA enrollment notifications, and sensitive business communications, is being copied to the attacker's inbox. This script finds every forwarding mechanism across every mailbox.

## Prerequisites

- Exchange Online PowerShell V3: `Install-Module ExchangeOnlineManagement`
- Exchange Admin role or Global Reader + Exchange recipient scope
- Connect: `Connect-ExchangeOnline -UserPrincipalName admin@contoso.com`

## Script

```powershell
<#
.SYNOPSIS
    Audit all mail forwarding, inbox rules, and delegate access across the tenant.
.DESCRIPTION
    Checks five forwarding vectors: SMTP forwarding, inbox rules with forwarding,
    mailbox forwarding (ForwardingAddress/ForwardingSMTPAddress), transport rules,
    and delegate/full access permissions. Produces a risk-scored CSV and summary.
.PARAMETER OutputPath
    Directory for the audit output.
.PARAMETER TargetMailbox
    Optional: audit a single mailbox instead of the entire tenant.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = ".",
    [string]$TargetMailbox
)

$ErrorActionPreference = 'Stop'
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportDir = Join-Path $OutputPath "ForwardingAudit_$timestamp"
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null

Write-Host "[*] Mail Forwarding and Delegation Audit" -ForegroundColor Cyan

$allFindings = @()

# --- 1. Mailbox-Level Forwarding ---
Write-Host "[*] Checking mailbox-level forwarding..." -ForegroundColor Yellow

$mailboxFilter = if ($TargetMailbox) {
    Get-Mailbox -Identity $TargetMailbox
} else {
    Get-Mailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox
}

foreach ($mbx in $mailboxFilter) {
    # ForwardingAddress (internal)
    if ($mbx.ForwardingAddress) {
        $allFindings += [PSCustomObject]@{
            Type        = "Mailbox Forwarding (Internal)"
            Mailbox     = $mbx.UserPrincipalName
            Target      = $mbx.ForwardingAddress
            External    = $false
            DeliverCopy = $mbx.DeliverToMailboxAndForward
            Rule        = "N/A"
            RiskScore   = 3
        }
    }

    # ForwardingSMTPAddress (external)
    if ($mbx.ForwardingSmtpAddress) {
        $isExternal = $mbx.ForwardingSmtpAddress -notmatch [regex]::Escape($mbx.UserPrincipalName.Split("@")[1])
        $allFindings += [PSCustomObject]@{
            Type        = "SMTP Forwarding"
            Mailbox     = $mbx.UserPrincipalName
            Target      = $mbx.ForwardingSmtpAddress
            External    = $isExternal
            DeliverCopy = $mbx.DeliverToMailboxAndForward
            Rule        = "N/A"
            RiskScore   = if ($isExternal) { 8 } else { 3 }
        }
    }
}

# --- 2. Inbox Rules with Forwarding ---
Write-Host "[*] Checking inbox rules..." -ForegroundColor Yellow

foreach ($mbx in $mailboxFilter) {
    $rules = Get-InboxRule -Mailbox $mbx.UserPrincipalName -ErrorAction SilentlyContinue

    foreach ($rule in $rules) {
        $isForwarding = $false
        $target = @()
        $riskScore = 0
        $riskFlags = @()

        if ($rule.ForwardTo) {
            $isForwarding = $true
            $target += $rule.ForwardTo
        }
        if ($rule.ForwardAsAttachmentTo) {
            $isForwarding = $true
            $target += $rule.ForwardAsAttachmentTo
            $riskFlags += "ForwardAsAttachment"
        }
        if ($rule.RedirectTo) {
            $isForwarding = $true
            $target += $rule.RedirectTo
            $riskFlags += "Redirect (no local copy)"
        }

        # Check for hiding behavior (mark as read + move to deleted/RSS)
        if ($rule.MarkAsRead -or
            $rule.MoveToFolder -match "Deleted|RSS|Archive|Junk" -or
            $rule.DeleteMessage) {
            $riskFlags += "Hiding behavior"
            $riskScore += 3
        }

        if ($isForwarding) {
            $targetStr = ($target | ForEach-Object { $_.ToString() }) -join "; "
            $domain = $mbx.UserPrincipalName.Split("@")[1]
            $isExternal = $targetStr -notmatch [regex]::Escape($domain)

            $riskScore += if ($isExternal) { 6 } else { 2 }
            if (-not $rule.Enabled) { $riskScore -= 2 }

            $allFindings += [PSCustomObject]@{
                Type        = "Inbox Rule"
                Mailbox     = $mbx.UserPrincipalName
                Target      = $targetStr
                External    = $isExternal
                DeliverCopy = -not ($rule.RedirectTo)
                Rule        = "$($rule.Name) [Enabled: $($rule.Enabled)]$(if ($riskFlags) { " | Flags: $($riskFlags -join ', ')" })"
                RiskScore   = [math]::Min($riskScore, 10)
            }
        }
    }
}

# --- 3. Transport Rules ---
Write-Host "[*] Checking transport rules..." -ForegroundColor Yellow

$transportRules = Get-TransportRule -ResultSize Unlimited -ErrorAction SilentlyContinue

foreach ($rule in $transportRules) {
    $hasForwarding = $false
    $target = @()

    if ($rule.BlindCopyTo) {
        $hasForwarding = $true
        $target += $rule.BlindCopyTo
    }
    if ($rule.CopyTo) {
        $hasForwarding = $true
        $target += $rule.CopyTo
    }
    if ($rule.RedirectMessageTo) {
        $hasForwarding = $true
        $target += $rule.RedirectMessageTo
    }

    if ($hasForwarding) {
        $targetStr = ($target | ForEach-Object { $_.ToString() }) -join "; "

        $allFindings += [PSCustomObject]@{
            Type        = "Transport Rule"
            Mailbox     = "(Tenant-wide)"
            Target      = $targetStr
            External    = $true
            DeliverCopy = $true
            Rule        = "$($rule.Name) [State: $($rule.State)] Priority: $($rule.Priority)"
            RiskScore   = 7
        }
    }
}

# --- 4. Delegate Access ---
Write-Host "[*] Checking delegate permissions..." -ForegroundColor Yellow

foreach ($mbx in $mailboxFilter) {
    $permissions = Get-MailboxPermission -Identity $mbx.UserPrincipalName -ErrorAction SilentlyContinue |
        Where-Object {
            $_.User -ne "NT AUTHORITY\SELF" -and
            $_.IsInherited -eq $false -and
            $_.AccessRights -contains "FullAccess"
        }

    foreach ($perm in $permissions) {
        $allFindings += [PSCustomObject]@{
            Type        = "Full Access Delegate"
            Mailbox     = $mbx.UserPrincipalName
            Target      = $perm.User
            External    = $false
            DeliverCopy = $true
            Rule        = "FullAccess (non-inherited)"
            RiskScore   = 4
        }
    }

    # SendAs
    $sendAs = Get-RecipientPermission -Identity $mbx.UserPrincipalName -ErrorAction SilentlyContinue |
        Where-Object { $_.Trustee -ne "NT AUTHORITY\SELF" }

    foreach ($sa in $sendAs) {
        $allFindings += [PSCustomObject]@{
            Type        = "Send As Permission"
            Mailbox     = $mbx.UserPrincipalName
            Target      = $sa.Trustee
            External    = $false
            DeliverCopy = $true
            Rule        = "SendAs"
            RiskScore   = 5
        }
    }
}

# --- Output ---
$allFindings = $allFindings | Sort-Object RiskScore -Descending

$csvPath = Join-Path $reportDir "forwarding_findings.csv"
$allFindings | Export-Csv -Path $csvPath -NoTypeInformation

$externalForwarding = ($allFindings | Where-Object External -eq $true).Count
$highRisk = ($allFindings | Where-Object { $_.RiskScore -ge 6 }).Count

$report = @"
# Mail Forwarding and Delegation Audit
## Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
$(if ($TargetMailbox) { "## Target: $TargetMailbox" } else { "## Scope: Tenant-wide" })

## Summary

| Category | Count |
|----------|-------|
| Total findings | $($allFindings.Count) |
| External forwarding | $externalForwarding |
| High risk (score >= 6) | $highRisk |

## Findings by Type

| Type | Count |
|------|-------|
$($allFindings | Group-Object Type | ForEach-Object { "| $($_.Name) | $($_.Count) |" } | Out-String)

## High Risk Findings (Score >= 6)

$($allFindings | Where-Object { $_.RiskScore -ge 6 } | ForEach-Object {
"- [$($_.RiskScore)/10] **$($_.Mailbox)** → $($_.Target)
  Type: $($_.Type) | External: $($_.External)
  Detail: $($_.Rule)"
} | Out-String)

## Recommended Actions

1. Investigate all external forwarding immediately (Type: SMTP Forwarding or Inbox Rule with External = True)
2. Verify transport rules with BCC/redirect actions are business-approved
3. Review inbox rules with hiding behavior (MarkAsRead + MoveToFolder) — classic BEC persistence
4. Audit FullAccess delegate permissions — these allow reading another user's email without forwarding
5. Consider implementing an outbound forwarding block via transport rule
"@

$reportPath = Join-Path $reportDir "audit_report.md"
$report | Out-File -FilePath $reportPath -Encoding UTF8

Write-Host "`n[✓] Audit complete" -ForegroundColor Green
Write-Host "  Findings: $($allFindings.Count) total, $externalForwarding external, $highRisk high-risk"
Write-Host "  Report: $reportPath"
```

## Usage

```powershell
# Tenant-wide audit
Connect-ExchangeOnline -UserPrincipalName admin@contoso.com
.\Invoke-ForwardingAudit.ps1 -OutputPath "D:\Investigations"

# Single mailbox (post-compromise)
.\Invoke-ForwardingAudit.ps1 -TargetMailbox "compromised.user@contoso.com"
```

## Five Forwarding Vectors

| Vector | Where It's Set | Survives Password Reset? | Visible to User? |
|--------|---------------|--------------------------|-------------------|
| SMTP Forwarding | Mailbox properties | Yes | No (admin only) |
| Inbox Rule | User's mailbox rules | Yes | Yes (if user checks) |
| Transport Rule | Exchange admin center | Yes | No (admin only) |
| FullAccess Delegate | Mailbox permissions | Yes | No |
| ForwardingAddress | Mailbox properties | Yes | No (admin only) |

All five vectors survive a password reset and MFA re-enrollment. This is why forwarding audit is mandatory in every BEC investigation, containment doesn't remove forwarding.

## Limitations

- Tenant-wide mailbox enumeration is slow for large tenants (10,000+ mailboxes). For incident response, use `-TargetMailbox` for the compromised accounts and run tenant-wide as a scheduled audit.
- Inbox rules are per-mailbox. No bulk API to pull all rules across all mailboxes. Each mailbox requires a separate `Get-InboxRule` call.
- The script doesn't check for Power Automate flows that forward email. These require a separate audit via the Power Automate admin API.

## Learn More

- [Incident Triage and First Response](https://ridgelinecyber.com/training/courses/incident-triage-first-response/). BEC investigation procedures including forwarding analysis
- [SOC Operations: Email Security](https://ridgelinecyber.com/training/courses/m365-security-operations/). email threat detection and response workflows
- [M365 Security Architecture: Email Protection](https://ridgelinecyber.com/training/courses/m365-security-architecture/). transport rule architecture and forwarding controls
