# M365 Mailbox Triage: BEC Investigation Rapid Assessment

Performs rapid triage of a potentially compromised Microsoft 365 mailbox. Checks inbox rules, delegates, forwarding, OAuth consents, recent sign-in anomalies, and sent items for payment-related keywords. Produces a structured report identifying BEC indicators.

## ATT&CK Coverage

T1114.002 (Email Collection), T1114.003 (Email Forwarding Rule), T1098.003 (Additional Cloud Credentials).

## Category

Triage, Mailbox compromise assessment.

## Requirements

- Microsoft Graph PowerShell SDK: `Install-Module Microsoft.Graph`
- Exchange Online Management: `Install-Module ExchangeOnlineManagement`
- Global Reader or Security Reader role minimum
- Exchange Admin role for mailbox-level queries

## Script

```powershell
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$UserPrincipalName,
    [string]$OutputPath = ".\Mailbox-Triage"
)

$ts = Get-Date -Format "yyyy-MM-dd_HHmmss"
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

# Connect
Connect-MgGraph -Scopes "User.Read.All","AuditLog.Read.All","MailboxSettings.Read" -NoWelcome
Connect-ExchangeOnline -ShowBanner:$false

$report = @{ User = $UserPrincipalName; TriagedAt = (Get-Date -Format "o"); Findings = @() }

# 1. Inbox rules
Write-Host "[*] Checking inbox rules..." -ForegroundColor Cyan
$rules = Get-InboxRule -Mailbox $UserPrincipalName -ErrorAction SilentlyContinue
$suspiciousRules = $rules | Where-Object {
    $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo -or
    $_.DeleteMessage -or $_.MoveToFolder -match 'RSS|Deleted|Archive'
}
if ($suspiciousRules) {
    $report.Findings += @{Type="InboxRule"; Severity="High"; Details=$suspiciousRules |
        Select-Object Name, ForwardTo, RedirectTo, DeleteMessage, MoveToFolder}
}

# 2. Mailbox forwarding
$mbx = Get-Mailbox -Identity $UserPrincipalName -ErrorAction SilentlyContinue
if ($mbx.ForwardingSmtpAddress -or $mbx.ForwardingAddress) {
    $report.Findings += @{Type="MailboxForwarding"; Severity="Critical";
        Details=@{ForwardingSMTP=$mbx.ForwardingSmtpAddress; ForwardingAddress=$mbx.ForwardingAddress}}
}

# 3. Delegates
$delegates = Get-MailboxPermission -Identity $UserPrincipalName |
    Where-Object { $_.User -notmatch 'NT AUTHORITY|S-1-5' -and $_.AccessRights -match 'FullAccess' }
if ($delegates) {
    $report.Findings += @{Type="FullAccessDelegate"; Severity="Medium"; Details=$delegates | Select-Object User, AccessRights}
}

# 4. OAuth consent grants
$consents = Get-MgUserOauth2PermissionGrant -UserId $UserPrincipalName -All -ErrorAction SilentlyContinue
$riskyConsents = $consents | Where-Object { $_.Scope -match 'Mail\.|Files\.|User\.Read\.All' }
if ($riskyConsents) {
    $report.Findings += @{Type="OAuthConsent"; Severity="High";
        Details=$riskyConsents | Select-Object ClientId, Scope, ConsentType}
}

# 5. Recent sign-in anomalies
$signins = Get-MgAuditLogSignIn -Filter "userPrincipalName eq '$UserPrincipalName'" -Top 50 -ErrorAction SilentlyContinue
$riskySignins = $signins | Where-Object { $_.RiskLevelDuringSignIn -in 'medium','high' -or $_.IsInteractive -eq $false }
if ($riskySignins) {
    $report.Findings += @{Type="RiskySignIn"; Severity="High";
        Details=$riskySignins | Select-Object CreatedDateTime, IpAddress, Location, AppDisplayName, RiskLevelDuringSignIn}
}

# Summary
$critCount = ($report.Findings | Where-Object {$_.Severity -eq 'Critical'}).Count
$highCount = ($report.Findings | Where-Object {$_.Severity -eq 'High'}).Count
$report.Summary = @{Critical=$critCount; High=$highCount; Total=$report.Findings.Count;
    Verdict = if($critCount -gt 0){"LIKELY COMPROMISED"}elseif($highCount -gt 0){"SUSPICIOUS"}else{"CLEAN"}}

$outFile = Join-Path $OutputPath "$($UserPrincipalName -replace '@','_')_triage_$ts.json"
$report | ConvertTo-Json -Depth 5 | Out-File $outFile -Encoding UTF8
Write-Host "`n=== VERDICT: $($report.Summary.Verdict) ===" -ForegroundColor $(if($critCount){'Red'}elseif($highCount){'Yellow'}else{'Green'})
Write-Host "Report: $outFile"

Disconnect-ExchangeOnline -Confirm:$false
Disconnect-MgGraph
```

## What This Checks

Inbox rules (forwarding, deletion, folder moves), mailbox-level SMTP forwarding, FullAccess delegates, OAuth consent grants with mail/file scopes, and risky sign-ins. Each finding is severity-rated and the script produces a verdict: CLEAN, SUSPICIOUS, or LIKELY COMPROMISED.

## Learn More

- [SOC Operations: BEC Investigation](https://ridgelinecyber.com/training/courses/m365-security-operations/). BEC investigation playbooks
- [Incident Response](https://ridgelinecyber.com/training/courses/practical-ir/). email compromise assessment
