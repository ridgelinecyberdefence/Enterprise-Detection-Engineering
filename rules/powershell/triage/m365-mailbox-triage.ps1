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
