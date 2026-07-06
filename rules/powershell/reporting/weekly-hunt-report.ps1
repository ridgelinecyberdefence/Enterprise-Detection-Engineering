<#
.SYNOPSIS
    Generate a weekly threat hunt report from Sentinel incidents and analytics rules.
.PARAMETER WorkspaceId
    Log Analytics Workspace ID.
.PARAMETER ResourceGroup
    Azure Resource Group containing the workspace.
.PARAMETER WorkspaceName
    Log Analytics Workspace name.
.PARAMETER DaysBack
    Reporting period in days. Default: 7.
.PARAMETER OutputPath
    Report output directory.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$WorkspaceId,

    [Parameter(Mandatory)]
    [string]$ResourceGroup,

    [Parameter(Mandatory)]
    [string]$WorkspaceName,

    [int]$DaysBack = 7,

    [string]$OutputPath = "."
)

$ErrorActionPreference = 'Stop'

Connect-AzAccount -ErrorAction SilentlyContinue | Out-Null

$timestamp = Get-Date -Format "yyyyMMdd"
$startDate = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-dd")
$endDate = (Get-Date).ToString("yyyy-MM-dd")
$reportPath = Join-Path $OutputPath "ThreatHuntReport_${startDate}_to_${endDate}.md"

Write-Host "[*] Generating threat hunt report ($startDate to $endDate)" -ForegroundColor Cyan

# Query Sentinel incidents
$incidentQuery = @"
SecurityIncident
| where CreatedTime >= ago(${DaysBack}d)
| summarize
    Count = count(),
    HighSev = countif(Severity == "High"),
    MedSev = countif(Severity == "Medium"),
    LowSev = countif(Severity == "Low"),
    Informational = countif(Severity == "Informational"),
    Closed = countif(Status == "Closed"),
    Active = countif(Status == "Active" or Status == "New"),
    TruePositive = countif(Classification == "TruePositive"),
    FalsePositive = countif(Classification == "FalsePositive"),
    BenignPositive = countif(Classification == "BenignPositive")
"@

$alertsByTactic = @"
SecurityAlert
| where TimeGenerated >= ago(${DaysBack}d)
| extend Tactics = parse_json(ExtendedProperties).Tactics
| mv-expand Tactic = split(tostring(Tactics), ",")
| summarize AlertCount = count() by tostring(Tactic)
| sort by AlertCount desc
"@

$topRules = @"
SecurityAlert
| where TimeGenerated >= ago(${DaysBack}d)
| summarize AlertCount = count(), Severities = make_set(AlertSeverity) by AlertName = DisplayName
| sort by AlertCount desc
| take 20
"@

$results = @{}

try {
    Write-Host "[*] Querying incident summary..." -ForegroundColor Yellow
    $results.Incidents = Invoke-AzOperationalInsightsQuery `
        -WorkspaceId $WorkspaceId -Query $incidentQuery

    Write-Host "[*] Querying alerts by tactic..." -ForegroundColor Yellow
    $results.Tactics = Invoke-AzOperationalInsightsQuery `
        -WorkspaceId $WorkspaceId -Query $alertsByTactic

    Write-Host "[*] Querying top detection rules..." -ForegroundColor Yellow
    $results.TopRules = Invoke-AzOperationalInsightsQuery `
        -WorkspaceId $WorkspaceId -Query $topRules
} catch {
    Write-Host "[!] Query failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  Generating template report without live data" -ForegroundColor Yellow
}

# Build report
$incident = if ($results.Incidents) { $results.Incidents.Results[0] } else { $null }

$report = @"
# Weekly Threat Hunt Report
## Period: $startDate to $endDate
## Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

---

## Executive Summary

$(if ($incident) {
"This week the SOC processed **$($incident.Count) incidents** ($($incident.HighSev) high, $($incident.MedSev) medium, $($incident.LowSev) low severity). Of these, **$($incident.TruePositive) were confirmed true positives**, $($incident.FalsePositive) false positives, and $($incident.BenignPositive) benign positive. **$($incident.Active) incidents remain active** and require continued investigation."
} else {
"[Populate with incident data from Sentinel]"
})

---

## Incident Summary

| Metric | Count |
|--------|-------|
$(if ($incident) {
"| Total incidents | $($incident.Count) |
| High severity | $($incident.HighSev) |
| Medium severity | $($incident.MedSev) |
| Low severity | $($incident.LowSev) |
| True positive | $($incident.TruePositive) |
| False positive | $($incident.FalsePositive) |
| Closed | $($incident.Closed) |
| Active/New | $($incident.Active) |"
} else {
"| [No data] | — |"
})

---

## Alerts by ATT&CK Tactic

$(if ($results.Tactics) {
    $results.Tactics.Results | ForEach-Object {
        "| $($_.Tactic) | $($_.AlertCount) |"
    } | Out-String
} else {
"| [No data] | — |"
})

---

## Top Detection Rules (by volume)

$(if ($results.TopRules) {
    $results.TopRules.Results | ForEach-Object {
        "- **$($_.AlertName)** — $($_.AlertCount) alerts [$($_.Severities -join ', ')]"
    } | Out-String
} else {
"[Populate from Sentinel analytics rules]"
})

---

## Hunt Hypotheses Tested

| Hypothesis | Data Sources | Findings | Status |
|-----------|-------------|----------|--------|
| [Describe hunt hypothesis] | [Data sources queried] | [Summary of findings] | Open/Closed |

---

## Recommendations

1. [Based on findings — specific, actionable, assigned]
2. [Detection gap identified → new rule to create]
3. [False positive tuning needed → which rule, what adjustment]

---

## Metrics

| KPI | This Week | Last Week | Trend |
|-----|-----------|-----------|-------|
| Mean time to detect (MTTD) | — | — | — |
| Mean time to respond (MTTR) | — | — | — |
| True positive rate | $(if ($incident -and [int]$incident.Count -gt 0) { "$([math]::Round([int]$incident.TruePositive / [int]$incident.Count * 100))%" } else { "—" }) | — | — |
| Detection rules active | — | — | — |
| Hunt hypotheses tested | — | — | — |
"@

$report | Out-File -FilePath $reportPath -Encoding UTF8

Write-Host "`n[✓] Report generated: $reportPath" -ForegroundColor Green
