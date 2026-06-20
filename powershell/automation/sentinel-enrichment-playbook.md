# Sentinel Alert Enrichment Playbook

Accepts a Sentinel alert, extracts IOCs (IPs, domains, file hashes, usernames), enriches each against multiple threat intelligence sources, and outputs a structured enrichment report. Designed to run as a Logic App action or standalone during manual investigation. Reduces the "open five browser tabs" enrichment workflow to a single command.

## ATT&CK Relevance

Supports triage of alerts across all tactics by accelerating IOC enrichment.

## Prerequisites

- VirusTotal API key (free tier: 4 requests/min)
- AbuseIPDB API key (free tier: 1,000 checks/day)
- Microsoft Graph access for Entra ID user lookups
- Optional: Shodan API key for IP enrichment

## Script

```powershell
<#
.SYNOPSIS
    Enrich Sentinel alert IOCs against threat intelligence sources.
.PARAMETER AlertId
    Sentinel alert SystemAlertId.
.PARAMETER IPAddresses
    Manual: array of IPs to enrich (use without AlertId for ad hoc enrichment).
.PARAMETER FileHashes
    Manual: array of SHA256 hashes to enrich.
.PARAMETER VTApiKey
    VirusTotal API key.
.PARAMETER AbuseIPDBKey
    AbuseIPDB API key.
#>
[CmdletBinding()]
param(
    [string]$AlertId,
    [string[]]$IPAddresses,
    [string[]]$FileHashes,
    [string[]]$Domains,

    [Parameter(Mandatory)]
    [string]$VTApiKey,

    [string]$AbuseIPDBKey,

    [string]$OutputPath = "."
)

$ErrorActionPreference = 'Stop'
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportDir = Join-Path $OutputPath "Enrichment_$timestamp"
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null

# Rate limiting for free API tiers
function Invoke-RateLimitedRequest {
    param([scriptblock]$Request, [int]$DelayMs = 16000)
    try {
        $result = & $Request
        Start-Sleep -Milliseconds $DelayMs
        return $result
    } catch {
        Write-Host "    API error: $($_.Exception.Message)" -ForegroundColor Yellow
        return $null
    }
}

# --- VirusTotal IP Lookup ---
function Get-VTIPReport {
    param([string]$IP)
    $headers = @{ "x-apikey" = $VTApiKey }
    $response = Invoke-RateLimitedRequest {
        Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/ip_addresses/$IP" `
            -Headers $headers -Method Get
    }
    if ($response) {
        $stats = $response.data.attributes.last_analysis_stats
        return [PSCustomObject]@{
            IOC         = $IP
            Type        = "IP"
            Source      = "VirusTotal"
            Malicious   = $stats.malicious
            Suspicious  = $stats.suspicious
            Clean       = $stats.harmless + $stats.undetected
            Country     = $response.data.attributes.country
            ASOwner     = $response.data.attributes.as_owner
            Reputation  = $response.data.attributes.reputation
        }
    }
}

# --- VirusTotal Hash Lookup ---
function Get-VTHashReport {
    param([string]$Hash)
    $headers = @{ "x-apikey" = $VTApiKey }
    $response = Invoke-RateLimitedRequest {
        Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$Hash" `
            -Headers $headers -Method Get
    }
    if ($response) {
        $stats = $response.data.attributes.last_analysis_stats
        return [PSCustomObject]@{
            IOC        = $Hash
            Type       = "Hash"
            Source     = "VirusTotal"
            Malicious  = $stats.malicious
            Suspicious = $stats.suspicious
            Clean      = $stats.harmless + $stats.undetected
            FileName   = $response.data.attributes.meaningful_name
            FileType   = $response.data.attributes.type_description
            FileSize   = "$([math]::Round($response.data.attributes.size / 1KB, 1)) KB"
        }
    }
}

# --- AbuseIPDB Lookup ---
function Get-AbuseIPDBReport {
    param([string]$IP)
    if (-not $AbuseIPDBKey) { return $null }
    $headers = @{ "Key" = $AbuseIPDBKey; "Accept" = "application/json" }
    $response = Invoke-RateLimitedRequest -DelayMs 1000 {
        Invoke-RestMethod -Uri "https://api.abuseipdb.com/api/v2/check?ipAddress=$IP&maxAgeInDays=90" `
            -Headers $headers -Method Get
    }
    if ($response) {
        return [PSCustomObject]@{
            IOC            = $IP
            Type           = "IP"
            Source         = "AbuseIPDB"
            AbuseScore     = $response.data.abuseConfidenceScore
            TotalReports   = $response.data.totalReports
            ISP            = $response.data.isp
            Domain         = $response.data.domain
            CountryCode    = $response.data.countryCode
            UsageType      = $response.data.usageType
        }
    }
}

# --- VirusTotal Domain Lookup ---
function Get-VTDomainReport {
    param([string]$Domain)
    $headers = @{ "x-apikey" = $VTApiKey }
    $response = Invoke-RateLimitedRequest {
        Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/domains/$Domain" `
            -Headers $headers -Method Get
    }
    if ($response) {
        $stats = $response.data.attributes.last_analysis_stats
        return [PSCustomObject]@{
            IOC        = $Domain
            Type       = "Domain"
            Source     = "VirusTotal"
            Malicious  = $stats.malicious
            Suspicious = $stats.suspicious
            Clean      = $stats.harmless + $stats.undetected
            Registrar  = $response.data.attributes.registrar
            Creation   = $response.data.attributes.creation_date
        }
    }
}

# --- Run Enrichment ---
Write-Host "[*] IOC Enrichment" -ForegroundColor Cyan

$allResults = @()

# Enrich IPs
if ($IPAddresses) {
    Write-Host "`n[*] Enriching $($IPAddresses.Count) IP addresses..." -ForegroundColor Yellow
    foreach ($ip in $IPAddresses) {
        Write-Host "  Processing: $ip"
        $vtResult = Get-VTIPReport -IP $ip
        if ($vtResult) { $allResults += $vtResult }

        $abuseResult = Get-AbuseIPDBReport -IP $ip
        if ($abuseResult) { $allResults += $abuseResult }
    }
}

# Enrich hashes
if ($FileHashes) {
    Write-Host "`n[*] Enriching $($FileHashes.Count) file hashes..." -ForegroundColor Yellow
    foreach ($hash in $FileHashes) {
        Write-Host "  Processing: $($hash.Substring(0, 12))..."
        $vtResult = Get-VTHashReport -Hash $hash
        if ($vtResult) { $allResults += $vtResult }
    }
}

# Enrich domains
if ($Domains) {
    Write-Host "`n[*] Enriching $($Domains.Count) domains..." -ForegroundColor Yellow
    foreach ($domain in $Domains) {
        Write-Host "  Processing: $domain"
        $vtResult = Get-VTDomainReport -Domain $domain
        if ($vtResult) { $allResults += $vtResult }
    }
}

# Output
$csvPath = Join-Path $reportDir "enrichment_results.csv"
$allResults | Export-Csv -Path $csvPath -NoTypeInformation

# Summary report
$malicious = $allResults | Where-Object { $_.Malicious -gt 5 -or $_.AbuseScore -gt 50 }

$report = @"
# IOC Enrichment Report
## Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

## Summary
- Total IOCs enriched: $($IPAddresses.Count + $FileHashes.Count + $Domains.Count)
- Total enrichment results: $($allResults.Count)
- Confirmed malicious (VT > 5 or AbuseIPDB > 50): $($malicious.Count)

## Malicious IOCs
$($malicious | ForEach-Object {
"- **$($_.IOC)** [$($_.Type)] via $($_.Source): $(
    if ($_.Malicious) { "VT $($_.Malicious) detections" }
    elseif ($_.AbuseScore) { "Abuse score $($_.AbuseScore)%" }
)"
} | Out-String)

## All Results
$(($allResults | Format-Table -AutoSize | Out-String))
"@

$reportPath = Join-Path $reportDir "enrichment_report.md"
$report | Out-File -FilePath $reportPath -Encoding UTF8

Write-Host "`n[✓] Enrichment complete" -ForegroundColor Green
Write-Host "  Results: $($allResults.Count) enrichment records"
Write-Host "  Malicious: $($malicious.Count) confirmed"
Write-Host "  Report: $reportPath"
```

## Usage

```powershell
# Enrich IPs and hashes from an investigation
.\Invoke-IOCEnrichment.ps1 `
    -IPAddresses "185.234.72.19","91.215.85.200" `
    -FileHashes "a1b2c3d4e5f6..." `
    -Domains "evil-domain.com" `
    -VTApiKey "your-vt-api-key" `
    -AbuseIPDBKey "your-abuseipdb-key"
```

## Learn More

- [SOC Operations: Alert Enrichment](https://ridgelinecyber.com/training/courses/m365-security-operations/). enrichment workflows and threat intelligence integration
- [Threat Hunting: IOC Analysis](https://ridgelinecyber.com/training/courses/threat-hunting-m365/). IOC correlation and pivoting techniques
- [Detection Engineering: Threat Intelligence](https://ridgelinecyber.com/training/courses/detection-engineering/). TI-driven detection rule creation
