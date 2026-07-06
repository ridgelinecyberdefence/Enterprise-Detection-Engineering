# Event Log Export: Targeted Security Log Collection

Exports Windows Security, Sysmon, PowerShell, and application event logs from local or remote endpoints with time-range filtering. Outputs EVTX files for forensic analysis or JSON for SIEM ingestion.

## Category

Collection, Evidence preservation.

## Requirements

- Administrative access to target endpoint
- PowerShell 5.1+
- For remote collection: WinRM enabled

## Script

```powershell
[CmdletBinding()]
param(
    [string]$ComputerName = $env:COMPUTERNAME,
    [int]$HoursBack = 24,
    [string]$OutputPath = ".\EventLog-Export",
    [string[]]$LogNames = @("Security","Microsoft-Windows-Sysmon/Operational",
        "Microsoft-Windows-PowerShell/Operational","System"),
    [switch]$JsonOutput
)

$ts = Get-Date -Format "yyyy-MM-dd_HHmmss"
$startTime = (Get-Date).AddHours(-$HoursBack)
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

foreach ($log in $LogNames) {
    $safeName = $log -replace '[/\\]','-'
    Write-Host "[*] Exporting $log from $ComputerName (last ${HoursBack}h)..." -ForegroundColor Cyan
    try {
        $events = Get-WinEvent -ComputerName $ComputerName -LogName $log -FilterHashtable @{
            StartTime = $startTime
        } -ErrorAction Stop

        if ($JsonOutput) {
            $outFile = Join-Path $OutputPath "${ComputerName}_${safeName}_$ts.json"
            $events | Select-Object TimeCreated, Id, LevelDisplayName, Message,
                @{N='EventData';E={$_.Properties | ForEach-Object {$_.Value}}} |
                ConvertTo-Json -Depth 3 | Out-File $outFile -Encoding UTF8
        } else {
            $outFile = Join-Path $OutputPath "${ComputerName}_${safeName}_$ts.evtx"
            $query = "*[System[TimeCreated[timediff(@SystemTime) <= $($HoursBack * 3600000)]]]"
            wevtutil epl $log $outFile /q:"$query" /r:$ComputerName 2>$null
            if (-not (Test-Path $outFile)) {
                # Fallback to XML export
                $outFile = $outFile -replace '\.evtx$','.xml'
                $events | Export-Clixml $outFile
            }
        }
        Write-Host "[+] $log: $($events.Count) events -> $outFile" -ForegroundColor Green
    } catch {
        Write-Host "[-] $log: $_" -ForegroundColor Red
    }
}
```

## Learn More

- [Incident Response](https://ridgelinecyber.com/training/courses/practical-ir/). evidence collection and preservation
- [Windows Forensics](https://ridgelinecyber.com/training/courses/windows-endpoint-investigation/). event log forensic analysis
