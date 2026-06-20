# KAPE Remote Evidence Collection Launcher

Deploys KAPE to remote Windows endpoints over SMB, executes a triage collection targeting forensic artifacts, and retrieves the output to a central evidence server. Designed for incident response scenarios where you need forensic triage from 5-50 endpoints without deploying an EDR agent or physically touching each machine.

## ATT&CK Relevance

Supports investigation of:
- T1078 — Valid Accounts (credential compromise scope assessment)
- T1570 — Lateral Movement Tool Transfer (identify compromised endpoints)
- T1059 — Command and Script Interpreter (scope of execution)

## Use Case

Your SOC has confirmed a compromised account. Sign-in logs show the account authenticated to 12 endpoints in the last 48 hours. You need triage artifacts from all 12 to determine which ones the attacker actually touched vs. which were legitimate user sessions. KAPE provides standardized forensic collection; this script automates deploying it at scale.

## Prerequisites

- KAPE binary package (kape.exe + targets + modules) in a network-accessible share
- Administrative credentials on target endpoints (domain admin or local admin)
- SMB access to target endpoints (TCP 445)
- PowerShell 5.1+ on the collection host
- Sufficient storage on the evidence server (estimate 500MB-2GB per endpoint for !SANS_Triage)

## Script

```powershell
<#
.SYNOPSIS
    Deploy KAPE to remote endpoints, run triage collection, retrieve results.
.DESCRIPTION
    Copies KAPE to each target via SMB admin share, executes a triage
    collection using the !SANS_Triage target, and pulls the output back
    to a central evidence directory. Each endpoint's evidence is stored
    in a timestamped, case-numbered directory.
.PARAMETER Targets
    Array of hostnames or IP addresses to collect from.
.PARAMETER CaseNumber
    Incident or case identifier for evidence organization.
.PARAMETER KAPESource
    UNC path to the KAPE binary package directory.
.PARAMETER EvidenceRoot
    Local or UNC path where collected evidence will be stored.
.PARAMETER TargetName
    KAPE target configuration to use. Default: !SANS_Triage
.PARAMETER Credential
    PSCredential for remote access. Prompts if not provided.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string[]]$Targets,

    [Parameter(Mandatory)]
    [string]$CaseNumber,

    [string]$KAPESource = "\\<fileserver>\tools\KAPE",

    [string]$EvidenceRoot = "D:\Evidence",

    [string]$TargetName = "!SANS_Triage",

    [PSCredential]$Credential
)

$ErrorActionPreference = 'Stop'
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

if (-not $Credential) {
    $Credential = Get-Credential -Message "Enter admin credentials for remote endpoints"
}

# Validate KAPE source exists
if (-not (Test-Path "$KAPESource\kape.exe")) {
    throw "KAPE not found at $KAPESource\kape.exe"
}

# Create case evidence directory
$caseDir = Join-Path $EvidenceRoot "$CaseNumber`_$timestamp"
New-Item -ItemType Directory -Path $caseDir -Force | Out-Null

# Collection log
$logPath = Join-Path $caseDir "collection_log.txt"
function Write-Log {
    param([string]$Message)
    $entry = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Write-Host $entry
    Add-Content -Path $logPath -Value $entry
}

Write-Log "Case: $CaseNumber | Targets: $($Targets.Count) | KAPE Target: $TargetName"

$results = @()

foreach ($target in $Targets) {
    Write-Log "--- Processing $target ---"

    $result = [PSCustomObject]@{
        Hostname    = $target
        Status      = "Pending"
        StartTime   = Get-Date
        EndTime     = $null
        ArtifactSize = $null
        Error       = $null
    }

    try {
        # Test connectivity
        if (-not (Test-Connection -ComputerName $target -Count 1 -Quiet)) {
            throw "Host unreachable"
        }

        # Create remote working directory
        $remoteKAPE = "\\$target\C$\Windows\Temp\KAPE_IR"
        $remoteOutput = "\\$target\C$\Windows\Temp\KAPE_Output"

        Write-Log "Deploying KAPE to $target"
        if (Test-Path $remoteKAPE) {
            Remove-Item -Path $remoteKAPE -Recurse -Force
        }
        Copy-Item -Path $KAPESource -Destination $remoteKAPE -Recurse -Force

        # Execute KAPE remotely
        Write-Log "Running KAPE on $target (target: $TargetName)"
        $kapeCmd = "C:\Windows\Temp\KAPE_IR\kape.exe " +
            "--tsource C: " +
            "--tdest C:\Windows\Temp\KAPE_Output " +
            "--target $TargetName " +
            "--vhdx $($target)_$timestamp " +
            "--zv false"

        $invokeResult = Invoke-Command -ComputerName $target -Credential $Credential -ScriptBlock {
            param($cmd)
            $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $cmd" `
                -Wait -PassThru -NoNewWindow -RedirectStandardOutput "C:\Windows\Temp\kape_stdout.txt" `
                -RedirectStandardError "C:\Windows\Temp\kape_stderr.txt"
            return @{
                ExitCode = $process.ExitCode
                StdOut   = Get-Content "C:\Windows\Temp\kape_stdout.txt" -ErrorAction SilentlyContinue
                StdErr   = Get-Content "C:\Windows\Temp\kape_stderr.txt" -ErrorAction SilentlyContinue
            }
        } -ArgumentList $kapeCmd

        if ($invokeResult.ExitCode -ne 0) {
            throw "KAPE exited with code $($invokeResult.ExitCode): $($invokeResult.StdErr -join ' ')"
        }

        # Retrieve evidence
        $endpointDir = Join-Path $caseDir $target
        New-Item -ItemType Directory -Path $endpointDir -Force | Out-Null

        Write-Log "Retrieving evidence from $target"
        Copy-Item -Path "$remoteOutput\*" -Destination $endpointDir -Recurse -Force

        # Calculate size
        $size = (Get-ChildItem -Path $endpointDir -Recurse | Measure-Object -Property Length -Sum).Sum
        $sizeMB = [math]::Round($size / 1MB, 2)

        # Clean up remote artifacts
        Write-Log "Cleaning up $target"
        Remove-Item -Path $remoteKAPE -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $remoteOutput -Recurse -Force -ErrorAction SilentlyContinue

        $result.Status = "Complete"
        $result.ArtifactSize = "$sizeMB MB"
        Write-Log "SUCCESS: $target — $sizeMB MB collected"
    }
    catch {
        $result.Status = "Failed"
        $result.Error = $_.Exception.Message
        Write-Log "FAILED: $target — $($_.Exception.Message)"
    }
    finally {
        $result.EndTime = Get-Date
        $results += $result
    }
}

# Summary report
Write-Log "`n=== Collection Summary ==="
$results | ForEach-Object {
    Write-Log "$($_.Hostname): $($_.Status) $(if ($_.ArtifactSize) { "($($_.ArtifactSize))" }) $(if ($_.Error) { "— $($_.Error)" })"
}

$succeeded = ($results | Where-Object Status -eq "Complete").Count
$failed = ($results | Where-Object Status -eq "Failed").Count
Write-Log "Completed: $succeeded/$($Targets.Count) | Failed: $failed"

# Export results
$results | Export-Csv -Path (Join-Path $caseDir "collection_results.csv") -NoTypeInformation

Write-Log "Evidence stored in: $caseDir"
```

## Usage

```powershell
# Collect from specific endpoints
.\Invoke-KAPERemoteCollection.ps1 `
    -Targets "WS001","WS002","WS003","SRV-DC01" `
    -CaseNumber "INC-2025-0847" `
    -KAPESource "\\fileserver\tools\KAPE" `
    -EvidenceRoot "D:\Evidence"

# Collect from a list file
$hosts = Get-Content "C:\IR\compromised_hosts.txt"
.\Invoke-KAPERemoteCollection.ps1 `
    -Targets $hosts `
    -CaseNumber "INC-2025-0847"
```

## Output Structure

```
D:\Evidence\INC-2025-0847_20250525_143022\
├── collection_log.txt
├── collection_results.csv
├── WS001\
│   └── [KAPE VHDX or directory output]
├── WS002\
│   └── [KAPE VHDX or directory output]
└── SRV-DC01\
    └── [KAPE VHDX or directory output]
```

## Evidence Handling Notes

- The `--vhdx` flag packages evidence as a VHDX container, maintaining file metadata and timestamps
- Each endpoint's evidence is isolated in its own directory under the case folder
- The collection log provides a chain-of-custody record with timestamps for each operation
- KAPE and its output are removed from the remote endpoint after collection to minimize footprint
- For legal proceedings, hash the VHDX containers immediately after collection: `Get-FileHash -Algorithm SHA256`

## Limitations

- Requires SMB (445) and WinRM (5985/5986) connectivity to targets
- WinRM must be enabled on target endpoints (`Enable-PSRemoting -Force`)
- Large collections (20+ endpoints) may benefit from parallel execution with `-ThrottleLimit` on `ForEach-Object -Parallel` (PowerShell 7+)
- KAPE's `!SANS_Triage` target collects 500MB-2GB per endpoint — plan storage accordingly
- The script runs KAPE as SYSTEM via the remote admin share — it collects artifacts the admin user can access, which is everything on a domain-joined endpoint

## Learn More

- [KAPE — Collection, Processing, and Analysis](https://ridgelinecyber.com/training/courses/kape-ez-tools/) — KAPE target configuration, artifact analysis, and investigation workflows
- [Incident Response — Evidence Collection](https://ridgelinecyber.com/training/courses/practical-ir/) — evidence collection procedures and chain of custody
- [Windows Forensics — Triage Artifacts](https://ridgelinecyber.com/training/courses/windows-endpoint-investigation/) — understanding the artifacts KAPE collects
