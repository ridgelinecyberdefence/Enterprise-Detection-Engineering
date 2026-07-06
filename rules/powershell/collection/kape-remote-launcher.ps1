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
