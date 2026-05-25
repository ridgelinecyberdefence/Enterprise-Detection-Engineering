# Remote WinRM Triage — Multi-Endpoint Rapid Assessment

Collects volatile evidence from remote Windows endpoints over WinRM without deploying an agent. Captures processes, network connections, services, scheduled tasks, persistence, and user sessions. Outputs structured JSON per host.

## ATT&CK Coverage

Triage across T1059 (Execution), T1053/T1547/T1543 (Persistence), T1021 (Lateral Movement), T1071 (C2).

## Category

Triage — First-response remote evidence collection.

## Requirements

- WinRM enabled on targets (TCP 5985/5986)
- Administrative credentials
- PowerShell 5.1+

## Script

```powershell
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$Targets,
    [string]$OutputPath = ".\Triage-Output",
    [PSCredential]$Credential
)

$ErrorActionPreference = "Continue"
$ts = Get-Date -Format "yyyy-MM-dd_HHmmss"
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
if (-not $Credential) { $Credential = Get-Credential -Message "Admin credentials for remote triage" }

$triageBlock = {
    $e = @{
        Hostname = $env:COMPUTERNAME
        CollectedAt = (Get-Date -Format "o")
        OS = (Get-CimInstance Win32_OperatingSystem).Caption
    }
    $e.Processes = Get-CimInstance Win32_Process |
        Select-Object ProcessId, Name, CommandLine, ParentProcessId, CreationDate |
        Sort-Object CreationDate -Descending
    $e.NetworkConnections = Get-NetTCPConnection -State Established,Listen -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess,
            @{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}}
    $e.Services = Get-CimInstance Win32_Service |
        Where-Object { $_.PathName -and $_.PathName -notmatch 'Windows|System32|svchost' } |
        Select-Object Name, State, StartMode, PathName, StartName
    $e.ScheduledTasks = Get-ScheduledTask |
        Where-Object { $_.TaskPath -notmatch '\\Microsoft\\' } |
        Select-Object TaskName, State, @{N='Action';E={($_.Actions[0]).Execute}}
    $regPaths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                  "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
    $e.RegistryPersistence = foreach ($p in $regPaths) {
        if (Test-Path $p) { Get-ItemProperty $p -EA SilentlyContinue |
            ForEach-Object { $_.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } |
                ForEach-Object { [PSCustomObject]@{Key=$p; Name=$_.Name; Value=$_.Value} } } }
    }
    $e.DNSCache = Get-DnsClientCache | Select-Object Entry, Data, TimeToLive
    $e.LoggedOnUsers = query user 2>$null
    return $e
}

foreach ($t in $Targets) {
    Write-Host "[*] Triaging $t..." -ForegroundColor Cyan
    try {
        $s = New-PSSession -ComputerName $t -Credential $Credential -EA Stop
        $r = Invoke-Command -Session $s -ScriptBlock $triageBlock
        Remove-PSSession $s
        $r | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputPath "$($t)_triage_$ts.json") -Encoding UTF8
        Write-Host "[+] $t complete" -ForegroundColor Green
    } catch { Write-Host "[-] $t FAILED: $_" -ForegroundColor Red }
}
```

## What This Collects

Processes with command lines, established network connections, non-default services, non-Microsoft scheduled tasks, Run/RunOnce registry persistence, DNS cache, and logged-on users. All volatile evidence that is destroyed by isolation or reboot.

## Learn More

- [Incident Response](https://training.ridgelinecyber.com/courses/practical-ir/) — volatile evidence collection methodology
- [SOC Operations](https://training.ridgelinecyber.com/courses/m365-security-operations/) — remote endpoint investigation
