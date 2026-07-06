# Windows Volatile Evidence Collection: First Responder Script

Collects volatile evidence from a live Windows system in order of volatility: network connections, running processes with command lines, DNS cache, logged-on users, scheduled tasks, and services. Designed to run before imaging or isolation. Captures evidence that disappears when the system is powered off or network-isolated.

## Use Case

You receive an alert for a compromised Windows endpoint. Before you isolate the machine (killing active attacker connections) or image the disk (which doesn't capture volatile data), you need to capture what's in memory and in active network state right now.

## Requirements

- PowerShell 5.1+ (built into Windows 10/11 and Server 2016+)
- Local administrator privileges on the target endpoint
- Run locally or via WinRM/PSExec. Do not copy the script to the endpoint's disk if preserving forensic integrity (run from a network share or invoke via remoting)

## Script

```powershell
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Volatile evidence collection for Windows incident response.
    Run BEFORE isolation or imaging. Captures evidence that does
    not survive power-off or network disconnect.
.NOTES
    Ridgeline Cyber — https://ridgelinecyber.com/training
    Writes output to a timestamped directory. Does not modify
    the target system. Read-only collection only.
#>

param(
    [string]$OutputPath = "C:\IR-Evidence",
    [string]$CaseId = "IR-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
)

$ErrorActionPreference = 'Continue'
$CasePath = Join-Path $OutputPath $CaseId
New-Item -ItemType Directory -Path $CasePath -Force | Out-Null

function Write-Evidence {
    param([string]$Name, [scriptblock]$Collect)
    $outFile = Join-Path $CasePath "$Name.txt"
    $startTime = Get-Date
    try {
        $result = & $Collect 2>&1
        $result | Out-File -FilePath $outFile -Encoding UTF8
        $duration = (Get-Date) - $startTime
        Write-Host "[+] $Name collected ($($duration.TotalSeconds.ToString('F1'))s)" -ForegroundColor Green
    }
    catch {
        "[ERROR] $($_.Exception.Message)" | Out-File -FilePath $outFile -Encoding UTF8
        Write-Host "[-] $Name failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Record collection metadata
@"
Case ID:        $CaseId
Hostname:       $env:COMPUTERNAME
Collected By:   $env:USERNAME
Collection Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC' -AsUTC)
PowerShell:     $($PSVersionTable.PSVersion)
OS:             $(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
"@ | Out-File (Join-Path $CasePath "_metadata.txt") -Encoding UTF8

# === TIER 1: Highest volatility — network state ===

Write-Evidence "01-network-connections" {
    Get-NetTCPConnection -State Established, Listen, CloseWait, TimeWait |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort,
        State, OwningProcess,
        @{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}},
        @{N='ProcessPath';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}} |
    Sort-Object State, RemoteAddress |
    Format-Table -AutoSize
}

Write-Evidence "02-dns-cache" {
    Get-DnsClientCache |
    Select-Object Entry, RecordType, Status, TimeToLive, Data |
    Sort-Object Entry |
    Format-Table -AutoSize
}

Write-Evidence "03-arp-table" {
    Get-NetNeighbor -State Reachable, Stale, Permanent |
    Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias |
    Format-Table -AutoSize
}

# === TIER 2: Process state ===

Write-Evidence "04-processes-full" {
    Get-CimInstance Win32_Process |
    Select-Object ProcessId, ParentProcessId, Name,
        @{N='CommandLine';E={$_.CommandLine}},
        @{N='ExecutablePath';E={$_.ExecutablePath}},
        @{N='Owner';E={
            $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction SilentlyContinue
            if ($owner.Domain) { "$($owner.Domain)\$($owner.User)" } else { "N/A" }
        }},
        CreationDate |
    Sort-Object CreationDate |
    Format-Table -AutoSize -Wrap
}

Write-Evidence "05-process-tree" {
    $procs = Get-CimInstance Win32_Process |
        Select-Object ProcessId, ParentProcessId, Name, CommandLine, CreationDate
    function Show-Tree($parentId, $indent) {
        $procs | Where-Object { $_.ParentProcessId -eq $parentId } | ForEach-Object {
            "$indent[$($_.ProcessId)] $($_.Name) | $($_.CommandLine)"
            Show-Tree $_.ProcessId "$indent  "
        }
    }
    Show-Tree 0 ""
}

Write-Evidence "06-loaded-dlls-unsigned" {
    Get-Process | ForEach-Object {
        $proc = $_
        try {
            $_.Modules | Where-Object {
                $sig = Get-AuthenticodeSignature $_.FileName -ErrorAction SilentlyContinue
                $sig.Status -ne 'Valid'
            } | Select-Object @{N='ProcessName';E={$proc.Name}},
                @{N='PID';E={$proc.Id}},
                ModuleName, FileName
        } catch {}
    } | Where-Object { $_ } | Format-Table -AutoSize
}

# === TIER 3: Persistence and logon state ===

Write-Evidence "07-logged-on-users" {
    query user 2>&1
    Write-Output "`n--- Logon Sessions ---"
    Get-CimInstance Win32_LogonSession |
    Where-Object { $_.LogonType -in 2, 3, 7, 10, 11 } |
    ForEach-Object {
        $session = $_
        $user = Get-CimAssociatedInstance -InputObject $_ -ResultClassName Win32_UserAccount -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            LogonId = $session.LogonId
            LogonType = $session.LogonType
            StartTime = $session.StartTime
            User = if ($user) { $user.Caption } else { "N/A" }
        }
    } | Format-Table -AutoSize
}

Write-Evidence "08-scheduled-tasks-nonms" {
    Get-ScheduledTask |
    Where-Object {
        $_.TaskPath -notlike '\Microsoft\*' -and
        $_.State -ne 'Disabled'
    } |
    Select-Object TaskName, TaskPath, State,
        @{N='Action';E={($_.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) -join "; "}},
        @{N='RunAs';E={$_.Principal.UserId}} |
    Format-Table -AutoSize -Wrap
}

Write-Evidence "09-services-nonstandard" {
    Get-CimInstance Win32_Service |
    Where-Object {
        $_.PathName -and
        $_.PathName -notlike '*\Windows\*' -and
        $_.PathName -notlike '*\Microsoft*' -and
        $_.StartMode -ne 'Disabled'
    } |
    Select-Object Name, DisplayName, State, StartMode, PathName,
        @{N='RunAs';E={$_.StartName}} |
    Sort-Object State -Descending |
    Format-Table -AutoSize -Wrap
}

Write-Evidence "10-run-keys" {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($path in $paths) {
        Write-Output "=== $path ==="
        if (Test-Path $path) {
            Get-ItemProperty $path -ErrorAction SilentlyContinue |
            Select-Object * -ExcludeProperty PS* |
            Format-List
        } else {
            Write-Output "(not found)"
        }
        Write-Output ""
    }
}

# === TIER 4: Recent activity ===

Write-Evidence "11-recent-file-modifications" {
    $suspiciousPaths = @(
        "$env:TEMP",
        "$env:USERPROFILE\Downloads",
        "$env:APPDATA",
        "$env:LOCALAPPDATA\Temp",
        "C:\ProgramData"
    )
    $suspiciousPaths | ForEach-Object {
        if (Test-Path $_) {
            Get-ChildItem -Path $_ -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
            Select-Object FullName, Length,
                @{N='Modified';E={$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')}},
                @{N='Created';E={$_.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')}}
        }
    } | Sort-Object Modified -Descending | Select-Object -First 100 |
    Format-Table -AutoSize -Wrap
}

Write-Evidence "12-prefetch-recent" {
    Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue |
    Select-Object Name,
        @{N='Modified';E={$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')}},
        @{N='Created';E={$_.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')}},
        Length |
    Sort-Object Modified -Descending |
    Select-Object -First 30 |
    Format-Table -AutoSize
}

# === Generate collection hash ===

Write-Evidence "_collection-hashes" {
    Get-ChildItem $CasePath -File |
    Where-Object { $_.Name -ne '_collection-hashes.txt' } |
    ForEach-Object {
        $hash = Get-FileHash $_.FullName -Algorithm SHA256
        "$($hash.Hash)  $($_.Name)"
    }
}

Write-Host "`n[*] Collection complete: $CasePath" -ForegroundColor Cyan
Write-Host "[*] Files: $((Get-ChildItem $CasePath -File).Count)" -ForegroundColor Cyan
```

## What This Collects and Why

| File | Evidence | Why it matters |
|---|---|---|
| 01-network-connections | TCP connections with process ownership | Shows active C2 connections, lateral movement sessions, and data exfiltration in progress. Lost on isolation. |
| 02-dns-cache | Resolved DNS names with TTL | Shows domains the endpoint contacted recently. Lost on reboot. Identifies C2 domains, phishing infrastructure. |
| 03-arp-table | IP-to-MAC mappings | Shows which hosts the endpoint communicated with on the local network. Identifies lateral movement targets. |
| 04-processes-full | All processes with command lines and owners | Complete process inventory. Command lines reveal attacker tools, encoded payloads, and living-off-the-land techniques. |
| 05-process-tree | Parent-child process relationships | Shows how processes were spawned. Identifies suspicious parent chains (Word → cmd → PowerShell). |
| 06-loaded-dlls-unsigned | DLLs without valid signatures | Identifies injected or side-loaded malicious DLLs in running processes. |
| 07-logged-on-users | Active sessions with logon types | Shows who is logged on, how (RDP, console, network), and since when. Identifies attacker sessions. |
| 08-scheduled-tasks | Non-Microsoft scheduled tasks | Persistence mechanism. Attacker tasks point to malicious binaries in user-writable directories. |
| 09-services | Non-standard Windows services | Persistence mechanism. Attacker services run malicious binaries at system startup. |
| 10-run-keys | Registry Run/RunOnce values | Persistence mechanism. Code that executes on every logon. |
| 11-recent-files | Files modified in last 7 days in temp/download paths | Shows recently dropped tools, staged data, and attacker artifacts. |
| 12-prefetch | Recently executed applications | Shows what ran and when. Identifies attacker tools even after they've been deleted. |

## What This Does NOT Collect

- **Memory dumps.** Use Winpmem, DumpIt, or Magnet RAM Capture for full memory acquisition. This script captures process metadata, not memory contents.
- **Disk images.** Use KAPE, FTK Imager, or dd for forensic imaging. This script reads volatile state only.
- **Event logs.** Logs are non-volatile (survive reboot). Collect them with KAPE's `!SANS_Triage` target after volatile collection.
- **MFT/registry hives.** Non-volatile. Collect with KAPE after volatile evidence is secured.

## Operational Notes

- **Run this FIRST.** Before isolating the endpoint, before imaging, before running KAPE. Network connections and process state are lost the moment you disconnect the network or reboot.
- **Chain of custody.** The script generates SHA256 hashes of all output files in `_collection-hashes.txt`. Record who ran the script, when, and the case ID in your evidence log.
- **Remote execution.** To run via WinRM without writing the script to the target disk: `Invoke-Command -ComputerName TARGET -FilePath .\Collect-Volatile.ps1 -ArgumentList "\\share\evidence", "IR-2026-001"`
- **Output size.** Typically 500KB-2MB per endpoint. Suitable for rapid collection across multiple endpoints during a large-scale incident.

## Learn More

- [Incident Triage and First Response](https://ridgelinecyber.com/training/courses/incident-triage-first-response/). evidence collection methodology, order of volatility, and triage decision framework
- [Practical Incident Response](https://ridgelinecyber.com/training/courses/practical-ir/). full investigation workflow from volatile collection through timeline analysis
