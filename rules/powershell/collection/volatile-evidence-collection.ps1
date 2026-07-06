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
