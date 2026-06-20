# USB Device History — Removable Media Forensic Collection

Extracts USB device connection history from the Windows registry, including device serial numbers, friendly names, first/last connection timestamps, and volume mount points. Essential for investigating data theft via removable media.

## Category

Collection — Removable media forensics.

## Requirements

- Administrative access, PowerShell 5.1+
- Access to SYSTEM and USBSTOR registry hives

## Script

```powershell
[CmdletBinding()]
param(
    [string]$OutputPath = ".\USB-History"
)

$ts = Get-Date -Format "yyyy-MM-dd_HHmmss"
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$usbDevices = @()

# USBSTOR registry key
$usbStorPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
if (Test-Path $usbStorPath) {
    $deviceClasses = Get-ChildItem $usbStorPath
    foreach ($class in $deviceClasses) {
        $instances = Get-ChildItem $class.PSPath -ErrorAction SilentlyContinue
        foreach ($instance in $instances) {
            $props = Get-ItemProperty $instance.PSPath -ErrorAction SilentlyContinue
            $serial = Split-Path $instance.PSPath -Leaf

            # Get first/last connection from setupapi logs or registry timestamps
            $friendlyName = $props.FriendlyName
            $deviceDesc = $props.DeviceDesc -replace '.*;\s*',''
            $mfg = $props.Mfg -replace '.*;\s*',''

            $usbDevices += [PSCustomObject]@{
                DeviceClass  = Split-Path $class.PSPath -Leaf
                SerialNumber = $serial
                FriendlyName = $friendlyName
                Description  = $deviceDesc
                Manufacturer = $mfg
                ContainerID  = $props.ContainerID
            }
        }
    }
}

# Mount points — which drive letters were assigned
$mountPoints = @()
$mpPath = "HKLM:\SYSTEM\MountedDevices"
if (Test-Path $mpPath) {
    $mpProps = Get-ItemProperty $mpPath -ErrorAction SilentlyContinue
    $mpProps.PSObject.Properties | Where-Object {
        $_.Name -match '\\DosDevices\\' -and $_.Value
    } | ForEach-Object {
        $mountPoints += [PSCustomObject]@{
            DriveLetter = ($_.Name -split '\\')[-1]
            DeviceData  = [System.Text.Encoding]::Unicode.GetString($_.Value) -replace '\x00',''
        }
    }
}

$report = @{
    CollectedAt  = (Get-Date -Format "o")
    Hostname     = $env:COMPUTERNAME
    USBDevices   = $usbDevices
    MountPoints  = $mountPoints
    DeviceCount  = $usbDevices.Count
}

$outFile = Join-Path $OutputPath "usb_history_$ts.json"
$report | ConvertTo-Json -Depth 4 | Out-File $outFile -Encoding UTF8
Write-Host "[+] Found $($usbDevices.Count) USB devices. Report: $outFile" -ForegroundColor Green
```

## Learn More

- [Windows Forensics](https://ridgelinecyber.com/training/courses/windows-endpoint-investigation/) — USB forensics and removable media investigation
- [Incident Response](https://ridgelinecyber.com/training/courses/practical-ir/) — data theft investigation
