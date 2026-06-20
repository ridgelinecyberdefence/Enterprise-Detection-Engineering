# HTML Smuggling — Browser-Dropped Archive or ISO

Detects HTML smuggling where a browser process writes an archive file (ZIP, ISO, IMG, VHD) to disk. Attackers embed encoded payloads in HTML attachments or web pages that assemble and download the payload entirely client-side, bypassing email gateway and proxy inspection.

## ATT&CK

- **Technique:** T1027.006 — Obfuscated Files or Information: HTML Smuggling
- **Tactic:** Initial Access, Defense Evasion

## Severity

**High.** HTML smuggling is specifically designed to bypass email security gateways and web proxies. The payload arrives as an HTML file (which passes most filters), then assembles the malicious archive in the browser via JavaScript.

## Data Sources

- Sysmon Event ID 11 (FileCreate)
- Microsoft Defender for Endpoint — `DeviceFileEvents`

## Detection

```yaml
title: HTML Smuggling — Browser Drops Archive or Disk Image
id: 9b3e7f82-c41a-4d93-b5e7-d2a8f6134c09
status: experimental
description: >
  Detects browser processes creating archive or disk image files,
  which is characteristic of HTML smuggling attacks. Legitimate
  downloads produce these files too, but the combination of browser
  process + specific container formats warrants investigation.
references:
  - https://attack.mitre.org/techniques/T1027/006/
author: Ridgeline Cyber
date: 2025/05/25
tags:
  - attack.initial_access
  - attack.defense_evasion
  - attack.t1027.006
logsource:
  category: file_event
  product: windows
detection:
  selection_process:
    Image|endswith:
      - '\chrome.exe'
      - '\msedge.exe'
      - '\firefox.exe'
      - '\brave.exe'
      - '\iexplore.exe'
      - '\msedgewebview2.exe'
  selection_extension:
    TargetFilename|endswith:
      - '.iso'
      - '.img'
      - '.vhd'
      - '.vhdx'
      - '.zip'
      - '.7z'
      - '.rar'
  filter_downloads:
    TargetFilename|contains:
      - '\Downloads\\'
  condition: selection_process and selection_extension
  # Note: the Downloads filter is intentionally NOT applied in the
  # condition. HTML smuggling drops to Downloads by default. Include
  # it as a secondary filter only if noise is unmanageable — but
  # be aware this is exactly where smuggled payloads land.
falsepositives:
  - Legitimate file downloads from trusted sites
  - Browser-based file conversion tools
  - Cloud storage web apps downloading archives
level: high
```

## What Triggers This

A browser process creates an ISO, IMG, VHD, ZIP, 7z, or RAR file. HTML smuggling payloads are assembled in the browser via JavaScript `Blob` objects and trigger an automatic download. The file types are significant:
- **ISO/IMG/VHD** — these mount as virtual drives on Windows, bypassing Mark-of-the-Web
- **ZIP/7z/RAR** — containers that may strip MOTW from enclosed executables

## False Positives

1. **Legitimate downloads.** Users download archives and disk images from the web routinely. Volume-based tuning helps: one ISO download is normal, three in an hour from the same user is suspicious.
2. **Cloud storage.** OneDrive, SharePoint, and Google Drive web interfaces trigger browser-based downloads. Correlate with known cloud storage domains.
3. **Web-based tools.** File conversion and packaging sites deliver archives via browser download.

## Tuning Notes

- ISO and VHD drops are higher confidence than ZIP — fewer legitimate reasons for a browser to drop a disk image
- Combine with Sysmon Event ID 1: if the dropped ISO/VHD is immediately mounted (explorer.exe accessing the new drive letter), that's the attack chain completing
- Combine with email logs: if the user received an HTML attachment in the 10 minutes before the browser drop, confidence is very high

## Learn More

- [SOC Operations — Phishing Triage](https://ridgelinecyber.com/training/courses/m365-security-operations/) — HTML smuggling indicators and response
- [Detection Engineering — Email & Endpoint Correlation](https://ridgelinecyber.com/training/courses/detection-engineering/) — cross-layer detection for delivery-to-execution chains
