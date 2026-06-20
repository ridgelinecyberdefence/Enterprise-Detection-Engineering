# RDP Tunneling — SSH or netsh Port Forwarding

Detects RDP tunneling via SSH port forwarding, netsh portproxy, plink, and chisel that encapsulate RDP traffic within allowed protocols to bypass network segmentation.

## ATT&CK

- **Technique:** T1572 — Protocol Tunneling, T1021.001 — Remote Services: RDP
- **Tactic:** Lateral Movement, Command and Control

## Severity

**High.** RDP tunneling bypasses network segmentation controls.

## Data Sources

- Process creation with command line: Sysmon Event ID 1, Windows Security 4688

## Query — Sigma

```yaml
title: RDP Tunneling via SSH, netsh, or Tunneling Tools
id: rc-sigma-022
status: production
description: |
  Detects port forwarding configurations that tunnel RDP (3389)
  through SSH, netsh portproxy, plink, chisel, or ligolo.
author: Ridgeline Cyber Detection Engineering
date: 2026/05/25
tags:
  - attack.lateral_movement
  - attack.t1572
  - attack.t1021.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_ssh:
    Image|endswith:
      - '\ssh.exe'
      - '\plink.exe'
    CommandLine|contains|any:
      - ':3389'
      - '3389:'
      - '-L'
      - '-R'
  selection_netsh:
    Image|endswith: '\netsh.exe'
    CommandLine|contains|all:
      - 'portproxy'
      - 'add'
    CommandLine|contains: '3389'
  selection_tools:
    CommandLine|contains|any:
      - 'chisel'
      - 'ligolo'
      - 'ngrok'
    CommandLine|contains|any:
      - '3389'
      - 'socks'
  selection_rdp_localhost:
    Image|endswith: '\mstsc.exe'
    CommandLine|contains|any:
      - '127.0.0.1'
      - 'localhost'
  condition: selection_ssh or selection_netsh or selection_tools or selection_rdp_localhost
falsepositives:
  - IT administrators using SSH tunnels for remote management
  - Developers tunneling to development environments
level: high
```

## Tuning Notes

- mstsc to localhost is very high confidence — no legitimate use case
- netsh portproxy is persistent across reboots — check for persistence

## Learn More

- [Offensive Security for Defenders](https://ridgelinecyber.com/training/courses/offensive-security-for-defenders/) — lateral movement and network pivoting
- [Network Detection and Forensics](https://ridgelinecyber.com/training/courses/network-detection-forensics/) — tunnel detection
