# RDP Tunneling: SSH or netsh Port Forwarding

Detects RDP tunneling via SSH port forwarding, netsh portproxy, plink, and chisel that encapsulate RDP traffic within allowed protocols to bypass network segmentation.

## ATT&CK

- **Technique:** T1572. Protocol Tunneling, T1021.001, Remote Services: RDP
- **Tactic:** Lateral Movement, Command and Control

## Severity

**High.** RDP tunneling bypasses network segmentation controls.

## Data Sources

- Process creation with command line: Sysmon Event ID 1, Windows Security 4688

## Query: Sigma

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

## What Triggers This

RDP being carried over another protocol to reach a host that should not be reachable. The rule matches `ssh.exe` or `plink.exe` with a port forward involving 3389, and `netsh interface portproxy` commands that achieve the same thing natively.

The point is not RDP use, which is ordinary. It is RDP arriving somewhere by a path that bypasses whatever network controls sit between the source and the target.

## False Positives

1. **Legitimate jump-host access.** Engineers forward RDP through a bastion because that is the sanctioned route into a segmented environment. On many estates this is the designed access path and the rule fires on correct behaviour.
2. **Vendor and supplier support sessions,** which frequently arrive as an SSH tunnel by prior arrangement.
3. **`netsh portproxy` in legitimate use** for IPv4 to IPv6 bridging and for elderly application compatibility.
4. **Developers reaching lab machines** through a tunnel to avoid VPN restrictions, which is a policy question rather than an attack.

## Tuning Notes

- mstsc to localhost is very high confidence, no legitimate use case
- netsh portproxy is persistent across reboots, check for persistence

## Tuning Notes

- **Source and destination decide everything here.** A tunnel from a workstation to a bastion is the sanctioned path; a tunnel between two workstations, or outbound to an external host, is not. Encode that as the rule's condition if your platform allows it, because it removes most false positives without weakening detection.
- **`netsh portproxy` warrants higher severity than the SSH selections.** It is rarer, it persists across reboots, and it has fewer legitimate uses than a client-side forward.
- **Enumerate the sanctioned tunnels rather than excluding the tools.** A short list of bastion hosts and support arrangements is maintainable; excluding `plink.exe` outright removes the coverage entirely.
- **Persistence is the stronger signal than the connection.** A portproxy rule added and left in place is a foothold. Checking for existing rules across the estate is a one-off hunt worth running alongside this detection.

## Learn More

- [Purple Teaming for Blue Teams](https://ridgelinecyber.com/training/courses/purple-teaming-for-blue-teams/)
- [Threat Detection Engineering](https://ridgelinecyber.com/training/courses/detection-engineering/)
