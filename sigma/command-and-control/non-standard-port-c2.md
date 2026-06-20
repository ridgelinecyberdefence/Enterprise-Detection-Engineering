# C2 via Protocol Mismatch — HTTP on Non-Standard Ports

Detects outbound connections where the application-layer protocol doesn't match the expected port assignment — HTTP/HTTPS traffic on non-standard ports, or non-HTTP traffic on port 80/443. Attackers configure C2 listeners on uncommon ports to avoid detection, or tunnel non-HTTP protocols over ports 80/443 to bypass firewall rules.

## ATT&CK

- **Technique:** T1571 — Non-Standard Port
- **Tactic:** Command and Control

## Severity

**Medium.** Protocol mismatch on its own can be legitimate (development servers, custom applications). Combined with other indicators (beaconing pattern, unknown destination), severity escalates to High.

## Data Sources

- Sysmon Event ID 3 (NetworkConnect)
- Firewall/proxy logs with protocol detection

## Detection

```yaml
title: Outbound Connection on Non-Standard Port from Suspicious Process
id: 4a2f8c61-d917-4b3e-8f42-a1c5e7903d2b
status: experimental
description: >
  Detects outbound network connections on uncommon ports from processes
  that typically use standard web ports. Indicates potential C2 on
  non-standard ports or port-hopping evasion.
references:
  - https://attack.mitre.org/techniques/T1571/
author: Ridgeline Cyber
date: 2025/05/25
tags:
  - attack.command_and_control
  - attack.t1571
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    Initiated: 'true'
    DestinationIsIpv6: 'false'
  suspicious_ports:
    DestinationPort|range:
      - 1024-4442
      - 4444-8079
      - 8081-8442
      - 8444-65535
  suspicious_processes:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\cmd.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
      - '\mshta.exe'
      - '\cscript.exe'
      - '\wscript.exe'
      - '\certutil.exe'
      - '\msiexec.exe'
  filter_loopback:
    DestinationIp|startswith:
      - '127.'
      - '10.'
      - '172.16.'
      - '172.17.'
      - '172.18.'
      - '172.19.'
      - '172.20.'
      - '172.21.'
      - '172.22.'
      - '172.23.'
      - '172.24.'
      - '172.25.'
      - '172.26.'
      - '172.27.'
      - '172.28.'
      - '172.29.'
      - '172.30.'
      - '172.31.'
      - '192.168.'
  condition: selection and suspicious_ports and suspicious_processes and not filter_loopback
falsepositives:
  - Development and testing environments with services on non-standard ports
  - VPN and proxy software using custom ports
  - Remote management tools on configured ports
level: medium
```

## What Triggers This

A scripting engine or LOLBin makes an outbound connection to a public IP on a non-standard port. Common C2 ports: 4443, 4444, 8443, 8080, 9090, 50050. The detection focuses on the combination of suspicious process + non-standard port + external destination.

## False Positives

1. **Development environments.** Dev servers often run on ports 3000, 5000, 8080. Exclude known dev tool processes.
2. **VPN clients.** Some VPN solutions use non-standard ports. Exclude by process after verification.
3. **Remote management.** RMM tools may use custom ports. Catalog and exclude.

## Tuning Notes

- Port 8080 and 8443 generate the most noise. Consider excluding them if your environment has many legitimate services on those ports, but be aware this is also where attackers hide.
- The private IP filter removes internal-only connections. If your network uses non-RFC1918 ranges internally, adjust the filter.
- Combine with the beaconing detection for high-confidence alerts: non-standard port + regular timing = strong C2 indicator

## Learn More

- [Detection Engineering — Network Detection Rules](https://ridgelinecyber.com/training/courses/detection-engineering/) — port-based and protocol-based detection strategies
- [Offensive Security for Defenders — C2 Infrastructure](https://ridgelinecyber.com/training/courses/offensive-security-for-defenders/) — C2 listener configuration and evasion
