# SSH Abuse: Brute Force, Key Theft, and Tunneling

Detects SSH-related attack patterns: credential stuffing against SSH, SSH private key exfiltration, unauthorized SSH tunnel creation, and SSH agent hijacking. SSH is the primary remote access protocol for Linux. Every SSH abuse detection directly protects the most common entry point.

## ATT&CK

- **Technique:** T1021.004. Remote Services: SSH, T1110.001, Brute Force
- **Tactic:** Lateral Movement, Credential Access, Command and Control

## Severity

**High.** SSH abuse indicates either initial access attempts (brute force) or post-compromise lateral movement and tunneling.

## Detection

```yaml
title: SSH Abuse — Brute Force, Key Theft, and Tunneling
id: 6a9d3e47-b182-4c63-8f75-d4e2c1a09b56
status: experimental
description: >
  Detects SSH-related attack patterns including private key theft,
  unauthorized tunneling, SSH agent forwarding abuse, and known
  attack tool usage.
references:
  - https://attack.mitre.org/techniques/T1021/004/
author: Ridgeline Cyber
date: 2025/05/25
tags:
  - attack.lateral_movement
  - attack.credential_access
  - attack.t1021.004
  - attack.t1110.001
logsource:
  product: linux
  category: process_creation
detection:
  # SSH private key exfiltration
  selection_key_theft:
    CommandLine|contains:
      - 'id_rsa'
      - 'id_ed25519'
      - 'id_ecdsa'
      - 'id_dsa'
      - '.ssh/id_'
      - '.pem'
    Image|endswith:
      - '/cat'
      - '/cp'
      - '/scp'
      - '/base64'
      - '/curl'
      - '/wget'
      - '/tar'
      - '/zip'
      - '/xxd'
  # SSH tunneling
  selection_tunnel:
    CommandLine|contains:
      - 'ssh -L '
      - 'ssh -R '
      - 'ssh -D '
      - 'ssh -f -N'
      - 'ssh -N -f'
      - '-o StrictHostKeyChecking=no'
      - '-o UserKnownHostsFile=/dev/null'
  # SSH agent hijacking
  selection_agent:
    CommandLine|contains:
      - 'SSH_AUTH_SOCK'
      - 'ssh-agent'
      - '/tmp/ssh-'
      - 'ssh-add -L'
  # SSH config manipulation
  selection_ssh_config:
    CommandLine|contains:
      - '/etc/ssh/sshd_config'
      - 'PermitRootLogin'
      - 'PasswordAuthentication'
      - 'AuthorizedKeysFile'
      - 'PubkeyAuthentication'
    Image|endswith:
      - '/sed'
      - '/echo'
      - '/tee'
      - '/vi'
      - '/nano'
  # Known SSH attack tools
  selection_tools:
    CommandLine|contains:
      - 'hydra'
      - 'medusa'
      - 'patator'
      - 'crowbar'
      - 'ssh-audit'
      - 'sshprank'
  # SSH to many hosts in rapid succession (lateral movement)
  selection_spray:
    Image|endswith: '/ssh'
  condition: 1 of selection_key_theft or 1 of selection_tunnel or
             1 of selection_agent or 1 of selection_ssh_config or
             1 of selection_tools
  # Note: selection_spray requires SIEM-side aggregation
  # (5+ distinct destinations from same source in 5 minutes)
falsepositives:
  - System administrators using SSH tunnels for legitimate maintenance
  - Ansible/Puppet/Chef connecting to managed hosts via SSH
  - Automated backup scripts copying SSH keys
  - SSH key rotation scripts
level: high
```

## Learn More

- [Linux IR: SSH Forensics](https://ridgelinecyber.com/training/courses/linux-endpoint-investigation/). SSH key analysis, auth.log forensics, and tunnel detection
- [Network Detection and Forensics: Encrypted Channel Analysis](https://ridgelinecyber.com/training/courses/network-detection-forensics/). SSH traffic analysis
