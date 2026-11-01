# SSH Abuse: Brute Force, Key Theft, and Tunneling

Detects SSH-related attack patterns: credential stuffing against SSH, SSH private key exfiltration, unauthorized SSH tunnel creation, and SSH agent hijacking. SSH is the primary remote access protocol for Linux. Every SSH abuse detection directly protects the most common entry point.

## ATT&CK

- **Technique:** T1021.004. Remote Services: SSH, T1110.001, Brute Force
- **Tactic:** Lateral Movement, Credential Access, Command and Control

## Severity

**High.** SSH abuse indicates either initial access attempts (brute force) or post-compromise lateral movement and tunneling.

## Data Sources

Linux process creation with full command lines. auditd `execve`, Sysmon for Linux `ProcessCreate`, or an eBPF agent such as Falco. Every selection matches on command line, so a process-name-only feed detects none of this.

## Query: Sigma
```yaml
title: SSH Abuse, Brute Force, Key Theft, and Tunneling
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

## What Triggers This

Two behaviours, deliberately kept apart by the condition. Key theft is a read, copy or encode of a private key file, matching `id_rsa`, `id_ed25519`, `.pem` and similar alongside a tool such as `cat`, `cp`, `scp`, `base64`, `curl`, `tar` or `xxd`. Tunnelling is `ssh` invoked with `-L`, `-R`, `-D` or `-f -N`, which forwards a port rather than opening a session.

The tool pairing on key theft is what makes it usable. `cat id_rsa` alone is something an engineer does; `base64 id_rsa` or `curl` with a key path is staging for exfiltration.

## False Positives

1. **Backup and configuration management.** Anything that archives home directories reads private keys with `tar`, and Ansible reads them to distribute authorised keys. Exclude on the agent's account.
2. **Legitimate port forwarding.** `ssh -L` to reach a database through a bastion is daily work for many engineers, and `-D` for a SOCKS proxy is a normal way to reach an internal network. On some teams this selection fires more than anything else in the rule.
3. **Key rotation tooling.** Rotation scripts read, copy and re-deploy keys by definition.
4. **Developers copying their own keys** to a new machine. Benign, common, and identical in telemetry to theft.

## Tuning Notes

- **The two halves want different treatment.** Key theft with an encoding or transfer tool is worth alerting on. Tunnelling is worth baselining per user and alerting only on new source-destination pairs, because the engineers who use it use it constantly.
- **`-R` is the one to escalate.** A remote forward opens a path inward from the SSH server to the client, which is how an operator turns a foothold into persistent access. Local and dynamic forwards have far more legitimate use.
- **Baseline tunnelling by user before enabling.** Two weeks of counts will show a handful of heavy users and a long tail. The tail is where the finding is.
- **Add destination context if you have it.** A tunnel to a bastion inside your estate is different from a tunnel to a VPS, and that distinction is not in process creation. Joining to network telemetry makes this rule considerably better.
- **Conversion:** `sigma convert -t splunk -p linux sigma/linux/ssh-abuse-bruteforce-tunneling.yml`

## Learn More

- [Linux IR: SSH Forensics](https://ridgelinecyber.com/training/courses/linux-endpoint-investigation/). SSH key analysis, auth.log forensics, and tunnel detection
- [Threat Detection Engineering](https://ridgelinecyber.com/training/courses/detection-engineering/)
