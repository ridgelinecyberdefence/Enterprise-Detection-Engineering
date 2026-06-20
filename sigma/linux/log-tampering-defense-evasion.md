# Linux Log Tampering and Defense Evasion

Detects attacker attempts to cover tracks on Linux: log deletion, history file manipulation, timestomping, auditd disabling, and process hiding. Attackers tamper with evidence to delay detection and frustrate forensic analysis.

## ATT&CK

- **Technique:** T1070.002 — Indicator Removal: Clear Linux or Mac System Logs
- **Tactic:** Defense Evasion

## Severity

**High.** Log tampering indicates a sophisticated attacker who is actively trying to hide their activity. The tampering itself is evidence of malicious intent.

## Detection

```yaml
title: Linux Log Tampering and Evidence Destruction
id: 2f6b8e93-a741-4c85-9d27-e3f1b5c06a84
status: experimental
description: >
  Detects deletion or modification of log files, shell history
  manipulation, auditd tampering, and other anti-forensic techniques
  on Linux systems.
references:
  - https://attack.mitre.org/techniques/T1070/002/
author: Ridgeline Cyber
date: 2025/05/25
tags:
  - attack.defense_evasion
  - attack.t1070.002
logsource:
  product: linux
  category: process_creation
detection:
  # Log file deletion
  selection_log_delete:
    CommandLine|contains:
      - 'rm -f /var/log'
      - 'rm -rf /var/log'
      - '> /var/log/'
      - 'truncate -s 0 /var/log'
      - 'cat /dev/null > /var/log'
      - 'shred /var/log'
      - 'dd if=/dev/null of=/var/log'
  # Shell history manipulation
  selection_history:
    CommandLine|contains:
      - 'unset HISTFILE'
      - 'export HISTSIZE=0'
      - 'export HISTFILESIZE=0'
      - 'set +o history'
      - 'history -c'
      - 'history -w /dev/null'
      - 'rm -f ~/.bash_history'
      - 'rm -f ~/.zsh_history'
      - '> ~/.bash_history'
      - 'ln -s /dev/null ~/.bash_history'
      - 'HISTCONTROL=ignorespace'
  # Auditd tampering
  selection_auditd:
    CommandLine|contains:
      - 'systemctl stop auditd'
      - 'systemctl disable auditd'
      - 'service auditd stop'
      - 'auditctl -D'
      - 'auditctl -e 0'
      - 'rm -f /var/log/audit'
      - 'kill -9'
    Image|endswith:
      - '/auditctl'
      - '/systemctl'
      - '/service'
  # Syslog tampering
  selection_syslog:
    CommandLine|contains:
      - 'systemctl stop rsyslog'
      - 'systemctl stop syslog'
      - 'service rsyslog stop'
      - 'kill -STOP'
  # Timestamp manipulation
  selection_timestomp:
    CommandLine|contains:
      - 'touch -t '
      - 'touch -r '
      - 'touch -d '
      - 'touch --date='
      - 'touch --reference='
  # Wtmp/utmp manipulation (login record tampering)
  selection_login_records:
    CommandLine|contains:
      - 'utmpdump'
      - '/var/log/wtmp'
      - '/var/log/btmp'
      - '/var/run/utmp'
      - '/var/log/lastlog'
  # LD_PRELOAD for process hiding
  selection_ld_preload:
    CommandLine|contains:
      - 'LD_PRELOAD='
      - '/etc/ld.so.preload'
  condition: 1 of selection_*
falsepositives:
  - Log rotation scripts (logrotate) — these use mv/gzip, not rm/truncate
  - Automated cleanup scripts during maintenance windows
  - Container environments that redirect logs to stdout
level: high
```

## Learn More

- [Linux IR — Anti-Forensics Detection](https://ridgelinecyber.com/training/courses/linux-endpoint-investigation/) — log tampering identification and evidence recovery
- [Incident Response — Evidence Preservation](https://ridgelinecyber.com/training/courses/practical-ir/) — protecting evidence integrity
