# Linux Log Tampering and Defense Evasion

Detects attacker attempts to cover tracks on Linux: log deletion, history file manipulation, timestomping, auditd disabling, and process hiding. Attackers tamper with evidence to delay detection and frustrate forensic analysis.

## ATT&CK

- **Technique:** T1070.002. Indicator Removal: Clear Linux or Mac System Logs
- **Tactic:** Defense Evasion

## Severity

**High.** Log tampering indicates a sophisticated attacker who is actively trying to hide their activity. The tampering itself is evidence of malicious intent.

## Data Sources

Linux process creation with full command lines. auditd `execve`, Sysmon for Linux `ProcessCreate`, or an eBPF agent such as Falco. Every selection matches on command line, so a process-name-only feed detects none of this.

## Query: Sigma
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
  - Log rotation scripts (logrotate), these use mv/gzip, not rm/truncate
  - Automated cleanup scripts during maintenance windows
  - Container environments that redirect logs to stdout
level: high
```

## What Triggers This

An account destroys evidence or disables its own recording. The selections cover deletion and truncation of `/var/log` by `rm`, `truncate`, `shred`, `dd` and shell redirection, and history suppression via `unset HISTFILE`, `HISTSIZE=0`, `history -c`, and symlinking `~/.bash_history` to `/dev/null`.

History suppression is the more telling half. Log rotation has legitimate reasons to truncate a log file; nothing legitimate needs to stop recording what a shell just did.

## False Positives

1. **Log rotation and cleanup scripts.** `logrotate` post-rotate actions, and hand-rolled cron jobs that truncate logs on full disks, match the deletion selections directly. Exclude on the parent being `logrotate` or the specific cron job, and keep the exclusion narrow to the paths that job owns.
2. **Disk-full incident response.** An engineer clearing `/var/log` at three in the morning to bring a service back looks exactly like an attacker covering tracks. Worth alerting on and closing quickly rather than excluding.
3. **`HISTCONTROL=ignorespace` in shipped dotfiles.** Some distributions and many personal dotfiles set this, so it fires on every login for some users. Baseline it per user before deciding.
4. **Container and CI images.** Build steps commonly clear history and logs to shrink layers.

## Tuning Notes

- **Split deletion from history suppression.** They have different false positive profiles and different severities. Log deletion needs the `logrotate` exclusion; history suppression mostly does not.
- **`ln -s /dev/null ~/.bash_history` deserves its own rule at high severity.** It is deliberate, persistent, and has no administrative use. Of everything in this rule it is the least ambiguous.
- **Time-of-day is a useful discriminator here.** Log truncation inside a change window with a ticket is operations; the same command at 0300 with no change record is not. If your platform can join to a change calendar, do it.
- **Watch what the exclusion costs you.** Excluding `logrotate` by parent is safe. Excluding by path is not, because an attacker will use the same paths.
- **Conversion:** `sigma convert -t splunk -p linux sigma/linux/log-tampering-defense-evasion.yml`

## Learn More

- [Linux IR: Anti-Forensics Detection](https://ridgelinecyber.com/training/courses/linux-endpoint-investigation/). log tampering identification and evidence recovery
- [Incident Response: Evidence Preservation](https://ridgelinecyber.com/training/courses/practical-ir/). protecting evidence integrity
