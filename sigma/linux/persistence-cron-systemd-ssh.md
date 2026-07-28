# Linux Persistence: Cron, Systemd, SSH Keys, Shell Profiles

Detects the creation of new persistence mechanisms on Linux systems: crontab modifications, new systemd service files, SSH authorized_keys additions, shell profile modifications, and at job scheduling. These are the techniques attackers use to survive reboots and maintain access.

## ATT&CK

- **Technique:** T1053.003. Cron, T1543.002, Systemd Service, T1098.004, SSH Authorized Keys
- **Tactic:** Persistence

## Severity

**High.** New persistence mechanisms on a production server should be rare and intentional. Any unscheduled persistence creation warrants investigation.

## Data Sources

Linux process creation with full command lines. Any of auditd `execve` records, Sysmon for Linux `ProcessCreate`, or an eBPF agent such as Falco will do, provided the command line is captured. A process-name-only feed will not work: eight of the nine selections match on command line rather than image.

## Query: Sigma
```yaml
title: Linux Persistence Mechanism Creation
id: 5e8a1c72-d934-4b68-a219-f7c3d6e82b45
status: experimental
description: >
  Detects creation of new cron jobs, systemd services, SSH authorized
  keys, shell profile modifications, and other Linux persistence
  mechanisms.
references:
  - https://attack.mitre.org/techniques/T1053/003/
  - https://attack.mitre.org/techniques/T1543/002/
  - https://attack.mitre.org/techniques/T1098/004/
author: Ridgeline Cyber
date: 2025/05/25
tags:
  - attack.persistence
  - attack.t1053.003
  - attack.t1543.002
  - attack.t1098.004
logsource:
  product: linux
  category: process_creation
detection:
  # Crontab modification
  selection_crontab:
    Image|endswith: '/crontab'
    CommandLine|contains:
      - '-e'
      - '-l'
  selection_cron_write:
    CommandLine|contains:
      - '/etc/cron'
      - '/var/spool/cron'
      - 'crontab -'
  # Systemd service creation
  selection_systemd:
    CommandLine|contains:
      - 'systemctl enable'
      - 'systemctl daemon-reload'
  selection_systemd_write:
    CommandLine|contains:
      - '/etc/systemd/system/'
      - '/lib/systemd/system/'
      - '.service'
    Image|endswith:
      - '/cp'
      - '/mv'
      - '/tee'
      - '/bash'
      - '/sh'
  # SSH key addition
  selection_ssh_keys:
    CommandLine|contains:
      - 'authorized_keys'
      - '.ssh/authorized'
    Image|endswith:
      - '/bash'
      - '/sh'
      - '/cp'
      - '/tee'
      - '/echo'
  # Shell profile modification
  selection_profile:
    CommandLine|contains:
      - '.bashrc'
      - '.bash_profile'
      - '.profile'
      - '.zshrc'
      - '/etc/profile'
      - '/etc/bash.bashrc'
    Image|endswith:
      - '/echo'
      - '/tee'
      - '/sed'
      - '/cat'
  # At job scheduling
  selection_at:
    Image|endswith: '/at'
    CommandLine|contains:
      - '-f'
      - 'now +'
  # Systemd timer creation (alternative to cron)
  selection_timer:
    CommandLine|contains:
      - '.timer'
      - 'OnCalendar'
      - 'OnBootSec'
  # Init script creation
  selection_init:
    CommandLine|contains:
      - '/etc/init.d/'
      - '/etc/rc.local'
      - 'update-rc.d'
      - 'chkconfig'
  condition: 1 of selection_*
falsepositives:
  - Legitimate system administration and package installation
  - Configuration management tools (Ansible, Puppet, Chef, SaltStack)
  - Automated deployment pipelines
level: high
```

## What Triggers This

A process touches one of nine persistence surfaces: `crontab` invoked directly, a write into `/etc/cron*` or a user crontab, `systemctl enable`, a write of a `.service` or `.timer` unit file, an append to an `authorized_keys` file, a write into a shell profile such as `.bashrc` or `/etc/profile.d`, an `at` job, or a write into an init script directory.

The rule condition is `1 of selection_*`, so any single surface fires it. It is deliberately broad, because an attacker only needs one of the nine and most estates do not know which of them they use.

## False Positives

1. **Configuration management.** Ansible, Puppet, Chef and Salt write systemd units, cron entries and `authorized_keys` as their normal function, and on a managed estate this is the largest single producer by a wide margin. Exclude on the agent's parent process or service account rather than on the file path, so a human editing the same file still fires.
2. **Package installation.** `dpkg` and `rpm` post-install scripts create units and timers. Exclude where the ancestor is a package manager, and keep the exclusion to the install window rather than making it permanent.
3. **Deployment pipelines.** CI runners push `authorized_keys` entries to grant themselves access, and container build steps write profile scripts. Both look identical to the technique.
4. **Legitimate administration.** An engineer running `crontab -e` on a server they own. This is the one you want to see, so tune it down with severity rather than exclusion.

## Tuning Notes

- **Split it before you deploy it.** Nine selections in one rule means one severity, one owner and one threshold for nine different behaviours. Splitting by surface lets `authorized_keys` writes run at high severity while shell profile writes run as a hunt.
- **The `authorized_keys` selection is the highest signal.** It grants access directly, survives password changes, and configuration management aside, it is rarely written by hand. If you deploy only one selection, deploy that one.
- **Baseline before enabling.** Run it for a fortnight in report-only and count by parent process. Whatever sits at the top is your configuration management, and excluding it is most of the tuning.
- **Container hosts need their own scoping.** Every image build writes profile scripts and units. Either exclude the builder's cgroup or run the rule on the host namespace only.
- **Conversion:** `sigma convert -t splunk -p linux sigma/linux/persistence-cron-systemd-ssh.yml`, and `-t microsoft365defender` for Defender for Endpoint on Linux.

## Learn More

- [Linux IR: Persistence Analysis](https://ridgelinecyber.com/training/courses/linux-endpoint-investigation/). identifying and removing Linux persistence
- [Purple Team Operations: Linux Persistence Testing](https://ridgelinecyber.com/training/courses/purple-teaming-for-blue-teams/). validating persistence detections
