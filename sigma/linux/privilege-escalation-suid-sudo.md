# Linux Privilege Escalation: SUID, Sudo, and Capabilities Abuse

Detects privilege escalation attempts on Linux via SUID binary abuse, sudo misconfigurations, and Linux capability exploitation. Attackers enumerate these after initial access to escalate from a web application user or low-privilege shell to root.

## ATT&CK

- **Technique:** T1548.001. Abuse Elevation Control Mechanism: SUID/SGID
- **Tactic:** Privilege Escalation

## Severity

**High.** SUID/sudo abuse is the most common Linux privilege escalation path. Detection at this stage catches the attacker between initial access and full system compromise.

## Data Sources

Linux process creation with full command lines. auditd `execve`, Sysmon for Linux `ProcessCreate`, or an eBPF agent such as Falco. Every selection matches on command line, so a process-name-only feed detects none of this.

## Query: Sigma
```yaml
title: Linux Privilege Escalation Enumeration and Exploitation
id: 7b3c9d14-e862-4a71-bf53-c2d8a6e91f30
status: experimental
description: >
  Detects enumeration and exploitation of SUID binaries, sudo
  misconfigurations, and Linux capabilities for privilege escalation.
references:
  - https://attack.mitre.org/techniques/T1548/001/
  - https://gtfobins.github.io/
author: Ridgeline Cyber
date: 2025/05/25
tags:
  - attack.privilege_escalation
  - attack.t1548.001
logsource:
  product: linux
  category: process_creation
detection:
  # SUID binary enumeration
  selection_find_suid:
    CommandLine|contains:
      - 'find / -perm -4000'
      - 'find / -perm -u=s'
      - 'find / -perm /4000'
      - 'find / -perm -2000'
      - 'find / -perm -g=s'
  # Sudo enumeration
  selection_sudo_enum:
    CommandLine|contains:
      - 'sudo -l'
      - 'sudo -ll'
      - 'sudoers'
      - 'cat /etc/sudoers'
  # Capabilities enumeration
  selection_caps_enum:
    CommandLine|contains:
      - 'getcap -r /'
      - 'getcap -r /usr'
      - '/sbin/getcap'
  # GTFOBins exploitation patterns
  selection_gtfobins:
    CommandLine|contains:
      - 'vim -c ":!/bin/sh"'
      - 'vim -c ":set shell=/bin/sh"'
      - "find . -exec /bin/sh"
      - "nmap --interactive"
      - "awk 'BEGIN {system("
      - "python -c 'import os; os.execl"
      - "python3 -c 'import os; os.execl"
      - "perl -e 'exec \"/bin/sh\"'"
      - "less /etc/passwd"  # followed by !/bin/sh
  # Sudo exploitation
  selection_sudo_exploit:
    CommandLine|contains:
      - 'sudo -u#-1'
      - 'sudo -u #-1'
      - 'sudo env /bin/'
      - 'sudo LD_PRELOAD'
      - 'sudo LD_LIBRARY_PATH'
      - 'pkexec'
  # Capability exploitation
  selection_caps_exploit:
    CommandLine|contains:
      - 'cap_setuid'
      - 'cap_setgid'
      - 'cap_dac_override'
      - 'cap_sys_admin'
  # LinPEAS/LinEnum execution
  selection_enum_tools:
    CommandLine|contains:
      - 'linpeas'
      - 'linenum'
      - 'linux-exploit-suggester'
      - 'lse.sh'
      - 'unix-privesc-check'
      - 'linux-smart-enumeration'
  condition: 1 of selection_*
falsepositives:
  - System administrators auditing SUID binaries and sudo configurations
  - Automated compliance scanning tools
  - Security assessment scripts
level: high
```

## What Triggers This

An account enumerates its own escalation surface or uses a known escape. The selections cover `find / -perm -4000` and its variants for SUID binaries, `sudo -l` and reads of `/etc/sudoers` for granted rights, `getcap -r /` for file capabilities, and GTFOBins shell escapes such as `vim -c ":!/bin/sh"`.

Enumeration and escape are separated because they carry different weight. Enumeration is what an attacker does on arrival; a GTFOBins escape means they have found something.

## False Positives

1. **Security scanners and CIS benchmarking.** Lynis, OpenSCAP and most hardening scanners run exactly these `find -perm` and `getcap` commands, on a schedule. They will be your top producer. Exclude on the scanner's service account, not on the command, so a human running the same command still fires.
2. **Engineers checking their own access.** `sudo -l` is the first thing a competent engineer runs on an unfamiliar host. Common, benign, and indistinguishable from reconnaissance by command line alone.
3. **Package and container build steps.** Dockerfiles frequently `find -perm` to strip SUID bits during hardening.
4. **Configuration management audits.** Ansible and Puppet compliance roles read `/etc/sudoers` on every run.

## Tuning Notes

- **The GTFOBins selection is the one to alert on.** Enumeration is noisy and ambiguous; a shell escape out of `vim`, `less` or `find` is not. Split it out and give it high severity, and run the enumeration selections as a hunt or a low-severity feed.
- **Enumeration is worth more in sequence than alone.** `sudo -l` on its own is nothing. `sudo -l` followed within minutes by a GTFOBins escape from the same session is the finding. If your platform supports correlation, that pairing is a better rule than either half.
- **Exclude your scanner first.** Count by parent process for a fortnight; the top entry is almost always the compliance scanner, and removing it takes most of the volume out.
- **Interactive sessions only, if you can.** Restricting to processes with a TTY cuts most automation without touching an attacker on a shell.
- **Conversion:** `sigma convert -t splunk -p linux sigma/linux/privilege-escalation-suid-sudo.yml`

## Learn More

- [Linux IR: Privilege Escalation Detection](https://ridgelinecyber.com/training/courses/linux-endpoint-investigation/). SUID, sudo, and capability analysis
- [Offensive Security for Defenders: Linux Privesc](https://ridgelinecyber.com/training/courses/offensive-security-for-defenders/). GTFOBins and Linux escalation techniques
