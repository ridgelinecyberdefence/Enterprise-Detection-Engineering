# Linux Kernel Module Loading and Rootkit Indicators

Detects suspicious kernel module operations: loading unsigned modules, insmod/modprobe from unusual locations, known rootkit module names, and kernel parameter manipulation. Kernel-level rootkits provide the deepest level of persistence and stealth. They can hide processes, files, and network connections from all userspace tools.

## ATT&CK

- **Technique:** T1014. Rootkit, T1547.006, Kernel Modules and Extensions
- **Tactic:** Persistence, Defense Evasion

## Severity

**Critical.** Kernel module loading outside of normal package management is rare on production systems. Any unauthorized module load should be investigated as a potential rootkit.

## Detection

```yaml
title: Linux Suspicious Kernel Module Loading
id: 1c4d7e28-f693-4b51-a827-e5c9d3f16a42
status: experimental
description: >
  Detects suspicious kernel module operations including loading from
  unusual paths, known rootkit module names, and kernel parameter
  manipulation that may indicate rootkit installation.
references:
  - https://attack.mitre.org/techniques/T1014/
  - https://attack.mitre.org/techniques/T1547/006/
author: Ridgeline Cyber
date: 2025/05/25
tags:
  - attack.persistence
  - attack.defense_evasion
  - attack.t1014
  - attack.t1547.006
logsource:
  product: linux
  category: process_creation
detection:
  # Module loading from non-standard paths
  selection_insmod:
    Image|endswith:
      - '/insmod'
      - '/modprobe'
    CommandLine|contains:
      - '/tmp/'
      - '/dev/shm/'
      - '/var/tmp/'
      - '/home/'
      - '/root/'
      - 'Downloads'
  # Known rootkit module names
  selection_rootkit_names:
    CommandLine|contains:
      - 'diamorphine'
      - 'reptile'
      - 'adore-ng'
      - 'knark'
      - 'enyelkm'
      - 'azazel'
      - 'jynx'
      - 'vlany'
      - 'bdvl'
      - 'brootus'
      - 'suterusu'
      - 'kovid'
  # Kernel parameter manipulation
  selection_sysctl:
    CommandLine|contains:
      - 'sysctl -w'
      - 'kernel.modules_disabled'
      - 'kernel.kptr_restrict'
      - 'kernel.dmesg_restrict'
      - 'kernel.yama.ptrace_scope'
      - '/proc/sys/kernel/'
  # DKMS abuse (building modules outside package management)
  selection_dkms:
    CommandLine|contains:
      - 'dkms install'
      - 'dkms add'
    Image|endswith:
      - '/dkms'
  # eBPF rootkit indicators
  selection_ebpf:
    CommandLine|contains:
      - 'bpf('
      - 'bpftool'
      - 'BPF_PROG_LOAD'
  # Direct write to /dev/kmem or /dev/mem
  selection_kmem:
    CommandLine|contains:
      - '/dev/kmem'
      - '/dev/mem'
      - '/dev/port'
  condition: 1 of selection_*
falsepositives:
  - DKMS during legitimate driver installation (GPU, network)
  - Kernel development and testing environments
  - Legitimate eBPF tools (bpftrace, BCC tools) used for performance monitoring
level: critical
```

## Learn More

- [Linux IR: Rootkit Detection](https://ridgelinecyber.com/training/courses/linux-endpoint-investigation/). kernel module forensics and rootkit indicators
- [Memory Forensics: Linux Memory Analysis](https://ridgelinecyber.com/training/courses/applied-memory-forensics/). analyzing kernel memory for hidden modules
