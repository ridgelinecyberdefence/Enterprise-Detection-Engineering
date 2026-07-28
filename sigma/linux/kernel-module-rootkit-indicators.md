# Linux Kernel Module Loading and Rootkit Indicators

Detects suspicious kernel module operations: loading unsigned modules, insmod/modprobe from unusual locations, known rootkit module names, and kernel parameter manipulation. Kernel-level rootkits provide the deepest level of persistence and stealth. They can hide processes, files, and network connections from all userspace tools.

## ATT&CK

- **Technique:** T1014. Rootkit, T1547.006, Kernel Modules and Extensions
- **Tactic:** Persistence, Defense Evasion

## Severity

**Critical.** Kernel module loading outside of normal package management is rare on production systems. Any unauthorized module load should be investigated as a potential rootkit.

## Data Sources

Linux process creation with full command lines. auditd `execve`, Sysmon for Linux `ProcessCreate`, or an eBPF agent such as Falco. Every selection matches on command line, so a process-name-only feed detects none of this.

## Query: Sigma
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

## What Triggers This

A kernel module is loaded from a location no packaged module lives in, or by a name matching a known rootkit. The selections cover `insmod` and `modprobe` with a path under `/tmp`, `/dev/shm`, `/var/tmp`, a home directory or `Downloads`, and command lines naming published rootkits including Diamorphine, Reptile, adore-ng, Azazel and vlany.

The path condition is doing most of the work. Legitimate modules ship in `/lib/modules` and are loaded by the package manager or the kernel itself, so a module loaded out of a writable temporary directory is the signal regardless of what it is called.

## False Positives

1. **Out-of-tree driver builds.** DKMS, NVIDIA and VirtualBox guest additions, and any hardware vendor driver compiled on the host will load a module from a build directory. This is the main producer and it is legitimate. Exclude on the DKMS or build parent process rather than on the path.
2. **Kernel development and testing.** Anyone building modules on a workstation triggers this constantly. Scope the rule to servers, or exclude developer hosts explicitly.
3. **Security agent installers.** Some EDR and monitoring agents load a module from their installer's working directory on first run.
4. **The rootkit-name selection has effectively no false positives**, but it also only catches an attacker who did not rename the file, which is a low bar. Treat a hit as high confidence and its absence as meaningless.

## Tuning Notes

- **Keep the path selection and the name selection separate.** The name list is high confidence and low coverage; the path condition is the opposite. One severity for both wastes the first and buries you in the second.
- **The name list needs maintaining or removing.** A static list of nine rootkits dates quickly and gives false comfort. Either review it against current reporting or drop it and rely on the path condition, which does not depend on knowing the malware's name.
- **Add `/lib/modules` as an explicit allow, not an assumption.** Being precise about where modules legitimately live makes the rule survive a distribution change.
- **Correlate with module unload and `lsmod` gaps.** A rootkit that hides itself from `lsmod` is invisible afterwards, so the load event is often the only chance. That argues for alerting rather than hunting on this one.
- **Conversion:** `sigma convert -t splunk -p linux sigma/linux/kernel-module-rootkit-indicators.yml`

## Learn More

- [Linux IR: Rootkit Detection](https://ridgelinecyber.com/training/courses/linux-endpoint-investigation/). kernel module forensics and rootkit indicators
- [Memory Forensics: Linux Memory Analysis](https://ridgelinecyber.com/training/courses/applied-memory-forensics/). analyzing kernel memory for hidden modules
