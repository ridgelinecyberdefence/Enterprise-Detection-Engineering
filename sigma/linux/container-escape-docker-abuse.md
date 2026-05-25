# Container Escape and Docker Abuse

Detects container escape techniques and Docker socket abuse on Linux container hosts. Attackers who compromise a containerized application target the host system by escaping the container via mounted Docker socket, privileged mode abuse, nsenter, cgroup manipulation, or kernel exploit.

## ATT&CK

- **Technique:** T1611 — Escape to Host
- **Tactic:** Privilege Escalation

## Severity

**Critical.** Container escape means an attacker who compromised one application now has access to the host and potentially all other containers on that host.

## Detection

```yaml
title: Container Escape Techniques
id: 8d2e6f14-b573-4a92-c816-d9f4a7e53b21
status: experimental
description: >
  Detects container escape attempts including Docker socket abuse,
  privileged container breakout, nsenter, cgroup escape, and
  host filesystem access from within containers.
references:
  - https://attack.mitre.org/techniques/T1611/
author: Ridgeline Cyber
date: 2025/05/25
tags:
  - attack.privilege_escalation
  - attack.t1611
logsource:
  product: linux
  category: process_creation
detection:
  # Docker socket access from inside container
  selection_docker_socket:
    CommandLine|contains:
      - '/var/run/docker.sock'
      - 'docker.sock'
      - 'docker exec'
      - 'docker run -v /:/host'
      - 'docker run --privileged'
      - 'docker run --pid=host'
      - 'docker run --net=host'
  # nsenter to host namespaces
  selection_nsenter:
    Image|endswith: '/nsenter'
    CommandLine|contains:
      - '--target 1'
      - '-t 1'
      - '--mount'
      - '--pid'
      - '--net'
  # Cgroup escape
  selection_cgroup:
    CommandLine|contains:
      - '/sys/fs/cgroup'
      - 'release_agent'
      - 'notify_on_release'
      - 'cgroup_manager'
  # Host filesystem mount from container
  selection_host_mount:
    CommandLine|contains:
      - 'mount /dev/'
      - 'mount -o bind'
      - '/proc/1/root'
      - '/proc/sysrq-trigger'
      - 'chroot /host'
  # Privileged container capabilities abuse
  selection_caps_abuse:
    CommandLine|contains:
      - 'capsh --print'
      - 'SYS_ADMIN'
      - 'SYS_PTRACE'
      - 'SYS_MODULE'
      - 'CAP_SYS_ADMIN'
  # Kubernetes service account token access
  selection_k8s_token:
    CommandLine|contains:
      - '/var/run/secrets/kubernetes.io'
      - '/serviceaccount/token'
      - 'kubectl'
  # Container runtime exploitation
  selection_runtime:
    CommandLine|contains:
      - 'runc'
      - 'containerd-shim'
      - 'crictl'
      - 'ctr run'
  condition: 1 of selection_*
falsepositives:
  - Container orchestration tools (Docker Compose, Kubernetes operators)
  - Container monitoring and logging agents
  - Authorized container administration
level: critical
```

## Learn More

- [Linux IR — Container Forensics](https://training.ridgelinecyber.com/courses/linux-ir/) — investigating compromised containers and container escapes
- [Offensive Security for Defenders — Container Attacks](https://training.ridgelinecyber.com/courses/offensive-security-defenders/) — container escape techniques and their detection
