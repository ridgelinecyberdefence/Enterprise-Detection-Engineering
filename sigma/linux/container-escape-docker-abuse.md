# Container Escape and Docker Abuse

Detects container escape techniques and Docker socket abuse on Linux container hosts. Attackers who compromise a containerized application target the host system by escaping the container via mounted Docker socket, privileged mode abuse, nsenter, cgroup manipulation, or kernel exploit.

## ATT&CK

- **Technique:** T1611, Escape to Host
- **Tactic:** Privilege Escalation

## Severity

**Critical.** Container escape means an attacker who compromised one application now has access to the host and potentially all other containers on that host.

## Data Sources

Linux process creation with full command lines. auditd `execve`, Sysmon for Linux `ProcessCreate`, or an eBPF agent such as Falco. Every selection matches on command line, so a process-name-only feed detects none of this.

## Query: Sigma
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

## What Triggers This

A process reaches for one of the three routes out of a container. The selections cover Docker socket access and privileged `docker run` flags including `--privileged`, `-v /:/host`, `--pid=host` and `--net=host`; `nsenter` against PID 1 to enter the host namespaces; and cgroup `release_agent` manipulation.

All three assume the attacker already has execution inside a container. The rule is about the boundary crossing, not the initial access.

## False Positives

1. **CI runners and build agents.** Docker-in-Docker mounts the socket by design, and most self-hosted CI mounts `/var/run/docker.sock` into the runner. This is the dominant producer on any estate that builds containers. Exclude the runner's service account or namespace, never the socket path.
2. **Container orchestration and monitoring agents.** cAdvisor, Datadog, Falco itself and most node agents read `/sys/fs/cgroup` and talk to the socket as their normal function.
3. **Engineers debugging containers.** `docker exec` into a running container is routine, and `nsenter -t 1` is a legitimate way to reach a host namespace from a privileged debug container.
4. **`--privileged` in development compose files.** Common, lazy, and identical to the technique. Worth reporting on for its own sake rather than excluding.

## Tuning Notes

- **Separate the socket selection from `nsenter` and `release_agent`.** Socket access is normal on a build host and abnormal on a database server, so the same rule needs different severities in different places. The other two have far fewer legitimate uses anywhere.
- **`release_agent` is the highest-signal selection.** It is a known escape primitive with essentially no administrative purpose, and unlike the socket it does not appear in normal operations. If you deploy one selection, deploy that.
- **Scope by host role before tuning by exclusion.** On build infrastructure this rule is close to useless; on application servers it is valuable. Splitting the deployment by host group beats a long exclusion list.
- **Watch for the reverse direction too.** These selections catch escaping outward. A privileged container being created is an earlier and quieter signal, and it lives in your orchestrator's audit log rather than in process creation.
- **Conversion:** `sigma convert -t splunk -p linux sigma/linux/container-escape-docker-abuse.yml`

## Learn More

- [Linux IR: Container Forensics](https://ridgelinecyber.com/training/courses/linux-endpoint-investigation/). investigating compromised containers and container escapes
- [Offensive Security for Defenders: Container Attacks](https://ridgelinecyber.com/training/courses/offensive-security-for-defenders/). container escape techniques and their detection
