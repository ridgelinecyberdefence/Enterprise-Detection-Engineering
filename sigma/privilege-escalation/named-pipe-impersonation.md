# Named Pipe Impersonation — Privilege Escalation

Detects tools that exploit named pipe impersonation for local privilege escalation, including PrintSpoofer, GodPotato, SweetPotato, JuicyPotato, and similar "potato" family exploits. These tools trick a SYSTEM-level service into connecting to an attacker-controlled named pipe, then impersonate the SYSTEM token to spawn an elevated process.

## ATT&CK

- **Technique:** T1134.001 — Access Token Manipulation: Token Impersonation/Theft
- **Tactic:** Privilege Escalation

## Severity

**Critical.** Named pipe impersonation exploits escalate from a service account (e.g., IIS AppPool, SQL Server) to SYSTEM in seconds. The exploit requires `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege`, which are granted to all service accounts by default. If the attacker has code execution in any Windows service context, they can escalate to SYSTEM.

## Data Sources

- Process creation: Sysmon Event ID 1, Windows Security 4688, EDR
- Named pipe creation: Sysmon Event ID 17/18
- Requires: Command line logging and pipe event logging

## Query — Sigma

```yaml
title: Named Pipe Impersonation — Potato Family and PrintSpoofer
id: rc-sigma-018
status: production
description: |
  Detects named pipe impersonation tools used for local privilege
  escalation from service context to SYSTEM. Covers PrintSpoofer,
  GodPotato, SweetPotato, JuicyPotato, RoguePotato, and generic
  pipe impersonation patterns. These exploits abuse
  SeImpersonatePrivilege to steal SYSTEM tokens.
author: Ridgeline Cyber Detection Engineering
date: 2026/05/25
tags:
  - attack.privilege_escalation
  - attack.t1134.001
  - attack.t1134.002
logsource:
  category: process_creation
  product: windows
detection:
  # Known tool names (even when renamed, original names appear in metadata)
  selection_known_tools:
    Image|endswith:
      - '\PrintSpoofer.exe'
      - '\PrintSpoofer64.exe'
      - '\GodPotato.exe'
      - '\SweetPotato.exe'
      - '\JuicyPotato.exe'
      - '\JuicyPotatoNG.exe'
      - '\RoguePotato.exe'
      - '\SharpEfsPotato.exe'
      - '\CoercedPotato.exe'
  # Command line patterns even with renamed binaries
  selection_cmdline_patterns:
    CommandLine|contains|any:
      - 'PrintSpoofer'
      - 'GodPotato'
      - 'SweetPotato'
      - 'JuicyPotato'
      - 'RoguePotato'
      - 'EfsPotato'
      - 'CoercedPotato'
      - '-c cmd'
      - '-i -c'
      - 'CreateProcessWithTokenW'
      - 'ImpersonateNamedPipeClient'
  # Generic pipe impersonation pattern — service account spawning elevated shell
  selection_service_to_shell:
    User|contains:
      - 'SERVICE'
      - 'NETWORK SERVICE'
      - 'LOCAL SERVICE'
      - 'IIS APPPOOL'
      - 'MSSQL'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
  condition: selection_known_tools or selection_cmdline_patterns or selection_service_to_shell
falsepositives:
  - IIS application pools legitimately spawning cmd.exe for CGI scripts
  - SQL Server xp_cmdshell (should be disabled)
  - Service recovery actions configured to run command-line tools
level: critical
```

## What Triggers This

1. Attacker gains code execution in a service context (IIS web shell, SQL injection, compromised service)
2. Attacker uploads or executes a potato-family exploit
3. The exploit creates a named pipe and coerces a SYSTEM service to connect
4. The exploit impersonates the SYSTEM token from the pipe connection
5. The exploit spawns a new process (cmd.exe, powershell.exe) running as SYSTEM

The generic `selection_service_to_shell` pattern catches renamed tools by detecting the behavioral outcome: a service account spawning a command interpreter.

## False Positives

1. **IIS CGI scripts.** Web applications using CGI execute cmd.exe under the IIS AppPool identity. These produce predictable command lines referencing the CGI script path.
2. **SQL Server xp_cmdshell.** SQL Server can execute OS commands via xp_cmdshell. This should be disabled in production. If enabled, it produces MSSQL → cmd.exe chains.
3. **Service recovery.** Windows services can be configured to run a command on failure. These produce SERVICE → cmd.exe chains with the recovery command in the command line.

## Tuning Notes

- **Service-to-shell is high value.** The `selection_service_to_shell` pattern has the broadest coverage but highest false positive rate. Start with the known tool and command line patterns, then add service-to-shell after baselining.
- **xp_cmdshell alert.** If `selection_service_to_shell` fires with MSSQL as the user, this is either xp_cmdshell abuse or a SQL Server compromise. Both warrant investigation.

## Validation

1. In a lab (non-production), verify the detection fires against known tool names
2. Test the service-to-shell pattern by running a command as a service account

## Learn More

- [Offensive Security for Defenders](https://training.ridgelinecyber.com/courses/offensive-security-for-defenders/) — Windows privilege escalation, token manipulation, and named pipe attacks
- [Purple Team Operations](https://training.ridgelinecyber.com/courses/purple-teaming-for-blue-teams/) — privilege escalation technique validation
