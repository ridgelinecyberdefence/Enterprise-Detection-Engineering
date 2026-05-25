# BloodHound/SharpHound Active Directory Reconnaissance

Detects BloodHound and SharpHound collection activity, which maps Active Directory trust relationships, group memberships, sessions, ACLs, and attack paths.

## ATT&CK

- **Technique:** T1087.002 — Account Discovery: Domain Account, T1069.002 — Permission Groups Discovery, T1482 — Domain Trust Discovery
- **Tactic:** Discovery

## Severity

**High.** BloodHound collection is a precursor to targeted privilege escalation.

## Data Sources

- Process creation with command line: Sysmon Event ID 1, Windows Security 4688

## Query — Sigma

```yaml
title: BloodHound or SharpHound Collection Activity
id: rc-sigma-021
status: production
description: |
  Detects SharpHound collector execution, AzureHound, and
  ADFind reconnaissance patterns. Covers command-line indicators
  and output file patterns.
author: Ridgeline Cyber Detection Engineering
date: 2026/05/25
tags:
  - attack.discovery
  - attack.t1087.002
  - attack.t1069.002
  - attack.t1482
logsource:
  category: process_creation
  product: windows
detection:
  selection_tools:
    CommandLine|contains|any:
      - 'SharpHound'
      - 'BloodHound'
      - 'AzureHound'
      - 'Invoke-BloodHound'
  selection_collection:
    CommandLine|contains|any:
      - '--CollectionMethods'
      - '-CollectionMethod'
      - '--OutputDirectory'
      - '--ZipFilename'
      - 'DCOnly'
  selection_output:
    CommandLine|contains|any:
      - '_BloodHound.zip'
      - '_computers.json'
      - '_users.json'
      - '_groups.json'
  selection_adfind:
    Image|endswith: '\AdFind.exe'
    CommandLine|contains|any:
      - '-f objectcategory=computer'
      - '-f objectcategory=person'
      - 'trustdmp'
      - '-gcb'
  condition: selection_tools or selection_collection or selection_output or selection_adfind
falsepositives:
  - Authorized red team / penetration testing
  - IT audit tools performing AD enumeration
level: high
```

## Learn More

- [Offensive Security for Defenders](https://training.ridgelinecyber.com/courses/offensive-security-for-defenders/) — BloodHound attack path analysis
- [Purple Team Operations](https://training.ridgelinecyber.com/courses/purple-teaming-for-blue-teams/) — AD reconnaissance validation
