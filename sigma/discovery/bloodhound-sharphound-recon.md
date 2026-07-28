# BloodHound/SharpHound Active Directory Reconnaissance

Detects BloodHound and SharpHound collection activity, which maps Active Directory trust relationships, group memberships, sessions, ACLs, and attack paths.

## ATT&CK

- **Technique:** T1087.002. Account Discovery: Domain Account, T1069.002, Permission Groups Discovery, T1482, Domain Trust Discovery
- **Tactic:** Discovery

## Severity

**High.** BloodHound collection is a precursor to targeted privilege escalation.

## Data Sources

- Process creation with command line: Sysmon Event ID 1, Windows Security 4688

## Query: Sigma

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

## What Triggers This

A directory collector runs. The rule matches the tool names `SharpHound`, `BloodHound`, `AzureHound` and `Invoke-BloodHound`, and separately the collection arguments `-CollectionMethod`, `--OutputDirectory` and `--ZipFilename`, which fire even when the binary has been renamed.

The argument selection is the durable half. Renaming `SharpHound.exe` is trivial; changing the argument names means recompiling the collector.

## False Positives

1. **Authorised internal assessment.** Your own red team and any external tester run exactly this, and it is the intended use of the tool. Coordinate with the engagement calendar rather than excluding, so an unannounced run still surfaces.
2. **Identity hygiene and attack path tooling.** Some commercial products and internal scripts run BloodHound collectors on a schedule to report on attack paths. This is legitimate and produces regular, predictable hits from a known host and account.
3. **Security team workstations.** Analysts run the tool to understand their own estate.
4. **Argument collisions are possible but rare.** `-CollectionMethod` is distinctive enough that unrelated software matching it is unusual.

## Tuning Notes

- **This should alert, not sit in a hunt.** Directory enumeration at this depth is a precursor to privilege escalation and the volume is low enough to carry the alert.
- **Know your authorised runs.** The tuning here is organisational rather than technical: a list of the accounts and hosts permitted to run collectors, and an alert on everything else. Without that list every engagement produces an incident.
- **Keep the argument selection even if you exclude the tool names.** Renaming the binary is the first thing an operator does, and the arguments are what catch it.
- **Watch for the LDAP side as well.** A collector generates a distinctive burst of directory queries, which Defender for Identity or your domain controller telemetry will show even when the process is missed. The two together are much harder to evade than either.
- **Conversion:** `sigma convert -t splunk -p windows sigma/discovery/bloodhound-sharphound-recon.yml`

## Learn More

- [Offensive Security for Defenders](https://ridgelinecyber.com/training/courses/offensive-security-for-defenders/). BloodHound attack path analysis
- [Purple Team Operations](https://ridgelinecyber.com/training/courses/purple-teaming-for-blue-teams/). AD reconnaissance validation
