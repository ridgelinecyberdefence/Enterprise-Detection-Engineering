# DCSync — Directory Replication Privilege Abuse

Detects DCSync attacks by identifying accounts exercising directory replication privileges (DS-Replication-Get-Changes and DS-Replication-Get-Changes-All) from non-domain-controller sources. DCSync extracts every password hash in the domain without touching LSASS, without running code on a DC, and without triggering most endpoint detections.

## ATT&CK

- **Technique:** T1003.006 — OS Credential Dumping: DCSync
- **Tactic:** Credential Access

## Severity

**Critical.** A successful DCSync gives the attacker the NTLM hash for every account in the domain, including `krbtgt`. With the `krbtgt` hash, the attacker forges Golden Tickets for persistent, undetectable domain admin access. This is typically the final step before full domain compromise.

## Data Sources

- Windows Security Event Log — Event ID 4662 (Directory Service Access) on Domain Controllers
- Requires: Advanced Audit Policy → DS Access → Audit Directory Service Access (Success)
- Sentinel: `SecurityEvent` table, or `Event` table with Windows Security Events connector

## Query — KQL (Sentinel)

```kql
let domainControllers = dynamic(["DC01", "DC02"]);
// DS-Replication-Get-Changes + DS-Replication-Get-Changes-All GUIDs
let replicationGUIDs = dynamic([
    "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}",
    "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}",
    "{89e95b76-444d-4c62-991a-0facbeda640c}"
]);
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4662
| where Properties has_any (replicationGUIDs)
| where AccountType != "Machine"
| extend SourceHost = tostring(split(Computer, ".")[0])
| where SourceHost !in (domainControllers)
| extend TargetAccount = SubjectUserName
| extend TargetDomain = SubjectDomainName
| project
    TimeGenerated,
    Computer,
    TargetAccount,
    TargetDomain,
    Properties,
    AccessMask,
    ObjectType,
    SourceHost
| sort by TimeGenerated desc
```

## Why This Detection Is Effective

DCSync is devastating because it uses a legitimate Active Directory replication protocol. Domain controllers replicate password data between each other using the Directory Replication Service (DRS) Remote Protocol. Tools like Mimikatz (`lsadump::dcsync`), Impacket's `secretsdump.py`, and DSInternals impersonate a domain controller by calling `DRSGetNCChanges` with the replication privileges.

The behavioral invariant: only domain controllers should exercise `DS-Replication-Get-Changes-All`. If a non-DC account calls this, it's either a misconfigured service account or an active attack. The set of legitimate sources is small, static, and known — your domain controllers. Anything else is suspicious.

This detection is highly reliable because:
- The replication GUIDs are specific and rarely appear in legitimate non-DC activity
- The `AccountType != "Machine"` filter removes DC machine account replication (normal inter-DC replication)
- The `SourceHost !in (domainControllers)` filter focuses on non-DC sources
- False positive rate in production: near zero in environments with properly managed DC infrastructure

## What Triggers This

1. Attacker compromises an account with `DS-Replication-Get-Changes-All` rights (typically Domain Admin, or an account with the replication privilege delegated)
2. Attacker runs Mimikatz: `lsadump::dcsync /domain:corp.local /user:krbtgt` from a workstation
3. The workstation sends DRS replication requests to a domain controller
4. The DC logs Event ID 4662 with the replication GUIDs in the Properties field
5. The detection fires because the source host is not in the DC list

The attacker now has the `krbtgt` NTLM hash and can forge Golden Tickets for unlimited, persistent domain admin access. The Golden Ticket is valid until the `krbtgt` password is reset twice (to invalidate both the current and previous key).

## False Positives

1. **Azure AD Connect.** The AD Connect server exercises replication privileges to synchronize password hashes to Entra ID. Add the AD Connect server hostname to the `domainControllers` list (it's a legitimate replication source).
2. **Third-party identity sync tools.** Products like MIM, Okta AD Agent, or PingFederate may require replication privileges. Validate and add to the exclusion list.
3. **Backup solutions.** Some AD-aware backup tools (Veeam, Commvault) request replication data for system state backups. These should run on designated servers with known hostnames.
4. **DVCS/migration tools.** Active Directory Migration Tool and similar utilities use replication during migrations. These are temporary and should be time-bounded exclusions.

## Tuning Notes

- **Populate the DC list.** The `domainControllers` dynamic list must include every DC hostname in your environment. Miss one and you get false positives from legitimate replication. Run: `Get-ADDomainController -Filter * | Select-Object Name`
- **Include AD Connect servers.** If you use Azure AD Connect with Password Hash Sync, the AD Connect server is a legitimate replication source. Add it explicitly.
- **Monitor the exclusion list.** Any account added to the exclusion list has the capability to extract every password hash in the domain. Review the list quarterly and remove entries that are no longer needed.
- **Alert on privilege assignment.** Complement this detection with a rule that fires when `DS-Replication-Get-Changes-All` is granted to any new account (Event ID 5136 with the replication GUID). The privilege assignment is the precursor; the DCSync execution is the attack.
- **Sentinel deployment:** NRT rule. DCSync events should be near-zero in normal operations. Entity mapping: `TargetAccount` as Account, `SourceHost` as Host.

## Validation

1. In an isolated test domain (never production), run:
   ```
   mimikatz # lsadump::dcsync /domain:test.local /user:testuser
   ```
2. Verify Event ID 4662 appears on the DC with the replication GUIDs
3. Verify the detection fires and captures the source host, account, and GUIDs
4. Reset the test user's password after validation

**Never test DCSync against production Active Directory.** The tool extracts real password hashes. Use an isolated lab domain.

## Response

If this detection fires on a non-excluded source:

1. **Assume full domain compromise.** The attacker likely has every password hash including `krbtgt`.
2. **Reset `krbtgt` password twice** (with a 12-24 hour gap between resets to avoid replication issues). This invalidates all existing Golden and Silver Tickets.
3. **Identify the compromised account.** The `TargetAccount` field shows which account exercised the privilege. Disable it immediately.
4. **Investigate lateral movement.** The attacker had domain-level privileges before executing DCSync. Trace the privilege escalation path from the initial compromise.
5. **Force password reset for all privileged accounts.** Domain Admins, Enterprise Admins, Schema Admins, and any service accounts with elevated privileges.

## References

- MITRE ATT&CK: [T1003.006 — DCSync](https://attack.mitre.org/techniques/T1003/006/)
- Microsoft: [Monitoring Active Directory for Signs of Compromise](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/monitoring-active-directory-for-signs-of-compromise)
- Hive Security: DCSync detection with Sentinel KQL (May 2025)
- SpecterOps: BloodHound attack path analysis — replication privilege delegation chains

## Learn More

- [Offensive Security for Defenders](https://training.ridgelinecyber.com/courses/offensive-security-for-defenders/) — DCSync execution, telemetry analysis, and detection engineering
- [Incident Response](https://training.ridgelinecyber.com/courses/practical-ir/) — domain compromise response procedures and krbtgt reset methodology
- [Purple Team Operations](https://training.ridgelinecyber.com/courses/purple-teaming-for-blue-teams/) — DCSync as part of attack chain validation
