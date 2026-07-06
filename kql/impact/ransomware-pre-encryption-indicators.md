# Ransomware Pre-Encryption: Shadow Copy Deletion and Recovery Disabled

Detects the pre-encryption phase of a ransomware attack by identifying shadow copy deletion, Windows Recovery Environment disabling, boot configuration modifications, and backup catalog wiping. These operations occur minutes before file encryption begins. They are the attacker's final preparation to ensure the victim cannot recover without paying the ransom.

## ATT&CK

- **Technique:** T1490. Inhibit System Recovery, T1486, Data Encrypted for Impact
- **Tactic:** Impact

## Severity

**Critical.** If this detection fires on a production endpoint, ransomware encryption is imminent or already in progress. Response time is measured in seconds. Immediately isolate the endpoint and every endpoint that shares credentials with it.

## Data Sources

- Defender for Endpoint, `DeviceProcessEvents` table
- Alternative: Sysmon Event ID 1 via `SecurityEvent` or `Event` table
- Enhanced: `DeviceFileEvents` for file encryption pattern detection
- Requires: Command line logging enabled

## Query: KQL (Defender XDR / Sentinel)

```kql
let lookback = 1h;
// Recovery inhibition commands — the ransomware preparation signature
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where (
    // Shadow copy deletion — vssadmin, wmic, PowerShell
    (FileName =~ "vssadmin.exe" and ProcessCommandLine has "delete shadows")
    or (FileName =~ "vssadmin.exe" and ProcessCommandLine has "resize shadowstorage" and ProcessCommandLine has "/maxsize=")
    or (FileName in~ ("wmic.exe", "WMIC.exe") and ProcessCommandLine has "shadowcopy" and ProcessCommandLine has "delete")
    or (FileName in~ ("powershell.exe", "pwsh.exe") and ProcessCommandLine has "Win32_ShadowCopy" and ProcessCommandLine has_any ("Delete", "Remove"))
    // Windows Recovery disabled
    or (FileName =~ "bcdedit.exe" and ProcessCommandLine has_any (
        "recoveryenabled no",
        "bootstatuspolicy ignoreallfailures",
        "safeboot"
    ))
    or (FileName =~ "reagentc.exe" and ProcessCommandLine has "/disable")
    // Backup catalog wiped
    or (FileName =~ "wbadmin.exe" and ProcessCommandLine has "delete" and ProcessCommandLine has_any ("catalog", "systemstatebackup", "backup"))
    // Event log clearing — destroy forensic evidence
    or (FileName =~ "wevtutil.exe" and ProcessCommandLine has_any ("cl", "clear-log"))
    or (FileName in~ ("powershell.exe", "pwsh.exe") and ProcessCommandLine has "Clear-EventLog")
    // Disable Windows Defender — remove last line of defense
    or (FileName in~ ("powershell.exe", "pwsh.exe") and ProcessCommandLine has "Set-MpPreference" and ProcessCommandLine has_any (
        "DisableRealtimeMonitoring $true",
        "DisableIOAVProtection $true",
        "DisableBehaviorMonitoring $true"
    ))
)
| extend TechniqueCategory = case(
    ProcessCommandLine has_any ("shadowcopy", "shadow", "vssadmin"), "Shadow Copy Deletion",
    ProcessCommandLine has_any ("recoveryenabled", "bootstatuspolicy", "reagentc"), "Recovery Disabled",
    ProcessCommandLine has_any ("wbadmin", "catalog"), "Backup Wiped",
    ProcessCommandLine has_any ("wevtutil", "Clear-EventLog"), "Event Log Cleared",
    ProcessCommandLine has_any ("DisableRealtimeMonitoring", "DisableIOAV", "DisableBehavior"), "Defender Disabled",
    "Other"
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    TechniqueCategory,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FolderPath
| sort by DeviceName asc, Timestamp asc
```

## Why This Detection Is Effective

Ransomware operators follow a predictable pre-encryption sequence because they must. Encrypting files is irreversible from the victim's perspective only if recovery is impossible. The preparation sequence is:

1. **Delete shadow copies**. Removes Volume Shadow Copy snapshots that would allow file restoration
2. **Disable Windows Recovery**. Prevents booting to recovery mode
3. **Wipe backup catalogs**. Removes Windows Server Backup metadata
4. **Clear event logs**. Destroys forensic evidence of the attacker's activity
5. **Disable endpoint protection**. Prevents the AV from stopping the encryption binary

Each of these operations uses well-known system utilities. The detection covers every common method for each operation. Vssadmin, WMIC, PowerShell WMI, bcdedit, reagentc, wbadmin, and wevtutil.

The 1-hour lookback is deliberately short. These operations occur in a burst immediately before encryption. A longer lookback would catch legitimate administrative operations. The tight window focuses on the attack pattern: multiple recovery-inhibition commands in rapid succession.

## What Triggers This

1. Ransomware operator gains admin access to the endpoint (typically via RDP, PsExec, or compromised RMM tool)
2. Operator executes the preparation sequence. Shadow copy deletion, recovery disable, backup wipe
3. Each command fires independently. A single detection. Multiple detections on the same host within minutes is the strongest signal.
4. Encryption begins after preparation completes

If you see 2+ TechniqueCategory values on the same DeviceName within the lookback window, encryption is imminent or in progress.

## False Positives

1. **System administrators managing storage.** `vssadmin resize shadowstorage` is used legitimately to manage shadow copy disk usage. The `delete shadows` variant is almost never legitimate. Distinguish by the specific subcommand.
2. **Build/deployment scripts.** Some deployment pipelines clear shadow copies and event logs as part of image preparation. These run from known automation accounts on known build servers.
3. **Disk space recovery.** IT operations may delete shadow copies to free disk space during emergencies. This should be a documented, approved operation, not an ad-hoc command.

## Tuning Notes

- **Multi-event correlation.** The highest-fidelity version of this detection requires 2+ different TechniqueCategory values on the same device within 1 hour. A single shadow copy deletion might be administrative. Shadow copy deletion + recovery disabled + event log cleared is ransomware.
- **Exclude known admin accounts.** If specific service accounts run legitimate maintenance scripts that touch shadow copies, exclude by `AccountName`. But audit these exclusions quarterly.
- **Endpoint isolation automation.** In Sentinel, configure an automation rule that triggers endpoint isolation (via Defender for Endpoint API) when this detection fires with 2+ technique categories. The time between detection and isolation is the time the ransomware has to encrypt files.
- **Sentinel deployment:** NRT rule. This is a last-line detection. Entity mapping: `DeviceName` as Host, `AccountName` as Account.

## Response

**This is a time-critical response. Every second matters.**

1. **Isolate the endpoint immediately.** Use Defender for Endpoint: Isolate device. Or network-level isolation via switch port shutdown. Do not wait for investigation.
2. **Isolate every endpoint that shares credentials.** If the compromised account is a domain admin, the attacker likely has access to every domain-joined system. Isolate systems in the same admin tier.
3. **Check for lateral movement.** Query for RDP, PsExec, WMI, and WinRM connections from the affected endpoint to other systems in the last 24 hours.
4. **Preserve evidence.** Capture memory and disk from the affected endpoint before reimaging.
5. **Identify the ransomware variant.** Check the encrypted file extension, ransom note filename, and process name. Submit to ID Ransomware (id-ransomware.malwarehunterteam.com) for variant identification and potential decryptor availability.
6. **Do not pay the ransom** without consulting legal counsel and your cyber insurance provider.

## References

- MITRE ATT&CK: [T1490](https://attack.mitre.org/techniques/T1490/), [T1486](https://attack.mitre.org/techniques/T1486/)
- CISA: [Ransomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide)
- M-Trends 2025: Ransomware pre-encryption behavioral patterns

## Learn More

- [Incident Response](https://ridgelinecyber.com/training/courses/practical-ir/). ransomware response procedures, containment decisions, and recovery planning
- [SOC Operations: Endpoint Detection](https://ridgelinecyber.com/training/courses/m365-security-operations/). endpoint threat detection and automated response
- [Offensive Security for Defenders](https://ridgelinecyber.com/training/courses/offensive-security-for-defenders/). ransomware operator TTPs and the telemetry each step produces
