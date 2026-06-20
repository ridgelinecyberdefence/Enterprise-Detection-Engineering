# WMI Event Subscription Persistence

Detects the creation of WMI event subscriptions used for persistence. WMI subscriptions survive reboots, run as SYSTEM, and are invisible to standard persistence checks that only examine scheduled tasks, services, and Run keys. Many IR teams miss them entirely.

## ATT&CK

- **Technique:** T1546.003 — Event Triggered Execution: WMI Event Subscription
- **Tactic:** Persistence, Privilege Escalation

## Severity

**High.** WMI event subscriptions are rarely used by legitimate software. A new subscription outside of known management tools is a strong persistence indicator. The subscription runs as SYSTEM regardless of who created it.

## Data Sources

- Sysmon Event IDs 19 (WMI filter), 20 (WMI consumer), 21 (WMI binding)
- WMI Activity operational log (Microsoft-Windows-WMI-Activity/Operational)

## Query — Sigma

```yaml
title: WMI Event Subscription Persistence
id: rc-sigma-011
status: production
description: |
  Detects creation of WMI event filter, consumer, and binding
  components used for fileless persistence. WMI subscriptions
  run as SYSTEM, survive reboots, and are invisible to most
  persistence enumeration tools. Sysmon Event IDs 19/20/21
  are the primary detection source.
author: Ridgeline Cyber Detection Engineering
date: 2026/05/25
tags:
  - attack.persistence
  - attack.t1546.003
  - attack.privilege_escalation
logsource:
  product: windows
  category: wmi_event
detection:
  selection_consumer:
    EventType: 'WmiConsumerCreated'
  selection_filter:
    EventType: 'WmiFilterCreated'
  selection_binding:
    EventType: 'WmiBindingCreated'
  filter_legitimate:
    Consumer|contains:
      - 'SCM Event Log Consumer'
      - 'BVTFilter'
      - 'TSLogonFilter'
  condition: (selection_consumer or selection_filter or selection_binding) and not filter_legitimate
falsepositives:
  - SCCM/Intune client operations
  - Dell/HP/Lenovo hardware monitoring agents
  - Some AV products use WMI subscriptions for real-time monitoring
level: high
```

## Alternative — Sysmon-Specific Rule

```yaml
title: WMI Persistence via Sysmon
id: rc-sigma-011b
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID:
      - 19  # WmiEventFilter activity
      - 20  # WmiEventConsumer activity
      - 21  # WmiEventConsumerToFilter activity
  filter_system:
    User: 'SYSTEM'
    EventNamespace|contains: 'SCM Event'
  condition: selection and not filter_system
```

## What Triggers This

1. Attacker creates a WMI event filter that triggers on an event (logon, timer, process start)
2. Attacker creates a WMI event consumer that executes a command (CommandLineEventConsumer or ActiveScriptEventConsumer)
3. Attacker binds the filter to the consumer
4. Every time the trigger condition occurs, the command executes as SYSTEM

Example attacker command:
```powershell
$Filter = Set-WmiInstance -Class __EventFilter -Arguments @{
    Name = 'SystemUpdate'
    EventNamespace = 'root/cimv2'
    QueryLanguage = 'WQL'
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Arguments @{
    Name = 'SystemUpdate'
    CommandLineTemplate = 'powershell.exe -enc <payload>'
}
Set-WmiInstance -Class __FilterToConsumerBinding -Arguments @{
    Filter = $Filter
    Consumer = $Consumer
}
```

## False Positives

1. **SCCM client.** Configuration Manager creates WMI subscriptions for client health monitoring. Known consumer names include "SCM Event Log Consumer."
2. **Hardware monitoring.** Dell OpenManage, HP Insight, and Lenovo Vantage create WMI subscriptions for hardware event monitoring.
3. **Endpoint protection.** Some AV products use WMI subscriptions for real-time file monitoring. Validate and add to filter.

## Tuning Notes

- **Deploy Sysmon with WMI logging.** Sysmon Events 19/20/21 are the most reliable detection source. Without Sysmon, fall back to WMI Activity operational logs.
- **Baseline existing subscriptions.** Run `Get-WmiObject -Class __FilterToConsumerBinding -Namespace root\subscription` across your fleet to identify existing legitimate subscriptions before enabling the detection.

## Validation

1. In a test environment, create a benign WMI subscription that logs to a file
2. Verify Sysmon Events 19, 20, and 21 fire
3. Remove the subscription after testing: `Get-WmiObject -Class __FilterToConsumerBinding -Namespace root\subscription | Remove-WmiObject`

## Learn More

- [Purple Team Operations](https://ridgelinecyber.com/training/courses/purple-teaming-for-blue-teams/) — WMI persistence as part of technique validation
- [Offensive Security for Defenders](https://ridgelinecyber.com/training/courses/offensive-security-for-defenders/) — WMI attack mechanics and detection gaps
