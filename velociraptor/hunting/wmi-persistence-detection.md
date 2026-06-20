# WMI Persistence Fleet Hunt

Hunts specifically for WMI-based persistence across the fleet. WMI event subscriptions are one of the stealthiest persistence mechanisms — they don't appear in Task Manager, aren't visible in the Services console, and survive reboots. This artifact enumerates all WMI event consumers, filters, and bindings, then flags any that execute commands or scripts.

## ATT&CK Coverage

- T1546.003 — Event Triggered Execution: WMI Event Subscription

## Artifact

```yaml
name: Custom.Windows.Hunting.WMIPersistence
description: |
  Hunt for WMI-based persistence by enumerating event consumers,
  event filters, and filter-to-consumer bindings. Flags any
  consumer that executes commands, scripts, or ActiveScript code.

type: CLIENT

sources:
  - name: EventConsumers
    description: All WMI event consumers (the action that fires)
    query: |
      LET CommandConsumers = SELECT parse_string_with_regex(
             string=FullPath,
             regex="__EventConsumer\\.Name=\"(?P<ConsumerName>.+)\"").ConsumerName AS Name,
             FullPath,
             Data.value AS ExecutablePath,
             "CommandLineEventConsumer" AS ConsumerType,
             "HIGH" AS Risk
      FROM glob(
        globs="ROOT/subscription:CommandLineEventConsumer.*",
        accessor="wmicli"
      )

      LET ScriptConsumers = SELECT parse_string_with_regex(
             string=FullPath,
             regex="__EventConsumer\\.Name=\"(?P<ConsumerName>.+)\"").ConsumerName AS Name,
             FullPath,
             Data.value AS ScriptText,
             "ActiveScriptEventConsumer" AS ConsumerType,
             "CRITICAL" AS Risk
      FROM glob(
        globs="ROOT/subscription:ActiveScriptEventConsumer.*",
        accessor="wmicli"
      )

      SELECT * FROM chain(a=CommandConsumers, b=ScriptConsumers)

  - name: EventFilters
    description: All WMI event filters (the trigger condition)
    query: |
      SELECT parse_string_with_regex(
             string=FullPath,
             regex="__EventFilter\\.Name=\"(?P<FilterName>.+)\"").FilterName AS Name,
             FullPath,
             Data.value AS Query,
             "EventFilter" AS Type
      FROM glob(
        globs="ROOT/subscription:__EventFilter.*",
        accessor="wmicli"
      )

  - name: Bindings
    description: Filter-to-consumer bindings (connects trigger to action)
    query: |
      SELECT * FROM Artifact.Windows.Persistence.PermanentWMIEvents()

  - name: Summary
    description: Consolidated view with risk assessment
    query: |
      SELECT * FROM Artifact.Windows.Persistence.PermanentWMIEvents()
```

## Why WMI Persistence Is Dangerous

Most Windows endpoints have zero legitimate WMI event subscriptions. Any WMI persistence found during a hunt should be investigated:

- `CommandLineEventConsumer` executes arbitrary commands at system privileges
- `ActiveScriptEventConsumer` runs VBScript/JScript in memory — no file on disk
- Event filters can trigger on system events (boot, logon, time interval) making execution reliable
- WMI persistence survives reboots and doesn't show in any standard admin console

## Learn More

- [Purple Team Operations — WMI Persistence](https://ridgelinecyber.com/training/courses/purple-teaming-for-blue-teams/) — WMI event subscription testing
- [Detection Engineering — WMI Detection Rules](https://ridgelinecyber.com/training/courses/detection-engineering/)
