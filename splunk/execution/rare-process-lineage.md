# Rare Process Lineage — Fleet-Unique Parent-Child Pair

Detects a parent-child process relationship seen on only one host across the entire fleet. Commodity software produces the same lineages everywhere; a parent-child pair unique to a single machine is either a rare legitimate tool or the bespoke execution chain of an intrusion, and it surfaces without any signature.

## ATT&CK

- **Technique:** T1059 — Command and Scripting Interpreter
- **Tactic:** Execution

## Severity

**Medium.** Rarity is suspicious rather than conclusive, so it sits at Medium as a hunting surface. It rises when the host is internet-facing or high-priority, or when the child is an interpreter or LOLBin.

## Data Sources

- Endpoint process telemetry mapped to the CIM Endpoint data model — Sysmon Event ID 1, EDR, or Windows 4688
- Requires: data-model acceleration for `tstats`; an `asset` lookup for host context

## Query

```spl
| tstats summariesonly=t count from datamodel=Endpoint where nodename="Endpoint.Processes"
    by Endpoint.dest, Endpoint.parent_process_name, Endpoint.process_name
| eventstats dc(Endpoint.dest) AS fleet_hosts by Endpoint.parent_process_name, Endpoint.process_name
| where fleet_hosts=1
| stats values(Endpoint.process_name) AS rare_children, count AS rare_lineages by Endpoint.dest
| lookup asset nt_host AS Endpoint.dest OUTPUT priority, is_internet_facing
| sort - rare_lineages
```

## What Triggers This

A host running lineages nothing else runs:

- A parent-child pair observed on exactly one host across the fleet
- Several such rare lineages concentrated on one machine
- The host being internet-facing or high-priority, which raises the stakes

## False Positives

1. **Niche software.** A tool installed on one workstation produces unique lineages. Build a per-host baseline and exclude known niche apps.
2. **Developer and engineering hosts.** These run varied toolchains and generate rarity. Treat them as a separate, higher-threshold population.
3. **New deployments.** A newly imaged host before it normalises. Re-baseline after rollout.

## Tuning Notes

- **Baseline per host class.** Compare against a per-role baseline so engineering hosts do not dominate.
- **Enrich with assets.** Use the `asset` lookup so internet-facing and high-priority hosts rank first.
- **Weight the child.** Promote rare lineages whose child is an interpreter or LOLBin.

## Validation

1. On a single test host, run an uncommon parent-child chain not present elsewhere.
2. Confirm the host surfaces with `fleet_hosts=1` for that lineage.

## Learn More

- [Splunk Detection and Incident Response — Endpoint Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/) — fleet-relative rarity and lineage baselining
- [Threat Hunting in Microsoft 365](https://ridgelinecyber.com/training/courses/threat-hunting-m365/) — rarity-driven hunting
