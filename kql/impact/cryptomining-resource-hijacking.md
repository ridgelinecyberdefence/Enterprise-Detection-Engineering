# Resource Hijacking: Cryptomining Detection

Detects cryptomining activity on endpoints and cloud resources by identifying connections to known mining pools, high sustained CPU usage from suspicious processes, and mining-related command-line patterns. Cryptojacking is the most common impact technique in cloud environments. Attackers use compromised compute resources to mine cryptocurrency.

## ATT&CK

- **Technique:** T1496, Resource Hijacking
- **Tactic:** Impact

## Severity

**High.** Cryptomining indicates an active compromise. The mining itself causes financial damage (compute costs), but the attacker's access to the environment means they can pivot to data theft or destructive actions at any time.

## Data Sources

- Microsoft Defender for Endpoint, `DeviceNetworkEvents`, `DeviceProcessEvents`
- Requires: Defender for Endpoint P2

## Query

```kql
let MiningPools = dynamic([
    "pool.minergate.com", "xmr.pool.minergate.com",
    "stratum+tcp://", "stratum+ssl://",
    "pool.hashvault.pro", "mine.moneropool.com",
    "xmrpool.eu", "pool.supportxmr.com",
    "monerohash.com", "minexmr.com",
    "nanopool.org", "xmr.nanopool.org",
    "nicehash.com", "mining.rig",
    "unmineable.com", "2miners.com",
    "ethermine.org", "f2pool.com",
    "pool.binance.com", "antpool.com"
]);
let MiningProcessPatterns = dynamic([
    "xmrig", "xmr-stak", "cpuminer", "minerd",
    "cgminer", "bfgminer", "ethminer", "nbminer",
    "phoenixminer", "t-rex", "gminer", "lolminer",
    "nanominer", "teamredminer", "srbminer",
    "randomx", "cryptonight", "kawpow"
]);
// Network connections to mining pools
let MiningConnections = DeviceNetworkEvents
| where Timestamp > ago(24h)
| where ActionType == "ConnectionSuccess"
| where RemoteUrl has_any (MiningPools)
    or RemoteUrl has "stratum"
    or RemotePort in (3333, 4444, 5555, 7777, 8888, 9999, 14433, 14444)
| project
    Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    "Mining Pool Connection" as DetectionType;
// Processes with mining-related names or command lines
let MiningProcesses = DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName has_any (MiningProcessPatterns)
    or ProcessCommandLine has_any (MiningProcessPatterns)
    or ProcessCommandLine has "stratum+tcp"
    or ProcessCommandLine has "stratum+ssl"
    or (ProcessCommandLine has "--algo" and ProcessCommandLine has "--url")
    or (ProcessCommandLine has "-o " and ProcessCommandLine has "-u " and ProcessCommandLine has "-p ")
| project
    Timestamp, DeviceName, FileName, ProcessCommandLine,
    AccountName, InitiatingProcessFileName,
    "Mining Process" as DetectionType;
union MiningConnections, MiningProcesses
| sort by Timestamp desc
```

## What Triggers This

Two complementary signals:
1. **Network**: outbound connections to known mining pool domains or the Stratum mining protocol on common mining ports
2. **Process**: executables with mining tool names or command-line patterns matching miner configuration (algorithm selection, pool URL, wallet address)

## False Positives

1. **Cryptocurrency research.** Security researchers analyzing miners. Rare in production environments.
2. **Blockchain development.** Development teams working on blockchain projects may have mining tools in test environments. Exclude known dev machines.
3. **Port overlap.** Some of the mining ports (8888, 9999) are used by legitimate services. The port-only signal should be combined with process or domain signals.

## Tuning Notes

- The mining pool domain list needs periodic updates. New pools appear regularly. Subscribe to a threat intelligence feed for mining IOCs.
- The Stratum protocol detection (`stratum+tcp://` in command lines or URLs) is the most reliable signal, it's specific to mining.
- For cloud environments, also monitor Azure resource creation for compute-heavy VM types (NC-series, GPU-enabled) in unexpected regions.

## Validation

1. In a test environment, download XMRig and configure it to connect to a test pool (don't actually mine on production hardware)
2. Verify both detection types fire: process name match and network connection
3. Remove the test miner

## Learn More

- [Detection Engineering: Resource Abuse Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). building detections for resource hijacking
- [Incident Response: Cryptojacking Response](https://ridgelinecyber.com/training/courses/practical-ir/). containing and remediating cryptomining compromises
