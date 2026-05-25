# C2 Beaconing — Periodic Callback Detection

Detects command-and-control beaconing by identifying network connections with suspiciously regular timing intervals. C2 frameworks (Cobalt Strike, Sliver, Havoc, Mythic) call home on a schedule — typically every 30-120 seconds with a jitter factor. This regularity is statistically distinguishable from human browsing and legitimate application traffic.

## ATT&CK

- **Technique:** T1071.001 — Application Layer Protocol: Web Protocols
- **Tactic:** Command and Control

## Severity

**High.** Regular beaconing to an external host is one of the strongest indicators of an active C2 channel. If the destination is uncategorized or recently registered, escalate to Critical.

## Data Sources

- Microsoft Defender for Endpoint — `DeviceNetworkEvents` table
- Requires: Defender for Endpoint P2 or Defender XDR

## Query

```kql
let TimePeriod = 6h;
let MinConnections = 20;
let MaxJitterPercent = 25;
DeviceNetworkEvents
| where Timestamp > ago(TimePeriod)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| where isnotempty(RemoteUrl) or isnotempty(RemoteIP)
| summarize
    ConnectionCount = count(),
    Timestamps = make_list(Timestamp, 500),
    DistinctPorts = dcount(RemotePort),
    BytesSent = sum(SentBytes),
    BytesReceived = sum(ReceivedBytes)
    by DeviceName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName
| where ConnectionCount >= MinConnections
| mv-apply Timestamps to typeof(datetime) on (
    sort by Timestamps asc
    | extend NextTimestamp = next(Timestamps)
    | where isnotempty(NextTimestamp)
    | extend IntervalMs = datetime_diff("millisecond", NextTimestamp, Timestamps)
    | summarize
        AvgIntervalMs = avg(IntervalMs),
        StdDevIntervalMs = stdev(IntervalMs),
        MinIntervalMs = min(IntervalMs),
        MaxIntervalMs = max(IntervalMs),
        IntervalCount = count()
)
| where AvgIntervalMs > 5000           // faster than 5s is likely app traffic
| where AvgIntervalMs < 7200000        // slower than 2h is unlikely beaconing
| extend JitterPercent = round(StdDevIntervalMs / AvgIntervalMs * 100, 1)
| where JitterPercent < MaxJitterPercent
| extend AvgIntervalSec = round(AvgIntervalMs / 1000, 1)
| project
    DeviceName,
    RemoteIP,
    RemoteUrl,
    RemotePort,
    InitiatingProcessFileName,
    ConnectionCount,
    AvgIntervalSec,
    JitterPercent,
    DistinctPorts,
    BytesSent,
    BytesReceived
| sort by JitterPercent asc
```

## What Triggers This

A process on an endpoint makes outbound connections to the same remote IP at regular intervals with low timing variance. The statistical signature:
- 20+ connections within 6 hours
- Average interval between 5 seconds and 2 hours
- Timing jitter under 25% of the average interval (human browsing jitter is typically 60-200%)

Cobalt Strike's default sleep is 60s with 0% jitter. Even with 20% jitter configured, the regularity is detectable.

## False Positives

1. **Telemetry and monitoring agents.** EDR, SIEM, and RMM tools beacon to their management servers on regular schedules. Exclude known agent processes and destination IPs.
2. **Cloud sync services.** OneDrive, Dropbox, and similar services check for changes on regular intervals. Exclude by process name and known destination domains.
3. **Heartbeat and health checks.** Applications that send heartbeats to cloud services. Exclude by process and destination after validation.
4. **Windows Update and OS telemetry.** Exclude `svchost.exe` connections to Microsoft IP ranges.

## Tuning Notes

- Start with `MaxJitterPercent = 15` for high-confidence detections, widen to 25 if your environment has few results
- The `MinConnections` threshold of 20 assumes 6 hours of data. Scale proportionally if you change `TimePeriod`
- Build an exclusion list of known monitoring agents and their destination IPs in the first week
- Combine with threat intelligence: if `RemoteIP` resolves to a domain registered in the last 30 days, escalate severity

## Validation

1. Use a C2 framework in a test lab (Sliver or Mythic with a test implant) configured with 60s sleep and 10% jitter
2. Verify the detection fires and captures the process name, remote IP, interval, and jitter percentage
3. Test with 20% and 30% jitter to confirm the threshold catches realistic C2 configurations

## Learn More

- [Threat Hunting — Network Anomaly Detection](https://training.ridgelinecyber.com/courses/threat-hunting/) — statistical hunting for beaconing patterns
- [Detection Engineering — Network Detection Rules](https://training.ridgelinecyber.com/courses/detection-engineering/) — building and tuning network-layer detections
- [Offensive Security for Defenders — C2 Frameworks](https://training.ridgelinecyber.com/courses/offensive-security-defenders/) — how C2 frameworks operate and how to detect them
