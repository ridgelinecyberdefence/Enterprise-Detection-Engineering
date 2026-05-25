# Domain Fronting — CDN Abuse for C2 Communication

Detects potential domain fronting where HTTPS traffic appears to go to a legitimate CDN or cloud provider but the TLS SNI or HTTP Host header routes to an attacker-controlled origin. Identifies endpoints with high-volume connections to CDN edge nodes where the traffic pattern doesn't match legitimate CDN usage.

## ATT&CK

- **Technique:** T1090.004 — Proxy: Domain Fronting
- **Tactic:** Command and Control

## Severity

**High.** Domain fronting is a deliberate evasion technique. Legitimate applications don't use it. Any confirmed instance indicates a sophisticated adversary with an active C2 channel designed to bypass network monitoring.

## Data Sources

- Microsoft Defender for Endpoint — `DeviceNetworkEvents` table
- Optional: Proxy logs with full URL inspection for HTTP Host header comparison

## Query

```kql
let CDNDomains = dynamic([
    "cloudfront.net", "azureedge.net", "akamaiedge.net",
    "fastly.net", "cloudflare.com", "cdn.cloudflare.net",
    "googleusercontent.com", "googleapis.com",
    "azurefd.net", "msecnd.net", "trafficmanager.net"
]);
let TimePeriod = 24h;
let MinBytes = 1048576;  // 1 MB minimum transfer
DeviceNetworkEvents
| where Timestamp > ago(TimePeriod)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| where RemoteUrl has_any (CDNDomains)
| summarize
    ConnectionCount = count(),
    TotalBytesSent = sum(SentBytes),
    TotalBytesReceived = sum(ReceivedBytes),
    DistinctRemoteIPs = dcount(RemoteIP),
    ProcessList = make_set(InitiatingProcessFileName, 10),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName, RemoteUrl, InitiatingProcessFileName
| where TotalBytesSent > MinBytes or TotalBytesReceived > MinBytes
| where InitiatingProcessFileName !in (
    "msedge.exe", "chrome.exe", "firefox.exe", "Teams.exe",
    "OneDrive.exe", "Outlook.exe", "EXCEL.EXE", "WINWORD.EXE",
    "MicrosoftEdgeUpdate.exe", "svchost.exe"
)
| extend
    SessionDurationMin = datetime_diff("minute", LastSeen, FirstSeen),
    SentMB = round(TotalBytesSent / 1048576.0, 2),
    ReceivedMB = round(TotalBytesReceived / 1048576.0, 2)
| project
    DeviceName,
    InitiatingProcessFileName,
    RemoteUrl,
    ConnectionCount,
    SentMB,
    ReceivedMB,
    DistinctRemoteIPs,
    SessionDurationMin,
    FirstSeen,
    LastSeen
| sort by SentMB desc
```

## What Triggers This

A non-browser process on an endpoint transfers significant data through a CDN endpoint. The logic:
- Connections go to known CDN domains (CloudFront, Azure CDN, Cloudflare, etc.)
- The initiating process is not a browser, Office app, or known cloud sync tool
- Data transfer exceeds 1 MB (filters out incidental CDN-routed API calls)

Domain fronting works by connecting to a CDN edge node via TLS (which appears as legitimate traffic) and then using the HTTP Host header to route the request to an attacker-controlled origin behind the same CDN.

## False Positives

1. **Developer tools.** CLI tools, SDKs, and package managers that pull from CDN-hosted repositories. Exclude after verifying the tool is expected.
2. **Background updaters.** Application update processes that download from CDN. Verify the process and exclude.
3. **Custom applications.** In-house apps that use CDN for content delivery. Catalog and exclude.

## Tuning Notes

- The process exclusion list needs environment-specific tuning. Start with browsers and Office, then add verified processes in the first week.
- Lower `MinBytes` to 100KB if you want higher sensitivity at the cost of more noise
- Combine with the beaconing detection: if the same non-browser process both beacons to a CDN domain AND transfers significant data, confidence is very high

## Validation

1. Configure a test C2 profile that routes through a CDN (Cobalt Strike malleable C2 with CloudFront profile)
2. Generate test traffic from a lab endpoint
3. Verify the detection captures the process, CDN domain, and data volume

## Learn More

- [Offensive Security for Defenders — C2 Evasion Techniques](https://training.ridgelinecyber.com/courses/offensive-security-defenders/) — domain fronting, redirectors, and CDN abuse
- [Network Detection and Forensics — TLS Analysis](https://training.ridgelinecyber.com/courses/network-detection-forensics/) — TLS inspection and SNI analysis
