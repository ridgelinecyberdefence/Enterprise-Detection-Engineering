# SRUM (System Resource Usage Monitor) Analysis

Parses the SRUM database (SRUDB.dat) to extract historical network usage, application resource consumption, and energy usage data per process. SRUM retains up to 30 days of data showing which processes used the network, how much data they transferred, and which network interfaces they used — invaluable for identifying data exfiltration and C2 communication patterns.

## ATT&CK Coverage

- T1048 — Exfiltration Over Alternative Protocol (network usage anomalies)
- T1071 — Application Layer Protocol (C2 traffic identification)
- T1059 — Command and Script Interpreter (process resource usage)

## Artifact

```yaml
name: Custom.Windows.Forensics.SRUM
description: |
  Parse the SRUM database for network usage, application resource
  consumption, and process execution data. Identifies high-volume
  network transfers and unusual process activity.

type: CLIENT

sources:
  - name: NetworkUsage
    description: Per-process network data transfer history
    query: |
      SELECT * FROM Artifact.Windows.Forensics.SRUM(
        Category="Network Usage"
      )

  - name: NetworkConnections
    description: Network connection history by interface
    query: |
      SELECT * FROM Artifact.Windows.Forensics.SRUM(
        Category="Network Connections"
      )

  - name: AppResourceUsage
    description: Application resource consumption (CPU, memory, I/O)
    query: |
      SELECT * FROM Artifact.Windows.Forensics.SRUM(
        Category="App Resource Usage"
      )

  - name: HighVolumeTransfers
    description: Processes with unusually high data transfer
    query: |
      SELECT AppId,
             UserSid,
             sum(BytesSent) AS TotalBytesSent,
             sum(BytesRecvd) AS TotalBytesRecvd,
             format(format="%.2f MB", args=sum(BytesSent) / 1048576.0) AS MBSent,
             format(format="%.2f MB", args=sum(BytesRecvd) / 1048576.0) AS MBReceived
      FROM Artifact.Windows.Forensics.SRUM(Category="Network Usage")
      GROUP BY AppId, UserSid
      HAVING TotalBytesSent > 104857600
      ORDER BY TotalBytesSent DESC
```

## Investigation Value

SRUM answers questions other artifacts can't:
- Which process transferred 2GB of data to the network last Tuesday?
- Was PowerShell making network connections during the compromise window?
- Which network interface (WiFi vs Ethernet vs VPN) was used for the transfer?
- How much total data left the endpoint over the past 30 days, by process?

## Learn More

- [Windows Forensics — SRUM Analysis](https://ridgelinecyber.com/training/courses/windows-endpoint-investigation/) — SRUM database forensics and network usage reconstruction
- [Network Detection and Forensics](https://ridgelinecyber.com/training/courses/network-detection-forensics/) — correlating SRUM data with network captures
