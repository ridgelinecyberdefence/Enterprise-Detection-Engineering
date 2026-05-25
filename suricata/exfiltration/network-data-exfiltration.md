# Network Data Exfiltration Detection

Suricata rules detecting data exfiltration patterns: large outbound transfers, HTTP/HTTPS uploads to file sharing services, FTP exfiltration, and ICMP tunneling. Catches the network-layer signature of data leaving the environment.

## ATT&CK

- **Technique:** T1048 — Exfiltration Over Alternative Protocol, T1567 — Exfiltration Over Web Service
- **Tactic:** Exfiltration

## Rules

```
# Large outbound HTTP POST (data exfil via upload)
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"RCY - Large HTTP POST to External Host - Possible Data Exfiltration";
    flow:to_server,established;
    content:"POST"; http_method;
    dsize:>1048576;
    threshold:type both, track by_src, count 3, seconds 600;
    classtype:trojan-activity;
    sid:2025040; rev:1;
    metadata:mitre_attack T1048.003, severity medium, author Ridgeline_Cyber;
)

# Upload to common file sharing services
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"RCY - File Upload to External Sharing Service";
    flow:to_server,established;
    content:"POST"; http_method;
    http_host; pcre:"/(mega\.nz|dropmefiles|file\.io|transfer\.sh|gofile\.io|anonymfile|anonfiles|sendspace|wetransfer|pixeldrain|catbox\.moe)/i";
    classtype:policy-violation;
    sid:2025041; rev:1;
    metadata:mitre_attack T1567.002, severity high, author Ridgeline_Cyber;
)

# FTP data transfer to external host
alert tcp $HOME_NET any -> $EXTERNAL_NET 20:21 (
    msg:"RCY - FTP Connection to External Host";
    flow:to_server,established;
    content:"USER"; depth:4;
    classtype:policy-violation;
    sid:2025042; rev:1;
    metadata:mitre_attack T1048.003, severity medium, author Ridgeline_Cyber;
)

# ICMP tunnel detection (oversized ICMP packets)
alert icmp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"RCY - Oversized ICMP Packet - Possible ICMP Tunnel";
    dsize:>128;
    itype:8;
    threshold:type both, track by_src, count 10, seconds 60;
    classtype:trojan-activity;
    sid:2025043; rev:1;
    metadata:mitre_attack T1095, severity medium, author Ridgeline_Cyber;
)

# Sustained outbound connection with high byte count
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"RCY - Sustained High-Volume Outbound TCP Session";
    flow:to_server,established;
    stream_size:server,>,10485760;
    threshold:type limit, track by_src, count 1, seconds 3600;
    classtype:trojan-activity;
    sid:2025044; rev:1;
    metadata:mitre_attack T1048, severity medium, author Ridgeline_Cyber;
)
```

## Learn More

- [Network Detection and Forensics — Traffic Analysis](https://training.ridgelinecyber.com/courses/network-detection-forensics/) — exfiltration pattern detection
- [Threat Hunting — Data Exfiltration](https://training.ridgelinecyber.com/courses/threat-hunting/) — hunting for data theft indicators
