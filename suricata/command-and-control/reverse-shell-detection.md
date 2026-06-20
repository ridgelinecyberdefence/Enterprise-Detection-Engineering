# Reverse Shell Network Detection

Suricata rules detecting reverse shell traffic at the network layer: interactive shell characteristics over TCP, common reverse shell ports, and shell command patterns in cleartext streams. Catches reverse shells that endpoint-based detection misses — particularly from containers, IoT devices, and systems without EDR.

## ATT&CK

- **Technique:** T1059.004 — Unix Shell, T1071 — Application Layer Protocol
- **Tactic:** Execution, Command and Control

## Severity

**Critical.** Network-layer reverse shell detection is the last line of defense when endpoint detection is absent or bypassed.

## Rules

```
# Interactive shell characteristics in TCP stream (bash prompt)
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"RCY - Possible Reverse Shell - Interactive Shell Prompt";
    flow:established;
    content:"uid="; content:"gid=";
    classtype:trojan-activity;
    sid:2025050; rev:1;
    metadata:mitre_attack T1059.004, severity critical, author Ridgeline_Cyber;
)

# Bash reverse shell /dev/tcp pattern in stream
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"RCY - Bash Reverse Shell - /dev/tcp Pattern";
    flow:to_server,established;
    content:"/dev/tcp/"; fast_pattern;
    classtype:trojan-activity;
    sid:2025051; rev:1;
    metadata:mitre_attack T1059.004, severity critical, author Ridgeline_Cyber;
)

# Shell commands in outbound TCP stream
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"RCY - Shell Commands in Outbound TCP - Possible Reverse Shell";
    flow:established;
    content:"whoami"; pcre:"/(?:whoami|id|uname\s+-a|cat\s+\/etc\/passwd|ifconfig|ip\s+addr|hostname)/";
    threshold:type both, track by_src, count 3, seconds 30;
    classtype:trojan-activity;
    sid:2025052; rev:1;
    metadata:mitre_attack T1059.004, severity high, author Ridgeline_Cyber;
)

# Common reverse shell ports from internal hosts
alert tcp $HOME_NET any -> $EXTERNAL_NET 4444 (
    msg:"RCY - Outbound Connection on Port 4444 - Common Reverse Shell Port";
    flow:to_server,established;
    threshold:type limit, track by_src, count 1, seconds 3600;
    classtype:trojan-activity;
    sid:2025053; rev:1;
    metadata:mitre_attack T1571, severity medium, author Ridgeline_Cyber;
)

alert tcp $HOME_NET any -> $EXTERNAL_NET 1234 (
    msg:"RCY - Outbound Connection on Port 1234 - Common Reverse Shell Port";
    flow:to_server,established;
    threshold:type limit, track by_src, count 1, seconds 3600;
    classtype:trojan-activity;
    sid:2025054; rev:1;
    metadata:mitre_attack T1571, severity medium, author Ridgeline_Cyber;
)

alert tcp $HOME_NET any -> $EXTERNAL_NET 9001 (
    msg:"RCY - Outbound Connection on Port 9001 - Common Reverse Shell Port";
    flow:to_server,established;
    threshold:type limit, track by_src, count 1, seconds 3600;
    classtype:trojan-activity;
    sid:2025055; rev:1;
    metadata:mitre_attack T1571, severity medium, author Ridgeline_Cyber;
)

# Python reverse shell pattern
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"RCY - Python Reverse Shell Pattern in Stream";
    flow:established;
    content:"import socket"; content:"subprocess";
    classtype:trojan-activity;
    sid:2025056; rev:1;
    metadata:mitre_attack T1059.006, severity critical, author Ridgeline_Cyber;
)
```

## Learn More

- [Network Detection and Forensics — Reverse Shell Detection](https://ridgelinecyber.com/training/courses/network-detection-forensics/) — network-layer shell detection techniques
- [Linux IR — Reverse Shell Investigation](https://ridgelinecyber.com/training/courses/linux-endpoint-investigation/) — identifying and containing active reverse shells
