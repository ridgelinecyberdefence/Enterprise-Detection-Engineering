# Reverse Shell Network Detection

Suricata rules detecting reverse shell traffic at the network layer: interactive shell characteristics over TCP, common reverse shell ports, and shell command patterns in cleartext streams. Catches reverse shells that endpoint-based detection misses. Particularly from containers, IoT devices, and systems without EDR.

## ATT&CK

- **Technique:** T1059.004. Unix Shell, T1071, Application Layer Protocol
- **Tactic:** Execution, Command and Control

## Severity

**Critical.** Network-layer reverse shell detection is the last line of defense when endpoint detection is absent or bypassed.

## Data Sources

Suricata or Suricata-compatible IDS with the relevant protocol parsers enabled, positioned where it can see the traffic. These rules assume `$HOME_NET` and `$EXTERNAL_NET` are set correctly for your estate, which is the single most common reason a network rule appears to do nothing.

Rules matching on payload content need unencrypted traffic. Where TLS terminates upstream of the sensor, place it after termination or accept that only the metadata rules will fire.

## Query: Sigma
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

## What Triggers This

Four signals on outbound TCP. A shell prompt or `id` output crossing the wire, matched on `uid=` with `gid=`. The bash `/dev/tcp/` pattern in payload. Reconnaissance commands in outbound traffic, matched by `pcre` on `whoami`, `id`, `uname -a` and similar, thresholded at three in thirty seconds. And any outbound connection to port 4444.

The first is the strongest: `uid=` and `gid=` together in outbound payload means command output is being returned to something, which is what a shell does and very little else.

## False Positives

1. **Port 4444 is used legitimately.** It is a default for several development and debugging tools, and the rule matches the port with no payload condition, so anything using it fires. Check what uses it in your estate before deploying that rule at all.
2. **Documentation, tickets and chat.** Anyone pasting `id` output or a reverse shell one-liner into a web form sends those exact strings outbound over HTTP. Security teams do this to each other constantly.
3. **Legitimate remote administration.** Web terminals, CI job logs streaming command output, and container consoles all carry shell output over the network by design.
4. **Encrypted traffic sees none of this.** Every payload rule here is defeated by TLS, so a competent operator produces no hits at all. Treat absence as absence of evidence.

## Tuning Notes

- **Reconsider the port 4444 rule.** A port match with no content condition generates volume proportional to whatever uses that port and tells you nothing about intent. Either add a payload condition or drop it.
- **The `uid=`/`gid=` rule is the one worth alerting on.** It requires actual command output in flight and has few legitimate causes outside deliberate pasting. Give it the higher severity.
- **Exclude your ticketing and chat egress from the command-string rules.** Once staff are discussing detections, those rules fire on the discussion. This is a real and often overlooked producer in security teams.
- **Direction and destination reputation add more than payload tuning.** A shell prompt heading to a hosting provider you have no relationship with is a finding; the same bytes heading to your own web application is a paste. That distinction is not in the payload.
- **Pair with the Sigma reverse shell rule rather than choosing between them.** Process telemetry sees the intent and misses the destination; the network sees the destination and misses the intent. Neither is sufficient and together they are strong.

## Learn More

- [Threat Detection Engineering](https://ridgelinecyber.com/training/courses/detection-engineering/)
- [Linux IR: Reverse Shell Investigation](https://ridgelinecyber.com/training/courses/linux-endpoint-investigation/). identifying and containing active reverse shells
