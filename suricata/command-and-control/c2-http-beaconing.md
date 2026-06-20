# C2 Beaconing — Suspicious HTTP Callback Patterns

Suricata rules detecting common C2 HTTP callback patterns: default Cobalt Strike malleable C2 profiles, generic beacon User-Agent strings, suspicious URI patterns, and encoded POST data characteristic of implant check-ins.

## ATT&CK

- **Technique:** T1071.001 — Application Layer Protocol: Web Protocols
- **Tactic:** Command and Control

## Severity

**High.** HTTP-based C2 callbacks are the most common C2 channel. These rules catch default and lightly customized C2 profiles.

## Rules

```
# Cobalt Strike default malleable C2 profile
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"RCY - Cobalt Strike Default Beacon HTTP GET";
    flow:to_server,established;
    content:"GET"; http_method;
    content:"/submit.php?id="; http_uri;
    content:"Mozilla/5.0 (compatible; MSIE"; http_user_agent;
    threshold:type both, track by_src, count 3, seconds 300;
    classtype:trojan-activity;
    sid:2025001; rev:1;
    metadata:mitre_attack T1071.001, severity high, author Ridgeline_Cyber;
)

# Cobalt Strike default POST beacon
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"RCY - Cobalt Strike Default Beacon HTTP POST";
    flow:to_server,established;
    content:"POST"; http_method;
    content:"/submit.php"; http_uri;
    content:"application/octet-stream"; http_content_type;
    dsize:>64;
    threshold:type both, track by_src, count 3, seconds 300;
    classtype:trojan-activity;
    sid:2025002; rev:1;
    metadata:mitre_attack T1071.001, severity high, author Ridgeline_Cyber;
)

# Suspicious short periodic HTTP GETs (generic beaconing)
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"RCY - Suspicious Periodic HTTP GET - Possible Beaconing";
    flow:to_server,established;
    content:"GET"; http_method;
    urilen:<20;
    http_user_agent; content:!"Mozilla/5.0"; content:!"Chrome"; content:!"Edge";
    threshold:type both, track by_src, count 10, seconds 600;
    classtype:trojan-activity;
    sid:2025003; rev:1;
    metadata:mitre_attack T1071.001, severity medium, author Ridgeline_Cyber;
)

# Base64-encoded POST body (common C2 data exfil)
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"RCY - Large Base64 Encoded HTTP POST Body";
    flow:to_server,established;
    content:"POST"; http_method;
    http_client_body; content:!"="; offset:64;
    pcre:"/^[A-Za-z0-9+\/]{128,}/R";
    dsize:>512;
    classtype:trojan-activity;
    sid:2025004; rev:1;
    metadata:mitre_attack T1071.001, severity medium, author Ridgeline_Cyber;
)

# Sliver HTTP C2 default profile
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"RCY - Sliver C2 Default HTTP Profile";
    flow:to_server,established;
    content:"GET"; http_method;
    content:"/info"; http_uri;
    content:"application/x-protobuf"; http_accept;
    threshold:type both, track by_src, count 3, seconds 300;
    classtype:trojan-activity;
    sid:2025005; rev:1;
    metadata:mitre_attack T1071.001, severity high, author Ridgeline_Cyber;
)

# Empty or minimal User-Agent (script/implant, not browser)
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"RCY - HTTP Request with Empty User-Agent";
    flow:to_server,established;
    content:!"User-Agent:"; http_header;
    threshold:type both, track by_src, count 5, seconds 300;
    classtype:trojan-activity;
    sid:2025006; rev:1;
    metadata:mitre_attack T1071.001, severity low, author Ridgeline_Cyber;
)
```

## False Positives

1. **Legitimate API clients.** Many API clients use minimal User-Agent strings or custom content types. The threshold of 10 requests in 10 minutes reduces noise.
2. **Update services.** Some software updaters use simple GET requests on regular intervals. Exclude known updater destinations.
3. **IoT devices.** Embedded devices may produce periodic HTTP calls with non-standard headers.

## Deployment

```bash
# Add to local.rules
cat c2-http-beaconing.rules >> /etc/suricata/rules/local.rules

# Test rules
suricata -T -c /etc/suricata/suricata.yaml

# Reload rules (live)
suricatasc -c reload-rules
```

## Learn More

- [Network Detection and Forensics — HTTP Analysis](https://ridgelinecyber.com/training/courses/network-detection-forensics/) — HTTP traffic analysis and C2 detection
- [Offensive Security for Defenders — C2 Traffic Patterns](https://ridgelinecyber.com/training/courses/offensive-security-for-defenders/) — understanding C2 HTTP profiles
