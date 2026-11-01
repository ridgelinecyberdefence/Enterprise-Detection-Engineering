# C2 Beaconing: Suspicious HTTP Callback Patterns

Suricata rules detecting common C2 HTTP callback patterns: default Cobalt Strike malleable C2 profiles, generic beacon User-Agent strings, suspicious URI patterns, and encoded POST data characteristic of implant check-ins.

## ATT&CK

- **Technique:** T1071.001. Application Layer Protocol: Web Protocols
- **Tactic:** Command and Control

## Severity

**High.** HTTP-based C2 callbacks are the most common C2 channel. These rules catch default and lightly customized C2 profiles.

## Data Sources

Suricata or a Suricata-compatible IDS with the relevant protocol parsers enabled, positioned where it can see the traffic. These rules assume `$HOME_NET` and `$EXTERNAL_NET` are set correctly for your estate, which is the most common reason a network rule appears to do nothing.

Rules matching on payload need unencrypted traffic. Where TLS terminates upstream of the sensor, place it after termination or accept that only the metadata rules fire.

## Query: Suricata
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

## What Triggers This

Default Cobalt Strike and Sliver profiles, plus generic periodicity. The Cobalt Strike rules match the unmodified malleable C2 URIs including `/submit.php?id=`, thresholded at three per source in the window. Others cover base64-encoded POST bodies, short periodic GETs, and minimal or absent User-Agent strings.

The default-profile rules are the strongest and the narrowest. Any operator who edits their malleable profile, which is a documented first step, defeats them entirely. The periodicity and User-Agent rules survive that but produce far more noise.

## False Positives

1. **Legitimate API clients.** Many API clients use minimal User-Agent strings or custom content types. The threshold of 10 requests in 10 minutes reduces noise.
2. **Update services.** Some software updaters use simple GET requests on regular intervals. Exclude known updater destinations.
3. **IoT devices.** Embedded devices may produce periodic HTTP calls with non-standard headers.

## Tuning Notes

- **Expect the default-profile rules to age out.** They catch unmodified tooling, which is worth having for the cost, but their absence proves nothing. Do not treat them as beacon coverage.
- **The empty User-Agent rule needs an estate baseline first.** Plenty of embedded devices, printers, scripts and health checks send no User-Agent, and on some networks that is thousands of events a day from legitimate sources.
- **Periodicity is better computed than matched.** A signature threshold approximates regularity; a proper interval analysis over proxy logs finds beacons the signature misses, including jittered ones. Use this rule as a cheap first pass and put the real detection in your SIEM.
- **Destination reputation changes the value more than any threshold.** A periodic callback to a domain registered last week is a finding; the same pattern to a monitoring SaaS is the product working.
- **Check the threshold window against your proxy's keepalive behaviour**, which can make ordinary sessions look periodic to a sensor counting requests.

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

- [Threat Detection Engineering](https://ridgelinecyber.com/training/courses/detection-engineering/)
- [Purple Teaming for Blue Teams](https://ridgelinecyber.com/training/courses/purple-teaming-for-blue-teams/)
