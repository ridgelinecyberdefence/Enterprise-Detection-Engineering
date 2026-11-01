# Network Data Exfiltration Detection

Suricata rules detecting data exfiltration patterns: large outbound transfers, HTTP/HTTPS uploads to file sharing services, FTP exfiltration, and ICMP tunneling. Catches the network-layer signature of data leaving the environment.

## ATT&CK

- **Technique:** T1048. Exfiltration Over Alternative Protocol, T1567, Exfiltration Over Web Service
- **Tactic:** Exfiltration

## Data Sources

Suricata or a Suricata-compatible IDS with the relevant protocol parsers enabled, positioned where it can see the traffic. These rules assume `$HOME_NET` and `$EXTERNAL_NET` are set correctly for your estate, which is the most common reason a network rule appears to do nothing.

Rules matching on payload need unencrypted traffic. Where TLS terminates upstream of the sensor, place it after termination or accept that only the metadata rules fire.

## Query: Sigma
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

## What Triggers This

Bulk outbound transfer over three routes. Large or repeated HTTP POSTs to one external destination, thresholded at three per source in the window. POSTs to known file-sharing services. And FTP to an external host, matched on the `USER` command.

The POST rules are volume and repetition signals rather than content signals. They do not know what is being sent, only that a host is sending a lot of it to one place.

## False Positives

1. **Cloud backup and sync clients.** OneDrive, Dropbox, Google Drive and every backup agent POST continuously to one destination. This is by far the largest producer and the traffic is indistinguishable from exfiltration by shape alone.
2. **Telemetry and crash reporting.** Application and OS telemetry uploads match the repeated-POST pattern from every host you own.
3. **Legitimate file sharing.** Staff send large files through WeTransfer and similar because email limits force them to. Whether that is a policy violation is a separate question from whether it is an attack.
4. **CI artifact upload.** Build agents push large artifacts to external registries constantly.
5. **FTP still runs in places.** Elderly integrations, printer firmware and supplier file drops use it, and the rule catches the protocol rather than the intent.

## Tuning Notes

- **Allow-list before you alert.** Sanctioned sync and backup destinations account for most of the volume, and until they are excluded these rules are unusable. That list is specific to your estate and cannot be shipped.
- **Volume thresholds have to come from your own baseline.** Three POSTs in the window is low for anything and the right figure depends on the host role. Set it separately for workstations and servers.
- **Destination novelty beats destination volume.** A host uploading to a service it has never used before is a stronger signal than one uploading a lot to a service it uses daily. If your platform can hold first-seen state per source and destination, that reframes these rules from noisy to useful.
- **The FTP rule is worth keeping as an inventory tool.** Cleartext FTP leaving the estate is a finding regardless of exfiltration, and the list of offenders is usually short and fixable.

## Learn More

- [Threat Detection Engineering](https://ridgelinecyber.com/training/courses/detection-engineering/)
- [Threat Hunting: Data Exfiltration](https://ridgelinecyber.com/training/courses/threat-hunting-m365/). hunting for data theft indicators
