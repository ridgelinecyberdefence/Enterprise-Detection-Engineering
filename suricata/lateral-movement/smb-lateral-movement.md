# SMB Lateral Movement Detection

Suricata rules detecting lateral movement via SMB: PsExec service creation, remote file writes to admin shares, SMB-based exploitation, and suspicious named pipe activity. These rules catch the network-layer signatures of the most common Windows lateral movement techniques.

## ATT&CK

- **Technique:** T1021.002. Remote Services: SMB/Windows Admin Shares
- **Tactic:** Lateral Movement

## Severity

**High.** SMB lateral movement between internal hosts indicates an active intrusion. Any alert should trigger immediate investigation of both source and destination endpoints.

## Data Sources

Suricata or a Suricata-compatible IDS with the relevant protocol parsers enabled, positioned where it can see the traffic. These rules assume `$HOME_NET` and `$EXTERNAL_NET` are set correctly for your estate, which is the most common reason a network rule appears to do nothing.

Rules matching on payload need unencrypted traffic. Where TLS terminates upstream of the sensor, place it after termination or accept that only the metadata rules fire.

## Query: Sigma
```
# PsExec-style service creation over SMB
alert smb $HOME_NET any -> $HOME_NET any (
    msg:"RCY - PsExec Service Creation via SMB";
    flow:to_server,established;
    content:"|FF|SMB"; offset:0; depth:4;
    content:"PSEXE"; nocase;
    classtype:trojan-activity;
    sid:2025020; rev:1;
    metadata:mitre_attack T1021.002, severity high, author Ridgeline_Cyber;
)

# File write to ADMIN$ or C$ share
alert smb $HOME_NET any -> $HOME_NET any (
    msg:"RCY - File Write to Administrative Share";
    flow:to_server,established;
    smb.share; content:"ADMIN$";
    classtype:trojan-activity;
    sid:2025021; rev:1;
    metadata:mitre_attack T1021.002, severity high, author Ridgeline_Cyber;
)

alert smb $HOME_NET any -> $HOME_NET any (
    msg:"RCY - File Write to C$ Share";
    flow:to_server,established;
    smb.share; content:"C$";
    classtype:trojan-activity;
    sid:2025022; rev:1;
    metadata:mitre_attack T1021.002, severity medium, author Ridgeline_Cyber;
)

# Executable written to remote share
alert smb $HOME_NET any -> $HOME_NET any (
    msg:"RCY - Executable Written to Remote SMB Share";
    flow:to_server,established;
    smb.filename; content:".exe"; nocase; endswith;
    classtype:trojan-activity;
    sid:2025023; rev:1;
    metadata:mitre_attack T1570, severity high, author Ridgeline_Cyber;
)

alert smb $HOME_NET any -> $HOME_NET any (
    msg:"RCY - DLL Written to Remote SMB Share";
    flow:to_server,established;
    smb.filename; content:".dll"; nocase; endswith;
    classtype:trojan-activity;
    sid:2025024; rev:1;
    metadata:mitre_attack T1570, severity high, author Ridgeline_Cyber;
)

# Impacket/smbexec named pipe pattern
alert smb $HOME_NET any -> $HOME_NET any (
    msg:"RCY - Impacket SMBExec Named Pipe Pattern";
    flow:to_server,established;
    smb.named_pipe; pcre:"/^__output_[a-f0-9]{8}/i";
    classtype:trojan-activity;
    sid:2025025; rev:1;
    metadata:mitre_attack T1021.002, severity critical, author Ridgeline_Cyber;
)
```

## What Triggers This

Remote execution and staging over SMB inside the estate. PsExec service creation, matched on the `PSEXE` service binary name in the SMB payload. And file writes to the administrative shares, matched on `ADMIN$` and `C$`.

All of these are internal, `$HOME_NET` to `$HOME_NET`. That is the point: lateral movement does not cross the perimeter, so a perimeter sensor sees none of it.

## False Positives

1. **Systems management tooling.** SCCM, PDQ Deploy, LANDesk and most software deployment platforms write to administrative shares and create remote services as their normal function. On a managed estate this produces near-continuous hits from a small number of servers.
2. **Legitimate PsExec use.** It remains in wide administrative use, and the rule matches the tool rather than who is holding it.
3. **Backup and inventory agents** that read and write administrative shares on a schedule.
4. **Vulnerability and asset scanners** authenticating to administrative shares to enumerate hosts.
5. **A renamed service binary defeats the PsExec rule entirely.** The `PSEXE` string is the default; anyone using the tool seriously changes it, and the many PsExec-equivalent tools never had it.

## Tuning Notes

- **Source is the whole tuning strategy for this rule set.** Deployment and management servers legitimately do this to everything; workstations should never do it to each other. Allow the management sources explicitly, then alert on any other source, and this becomes one of the more valuable internal rules.
- **Workstation to workstation is the finding.** If you can express source and destination roles, that single condition removes most false positives without weakening detection, because lateral movement between peers is what you are looking for.
- **Sensor placement decides whether this works at all.** Internal SMB does not traverse a perimeter sensor. Without east-west visibility, or at minimum visibility of the datacentre and client segments, these rules will never fire.
- **Do not rely on the `PSEXE` content match.** Treat it as a bonus catch for unsophisticated use, and lean on the administrative share writes, which every equivalent tool must do.
- **SMB signing and encryption affect what the sensor can read.** Where SMB3 encryption is enforced the payload matches fail and only the connection metadata remains.

## Learn More

- [Threat Detection Engineering](https://ridgelinecyber.com/training/courses/detection-engineering/)
- [Purple Teaming for Blue Teams](https://ridgelinecyber.com/training/courses/purple-teaming-for-blue-teams/)
