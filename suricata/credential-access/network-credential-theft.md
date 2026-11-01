# Network Credential Theft Detection

Suricata rules detecting credential theft and relay attacks at the network layer: NTLM relay signatures, Kerberoasting traffic patterns, LDAP cleartext bind attempts, and Responder/LLMNR poisoning indicators.

## ATT&CK

- **Technique:** T1557.001. AitM: LLMNR/NBT-NS Poisoning, T1558.003, Kerberoasting
- **Tactic:** Credential Access

## Data Sources

Suricata or a Suricata-compatible IDS with the relevant protocol parsers enabled, positioned where it can see the traffic. These rules assume `$HOME_NET` and `$EXTERNAL_NET` are set correctly for your estate, which is the most common reason a network rule appears to do nothing.

Rules matching on payload need unencrypted traffic. Where TLS terminates upstream of the sensor, place it after termination or accept that only the metadata rules fire.

## Query: Sigma
```
# NTLM authentication to external IP (relay or theft)
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"RCY - NTLM Authentication to External Host";
    flow:to_server,established;
    content:"NTLMSSP"; fast_pattern;
    content:"|03 00 00 00|"; distance:0; within:4;
    classtype:credential-theft;
    sid:2025030; rev:1;
    metadata:mitre_attack T1557.001, severity critical, author Ridgeline_Cyber;
)

# LDAP cleartext bind (password in plaintext)
alert tcp $HOME_NET any -> $HOME_NET 389 (
    msg:"RCY - LDAP Simple Bind - Cleartext Credentials";
    flow:to_server,established;
    content:"|30|"; depth:1;
    content:"|60|"; within:10;
    content:"|80|"; within:5;
    classtype:credential-theft;
    sid:2025031; rev:1;
    metadata:mitre_attack T1552.006, severity high, author Ridgeline_Cyber;
)

# Responder LLMNR poisoning response
alert udp any any -> $HOME_NET 5355 (
    msg:"RCY - LLMNR Response from Non-DNS Server - Possible Responder";
    content:"|00 00 80 00 00 01 00 01|"; depth:8;
    threshold:type both, track by_src, count 5, seconds 60;
    classtype:credential-theft;
    sid:2025032; rev:1;
    metadata:mitre_attack T1557.001, severity high, author Ridgeline_Cyber;
)

# Kerberos TGS-REQ with RC4 encryption (Kerberoasting)
alert tcp $HOME_NET any -> $HOME_NET 88 (
    msg:"RCY - Kerberos TGS-REQ with RC4 Encryption - Possible Kerberoasting";
    flow:to_server,established;
    content:"|a1 03 02 01 0d|";
    content:"|17|"; distance:0; within:30;
    threshold:type both, track by_src, count 10, seconds 60;
    classtype:credential-theft;
    sid:2025033; rev:1;
    metadata:mitre_attack T1558.003, severity high, author Ridgeline_Cyber;
)

# DCSync replication traffic from non-DC
alert tcp $HOME_NET any -> $HOME_NET 135 (
    msg:"RCY - Directory Replication from Non-Domain-Controller";
    flow:to_server,established;
    content:"|05 00 0b|"; depth:3;
    content:"drsuapi"; nocase;
    threshold:type limit, track by_src, count 1, seconds 3600;
    classtype:credential-theft;
    sid:2025034; rev:1;
    metadata:mitre_attack T1003.006, severity critical, author Ridgeline_Cyber;
)
```

## Deployment Notes

- Rule 2025034 (DCSync) requires `$HOME_NET` to exclude domain controller IPs. DCs legitimately replicate. The rule fires when a non-DC initiates replication.
- Rule 2025033 (Kerberoasting) uses a threshold of 10 TGS-REQ with RC4 in 60 seconds. A single RC4 TGS-REQ is normal (legacy compatibility). Bursts indicate Kerberoasting.

## What Triggers This

Credentials crossing the network in a form an attacker can capture or relay. NTLM authentication leaving `$HOME_NET` for an external host, matched on the `NTLMSSP` signature and the type-3 message bytes. LDAP simple bind, which carries the password in cleartext, matched on the BER structure. And responder-style poisoning traffic on LLMNR port 5355.

Outbound NTLM is the one to understand. Windows will authenticate to a UNC path anywhere it is pointed, so a link in a document can make a workstation send its hash to an attacker's server. There is no legitimate reason for NTLM to leave your estate.

## False Positives

1. **LDAP simple bind is common and legitimate in old applications.** Printers, scanners, network appliances and elderly line-of-business software bind this way as standard. On most estates this rule fires constantly and every hit is real cleartext, which makes it a genuine finding but a poor alert. Treat it as an inventory exercise first.
2. **LLMNR is on by default.** Windows uses it for name resolution whenever DNS fails, so port 5355 traffic is normal background noise. The rule catches the protocol, not the poisoning, so it cannot distinguish a responder from ordinary resolution.
3. **NTLM to a cloud or partner service.** Some hybrid configurations and federated partners legitimately receive NTLM. These are few and worth enumerating explicitly.
4. **Vulnerability scanners** deliberately generate all three patterns.

## Tuning Notes

- **Outbound NTLM deserves the highest severity here and needs almost no tuning.** Enumerate the handful of legitimate external destinations, allow those, and alert on everything else. This is one of the highest-value network rules available.
- **Run the LDAP rule as a report, not an alert.** Every hit is a real weakness and none is an incident, so a weekly list of source and destination pairs drives remediation where an alert queue drives fatigue.
- **The LLMNR rule needs pairing to be useful.** LLMNR traffic alone is noise; LLMNR followed by NTLM authentication to the responding host is the poisoning attack. If your platform can correlate, do that. If it cannot, consider disabling LLMNR at the endpoint instead, which removes the attack rather than detecting it.
- **Direction is doing the work in the NTLM rule.** Check `$HOME_NET` covers every internal range, including VPN pools and cloud subnets, or internal NTLM will look external and bury you.

## Learn More

- [Purple Teaming for Blue Teams](https://ridgelinecyber.com/training/courses/purple-teaming-for-blue-teams/)
- [Threat Detection Engineering](https://ridgelinecyber.com/training/courses/detection-engineering/)
