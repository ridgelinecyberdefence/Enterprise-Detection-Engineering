# Network Credential Theft Detection

Suricata rules detecting credential theft and relay attacks at the network layer: NTLM relay signatures, Kerberoasting traffic patterns, LDAP cleartext bind attempts, and Responder/LLMNR poisoning indicators.

## ATT&CK

- **Technique:** T1557.001 — AitM: LLMNR/NBT-NS Poisoning, T1558.003 — Kerberoasting
- **Tactic:** Credential Access

## Rules

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

## Learn More

- [Offensive Security for Defenders — Credential Attacks](https://training.ridgelinecyber.com/courses/offensive-security-defenders/) — NTLM relay, Kerberoasting, and Responder
- [Network Detection and Forensics — Protocol Analysis](https://training.ridgelinecyber.com/courses/network-detection-forensics/) — NTLM, Kerberos, and LDAP wire analysis
