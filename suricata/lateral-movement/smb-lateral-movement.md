# SMB Lateral Movement Detection

Suricata rules detecting lateral movement via SMB: PsExec service creation, remote file writes to admin shares, SMB-based exploitation, and suspicious named pipe activity. These rules catch the network-layer signatures of the most common Windows lateral movement techniques.

## ATT&CK

- **Technique:** T1021.002. Remote Services: SMB/Windows Admin Shares
- **Tactic:** Lateral Movement

## Severity

**High.** SMB lateral movement between internal hosts indicates an active intrusion. Any alert should trigger immediate investigation of both source and destination endpoints.

## Rules

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

## Learn More

- [Network Detection and Forensics: SMB Analysis](https://ridgelinecyber.com/training/courses/network-detection-forensics/). SMB protocol dissection and lateral movement detection
- [Offensive Security for Defenders: Lateral Movement](https://ridgelinecyber.com/training/courses/offensive-security-for-defenders/). PsExec, WMI, and SMB-based movement techniques
