# Ridgeline Detection Library

Production-validated detection queries, investigation scripts, and hunting artifacts with the context you need to deploy and tune them. Every detection includes the query, what triggers it, known false positives, tuning guidance, and a link to the Ridgeline course that teaches the underlying concept.

**143 artifacts** across nine platforms: KQL (28), Sigma (33), Splunk (12), Athena (11), PowerShell (19), Velociraptor (22), YARA (5), Suricata (6), osquery (7).

## What makes this different

Other repos give you queries. This one gives you queries you can actually deploy.

Every detection in this library includes:

- **The query** — KQL, Sigma, PowerShell, or VQL, ready to deploy
- **What triggers it** — the specific attacker behavior, not a vague description
- **False positives** — what legitimate activity matches and how to distinguish it
- **Tuning notes** — thresholds, exclusions, and environment-specific adjustments
- **Validation steps** — how to test that the detection works before relying on it
- **Learn more** — the Ridgeline training module that teaches the concept in depth

## KQL — Microsoft Sentinel & Defender XDR (28)

| Detection | Tactic | Severity |
|---|---|---|
| [Sign-In from Anonymizer Infrastructure](kql/initial-access/signin-from-anonymizer-infrastructure.md) | Initial Access | Medium |
| [Office Spawning Suspicious Child Process](kql/execution/office-spawning-suspicious-child.md) | Execution | High |
| [AiTM Token Replay — User-Agent Similarity](kql/credential-access/aitm-token-replay-useragent-similarity.md) | Credential Access | Critical |
| [DCSync — Directory Replication Abuse](kql/credential-access/dcsync-directory-replication-abuse.md) | Credential Access | Critical |
| [LSASS Access Mask Monitoring](kql/credential-access/lsass-access-mask-monitoring.md) | Credential Access | High |
| [Password Spray — Distributed Detection](kql/credential-access/password-spray-distributed-detection.md) | Credential Access | High |
| [Token Replay — Geo Inconsistency](kql/credential-access/token-replay-geo-inconsistency.md) | Credential Access | Critical |
| [Kerberoasting — RC4 TGS Requests](kql/credential-access/kerberoasting-rc4-tgs-requests.md) | Credential Access | High |
| [OAuth Illicit Consent Grant](kql/persistence/oauth-illicit-consent-grant.md) | Persistence | High |
| [Inbox Rule — BEC Persistence](kql/persistence/inbox-rule-bec-persistence.md) | Persistence, Collection | High |
| [Federation Trust Modification](kql/persistence/federation-trust-modification.md) | Persistence | Critical |
| [Workload Identity Federation Added](kql/persistence/workload-identity-federation-added.md) | Persistence | Critical |
| [Application Permission Escalation](kql/privilege-escalation/app-permission-escalation.md) | Privilege Escalation | High |
| [Audit Log Gap Detection](kql/defense-evasion/audit-log-gap-detection.md) | Defense Evasion | High |
| [Bulk Graph API Enumeration](kql/discovery/bulk-graph-api-enumeration.md) | Discovery | Medium |
| [Service Principal Credential + API Activity](kql/lateral-movement/service-principal-credential-then-authenticate.md) | Lateral Movement | Critical |
| [Cross-Tenant Guest Elevated Activity](kql/lateral-movement/cross-tenant-guest-elevated-activity.md) | Lateral Movement | High |
| [BEC Outbound Email — Payment Keywords](kql/collection/bec-payment-keyword-outbound.md) | Impact | Critical |
| [Bulk SharePoint/OneDrive Download](kql/collection/bulk-sharepoint-onedrive-download.md) | Collection | High |
| [MailItemsAccessed Volume Spike](kql/collection/mailitemsaccessed-volume-spike.md) | Collection | Critical |
| [Ransomware Pre-Encryption Indicators](kql/impact/ransomware-pre-encryption-indicators.md) | Impact | Critical |
| [Cryptomining — Resource Hijacking](kql/impact/cryptomining-resource-hijacking.md) | Impact | High |
| [MFA Fatigue — Push Bombing](kql/initial-access/mfa-fatigue-push-bombing.md) | Initial Access | High |
| [OAuth Device Code Phishing](kql/initial-access/device-code-phishing.md) | Initial Access | Critical |
| [C2 Beaconing — Periodic Callbacks](kql/command-and-control/c2-beaconing-periodic-callbacks.md) | Command and Control | High |
| [Domain Fronting — CDN Abuse](kql/command-and-control/domain-fronting-cdn-abuse.md) | Command and Control | High |
| [SharePoint External Sharing Spike](kql/exfiltration/sharepoint-external-sharing-spike.md) | Exfiltration | High |
| [Email Auto-Forward to External Domain](kql/exfiltration/email-autoforward-external.md) | Exfiltration | Critical |

## Sigma — Vendor-Agnostic (33)

| Detection | Tactic | Severity |
|---|---|---|
| [Macro-Enabled Document Spawning Suspicious Process](sigma/execution/macro-child-process.md) | Execution | High |
| [MSBuild Inline Task Code Execution](sigma/execution/msbuild-inline-task.md) | Defense Evasion, Execution | High |
| [PowerShell with Multiple Evasion Indicators](sigma/execution/powershell-evasion-indicators.md) | Execution, Defense Evasion | High |
| [WMIC Remote Execution and Reconnaissance](sigma/execution/wmic-remote-execution-recon.md) | Execution, Lateral Movement | Medium |
| [SAM Database Dump](sigma/credential-access/sam-database-dump.md) | Credential Access | High |
| [Privileged Role Assignment Outside PIM](sigma/privilege-escalation/privileged-role-outside-pim.md) | Privilege Escalation | High |
| [Named Pipe Impersonation — Potato Family](sigma/privilege-escalation/named-pipe-impersonation.md) | Privilege Escalation | Critical |
| [AMSI Bypass — Reflection-Based Memory Patching](sigma/defense-evasion/amsi-bypass-memory-patch.md) | Defense Evasion | High |
| [Conditional Access Policy Weakened](sigma/defense-evasion/conditional-access-policy-weakened.md) | Defense Evasion | High |
| [DLL Search Order Hijacking](sigma/defense-evasion/dll-search-order-hijacking.md) | Defense Evasion, Persistence | High |
| [ETW Provider Tampering](sigma/defense-evasion/etw-provider-tampering.md) | Defense Evasion | Critical |
| [Inbox Rule Deleting or Hiding Email](sigma/defense-evasion/inbox-rule-hiding-email.md) | Defense Evasion | High |
| [LOLBin Download or Decode](sigma/defense-evasion/lolbin-download-decode.md) | Defense Evasion, Execution | Medium |
| [Timestomping — File Time Manipulation](sigma/defense-evasion/timestomping-setfiletime.md) | Defense Evasion | Medium |
| [BloodHound/SharpHound AD Reconnaissance](sigma/discovery/bloodhound-sharphound-recon.md) | Discovery | High |
| [RDP Tunneling — SSH/netsh Port Forwarding](sigma/lateral-movement/rdp-tunneling.md) | Lateral Movement | High |
| [Persistence via Scheduled Task, Run Key, or Service](sigma/persistence/scheduled-task-run-key-service.md) | Persistence | Medium |
| [Transport Rule Manipulation](sigma/persistence/transport-rule-manipulation.md) | Persistence, Collection | Critical |
| [WMI Event Subscription Persistence](sigma/persistence/wmi-event-subscription.md) | Persistence | High |
| [DNS Exfiltration — High-Entropy Subdomains](sigma/exfiltration/dns-exfiltration-high-entropy.md) | Exfiltration | Medium |
| [OneDrive Sync to Unmanaged Device](sigma/exfiltration/onedrive-sync-unmanaged-device.md) | Exfiltration | High |
| [DNS C2 — Encoded Subdomain Queries](sigma/command-and-control/dns-c2-encoded-subdomains.md) | Command and Control | High |
| [Non-Standard Port C2](sigma/command-and-control/non-standard-port-c2.md) | Command and Control | Medium |
| [HTML Smuggling — Browser-Dropped Archive](sigma/initial-access/html-smuggling-browser-drop.md) | Initial Access | High |
| [Mass Account Disablement or Deletion](sigma/impact/mass-account-disablement-deletion.md) | Impact | Critical |
| [Cloud Permission and Role Enumeration](sigma/discovery/cloud-permission-enumeration.md) | Discovery | Medium |
| [Linux Reverse Shell Detection](sigma/linux/reverse-shell-detection.md) | Execution | Critical |
| [Linux Privilege Escalation — SUID/Sudo/Capabilities](sigma/linux/privilege-escalation-suid-sudo.md) | Privilege Escalation | High |
| [Linux Persistence — Cron/Systemd/SSH Keys](sigma/linux/persistence-cron-systemd-ssh.md) | Persistence | High |
| [Linux Log Tampering and Defense Evasion](sigma/linux/log-tampering-defense-evasion.md) | Defense Evasion | High |
| [Container Escape and Docker Abuse](sigma/linux/container-escape-docker-abuse.md) | Privilege Escalation | Critical |
| [Linux Kernel Module and Rootkit Indicators](sigma/linux/kernel-module-rootkit-indicators.md) | Persistence, Defense Evasion | Critical |
| [SSH Abuse — Brute Force, Key Theft, Tunneling](sigma/linux/ssh-abuse-bruteforce-tunneling.md) | Lateral Movement, Credential Access | High |

## Splunk — SPL (12)

| Detection | Tactic | Severity |
|---|---|---|
| [Distributed Password Spray — Low-and-Slow by Source IP](splunk/credential-access/password-spray-distributed.md) | Credential Access | High |
| [LSASS Credential Dump — comsvcs MiniDump and Dump Files](splunk/credential-access/lsass-credential-dump.md) | Credential Access | Critical |
| [Sign-In from a Rare Source Country — Tenant-Relative Geo Anomaly](splunk/initial-access/signin-from-rare-source-country.md) | Initial Access | High |
| [Office Application — Spawning a Shell or Script Host](splunk/execution/office-spawning-shell-child.md) | Execution | High |
| [PowerShell — Encoded or Hidden-Window Execution](splunk/execution/encoded-or-hidden-powershell.md) | Execution, Defense Evasion | High |
| [LOLBin Cluster — Multiple Signed Binaries from cmd.exe](splunk/defense-evasion/lolbin-cluster-from-cmd.md) | Defense Evasion | High |
| [Scheduled Task Creation — Command-Line Persistence](splunk/persistence/scheduled-task-creation.md) | Persistence | Medium |
| [WMIC Remote Execution — /node Process Creation](splunk/lateral-movement/wmic-remote-node-execution.md) | Lateral Movement | High |
| [Network Beaconing — Regular-Interval Callbacks](splunk/command-and-control/regular-interval-beaconing.md) | Command and Control | High |
| [Threat-Intel Match — Outbound Connection to a Known Indicator](splunk/command-and-control/connection-to-threat-intel-ioc.md) | Command and Control | High |
| [Recovery Inhibition — Shadow Copy Deletion](splunk/impact/shadow-copy-deletion-recovery-inhibition.md) | Impact | Critical |
| [Multi-Stage Attack — Kill-Chain Correlation on One Host](splunk/hunting/multi-stage-attack-correlation.md) | Multiple | Critical |

## Athena — AWS CloudTrail SQL (11)

Detections for AWS, written as Athena SQL over the standard CloudTrail, VPC Flow Log, and S3 access log tables. They port to CloudTrail Lake and Security Lake by mapping the field names.

| Detection | Tactic | Severity |
|---|---|---|
| [IAM Access Key — Concurrent Internal and External Use](athena/credential-access/access-key-concurrent-internal-external.md) | Credential Access | High |
| [Secrets Manager — Bulk Secret Retrieval](athena/credential-access/secrets-manager-bulk-access.md) | Credential Access | High |
| [Assumed Role — Credentials Used from an External Source](athena/lateral-movement/assumed-role-from-external-source.md) | Lateral Movement | High |
| [IAM Permission Expansion — Policy Attach and Version Pivot](athena/privilege-escalation/iam-permission-self-expansion.md) | Privilege Escalation | High |
| [IAM Identity Manufacture — Burst of Create Verbs](athena/persistence/iam-identity-manufacture-burst.md) | Persistence | High |
| [IAM Backdoor Credential — Key or Login Added to a Principal](athena/persistence/iam-backdoor-credential-added.md) | Persistence | High |
| [Cloud Logging and Detection Disabled — CloudTrail, Config, GuardDuty](athena/defense-evasion/cloud-logging-detection-disabled.md) | Defense Evasion | High |
| [S3 Bucket Enumeration — Account-Wide Listing](athena/discovery/s3-bucket-enumeration.md) | Discovery | Medium |
| [S3 Mass Object Read — Bulk Collection by One Principal](athena/collection/s3-mass-object-read.md) | Collection | High |
| [Large Data Egress — Sustained Outbound to an External Destination](athena/exfiltration/large-egress-to-external-destination.md) | Exfiltration | High |
| [S3 Mass Object Deletion — Destructive Impact](athena/impact/s3-mass-object-deletion.md) | Impact | Critical |

## PowerShell — Investigation, Triage & Automation (19)

### Collection (5)

| Script | Use Case |
|---|---|
| [Volatile Evidence Collection](powershell/collection/volatile-evidence-collection.md) | First-responder capture: network state, processes, persistence, DNS cache |
| [Browser Artifact Collection](powershell/collection/browser-artifact-collection.md) | Chrome/Edge/Firefox history, downloads, cookies, login metadata |
| [Event Log Export](powershell/collection/event-log-export.md) | Targeted export of security, Sysmon, PowerShell, and Defender logs |
| [USB Device History](powershell/collection/usb-device-history.md) | USBSTOR registry, SetupAPI logs, device serial numbers |
| [KAPE Remote Launcher](powershell/collection/kape-remote-launcher.md) | Remote KAPE triage collection via WinRM or PsExec |

### Investigation (7)

| Script | Use Case |
|---|---|
| [Entra ID Compromise Assessment](powershell/investigation/entra-id-compromise-assessment.md) | Post-incident audit: OAuth, inbox rules, CA policy, credentials, roles |
| [Sign-In Log Analysis](powershell/investigation/signin-log-analysis.md) | Entra ID sign-in analysis: impossible travel, MFA bypass, risk scoring |
| [Consent Grant Audit](powershell/investigation/consent-grant-audit.md) | OAuth consent grant inventory with risk scoring |
| [CA Policy Evaluation Audit](powershell/investigation/ca-policy-evaluation-audit.md) | Conditional Access policy coverage and gap analysis |
| [Forwarding & Delegation Audit](powershell/investigation/forwarding-delegation-audit.md) | Mailbox forwarding, delegates, transport rules, inbox rules |
| [Service Principal Credential Audit](powershell/investigation/sp-credential-audit.md) | App registration credential inventory, lifetime, multi-credential flags |
| [Role Assignment Timeline](powershell/investigation/role-assignment-timeline.md) | Active vs PIM-eligible role mapping, multi-role detection |

### Triage (2)

| Script | Use Case |
|---|---|
| [M365 Mailbox Triage](powershell/triage/m365-mailbox-triage.md) | Rapid mailbox assessment: forwarding, rules, delegates, recent activity |
| [Remote WinRM Triage](powershell/triage/remote-winrm-triage.md) | Remote endpoint triage: processes, connections, persistence, services |

### Automation (4)

| Script | Use Case |
|---|---|
| [IR Containment](powershell/automation/ir-containment.md) | 5-step containment: disable, revoke, reset, block, IP block |
| [OAuth Consent Revocation](powershell/automation/oauth-revocation.md) | Bulk OAuth grant removal with dry-run support |
| [Emergency CA Deployment](powershell/automation/emergency-ca-deployment.md) | Pre-built CA policies for active incidents (legacy block, MFA, compliance) |
| [Sentinel Enrichment Playbook](powershell/automation/sentinel-enrichment-playbook.md) | Multi-source IOC enrichment: VirusTotal, AbuseIPDB |

### Reporting (1)

| Script | Use Case |
|---|---|
| [Weekly Threat Hunt Report](powershell/reporting/weekly-hunt-report.md) | Sentinel-driven weekly report: incidents, ATT&CK mapping, top rules, metrics |

## Velociraptor — Endpoint Investigation & Hunting (22)

### Collection (9)

| Artifact | Use Case |
|---|---|
| [Rapid Endpoint Triage](velociraptor/collection/rapid-endpoint-triage.md) | 60-second triage: processes, connections, persistence, recent files |
| [Persistence Deep Dive](velociraptor/collection/persistence-deep-dive.md) | Run keys, Tasks, Services, WMI, Startup, AppInit DLLs, IFEO |
| [Browser Credentials](velociraptor/collection/browser-credentials.md) | Chrome/Edge/Firefox login metadata, session cookies, auth URLs |
| [Prefetch Analysis](velociraptor/collection/prefetch-analysis.md) | Program execution history with suspicious pattern matching |
| [Amcache Analysis](velociraptor/collection/amcache-analysis.md) | SHA1 hashes of executed binaries (persists after deletion) |
| [USB Device History](velociraptor/collection/usb-device-history.md) | USBSTOR registry, mount points, SetupAPI logs |
| [ShellBags Analysis](velociraptor/collection/shellbags-analysis.md) | Folder access history: network shares, removable media, staging paths |
| [SRUM Analysis](velociraptor/collection/srum-analysis.md) | Per-process network usage, high-volume transfer detection |
| [Event Log Export](velociraptor/collection/event-log-export.md) | Targeted event collection by Event ID with time windowing |

### Hunting (10)

| Artifact | Use Case |
|---|---|
| [Lateral Movement Fleet Hunt](velociraptor/hunting/lateral-movement-fleet-hunt.md) | Remote logons, PsExec, WMI, WinRM, RDP across the fleet |
| [Unauthorized Software Stacking](velociraptor/hunting/unauthorized-software-stacking.md) | Installed software and processes not on approved whitelist |
| [Persistence Stacking](velociraptor/hunting/persistence-stacking.md) | Per-endpoint persistence density — flag statistical outliers |
| [Process Injection Detection](velociraptor/hunting/process-injection-detection.md) | Unbacked executable memory, suspicious parent-child, DLL anomalies |
| [DNS Anomaly Detection](velociraptor/hunting/dns-anomaly-detection.md) | High-entropy subdomains, DGA detection, TXT tunneling |
| [Unsigned Driver Detection](velociraptor/hunting/unsigned-driver-detection.md) | Signature verification, BYOVD hash matching, unusual paths |
| [WMI Persistence Detection](velociraptor/hunting/wmi-persistence-detection.md) | Event consumers, filters, bindings with risk classification |
| [Certificate Anomaly Detection](velociraptor/hunting/certificate-anomaly-detection.md) | Self-signed root CAs, weak keys, recently added certificates |
| [Credential Tool Detection](velociraptor/hunting/credential-tool-detection.md) | Mimikatz/Rubeus/LaZagne across Prefetch, Amcache, file system, memory |
| [Data Staging Detection](velociraptor/investigation/data-staging-detection.md) | Archive files in unusual locations, compression tool usage |

### Investigation (4)

| Artifact | Use Case |
|---|---|
| [Timeline Construction](velociraptor/investigation/timeline-construction.md) | Unified timeline from EventLog, Prefetch, Amcache, and Sysmon |
| [User Activity Reconstruction](velociraptor/investigation/user-activity-reconstruction.md) | Recent Files, UserAssist, PS history, browser, typed paths |
| [Ransomware Impact Assessment](velociraptor/investigation/ransomware-impact-assessment.md) | Encrypted file scan, ransom notes, shadow copies, recovery status |
| [Data Staging Detection](velociraptor/investigation/data-staging-detection.md) | Archive files in staging locations, large recent files, compression |

## YARA — Malware and Artifact Classification (5)

| Rule | Target | Severity |
|---|---|---|
| [Cobalt Strike Beacon](yara/malware/cobalt-strike-beacon.md) | Beacon config, named pipes, sleep masks, reflective loader | Critical |
| [Open-Source C2 Implants](yara/malware/open-source-c2-implants.md) | Sliver, Mythic (Apollo/Poseidon), Havoc Demon agents | Critical |
| [Credential Harvesting Tools](yara/malware/credential-harvesting-tools.md) | Mimikatz, Rubeus, SharpHound, LaZagne, LSASS dumpers | Critical |
| [Webshell Detection](yara/webshells/webshell-php-aspx-jsp.md) | PHP, ASPX, and JSP webshells — eval, exec, known shells | Critical |
| [Suspicious PE Characteristics](yara/suspicious-pe/suspicious-pe-characteristics.md) | High entropy, packer sections, missing imports, timestamp anomalies | Medium |

## Suricata — Network IDS (6)

| Rule Set | Target | Severity |
|---|---|---|
| [C2 HTTP Beaconing](suricata/command-and-control/c2-http-beaconing.md) | Cobalt Strike/Sliver default profiles, periodic callbacks, Base64 POST | High |
| [DNS Tunneling](suricata/command-and-control/dns-tunneling-detection.md) | Long subdomains, high-frequency TXT queries, encoded labels | High |
| [Reverse Shell Network Detection](suricata/command-and-control/reverse-shell-detection.md) | Interactive shell prompts, /dev/tcp patterns, Python shells, common ports | Critical |
| [SMB Lateral Movement](suricata/lateral-movement/smb-lateral-movement.md) | PsExec, admin share writes, Impacket pipes, executable transfer | High |
| [Network Credential Theft](suricata/credential-access/network-credential-theft.md) | NTLM relay, LDAP cleartext, Responder/LLMNR, Kerberoasting, DCSync | Critical |
| [Data Exfiltration](suricata/exfiltration/network-data-exfiltration.md) | Large POST uploads, file sharing services, FTP, ICMP tunneling | Medium |

## osquery — Cross-Platform Endpoint (7)

| Query Pack | Platform | Use Case |
|---|---|---|
| [Linux Persistence Detection](osquery/persistence/linux-persistence-detection.md) | Linux | Cron, systemd, SSH keys, shell profiles, LD_PRELOAD, init scripts |
| [Cross-Platform Process & Network Hunting](osquery/hunting/cross-platform-process-network.md) | All | External connections, temp-dir processes, suspicious parent-child, cryptomining |
| [Linux Volatile Evidence Collection](osquery/collection/linux-volatile-evidence.md) | Linux | Processes, connections, users, open files, kernel modules, DNS config |
| [Cross-Platform Asset Inventory](osquery/discovery/cross-platform-asset-inventory.md) | All | Packages, users, groups, listeners, system info, startup items |
| [SUID Binary and Capability Hunting](osquery/linux-hunting/suid-capability-hunting.md) | Linux | SUID audit, GTFOBins candidates, capabilities, world-writable files |
| [Container and Docker Security Audit](osquery/linux-hunting/container-docker-security.md) | Linux | Privileged containers, socket mounts, host namespaces, image inventory |
| [File Integrity and Rootkit Detection](osquery/linux-hunting/file-integrity-rootkit-detection.md) | Linux | Binary hashing, hidden files, LD_PRELOAD, PAM audit, /etc monitoring |

## Format

Every detection follows the [standard format](DETECTION-FORMAT.md). Contributions must include all required fields.

## Training

Every detection maps to a module in the [Ridgeline Cyber training platform](https://ridgelinecyber.com/training). The detection gives you the query. The training gives you the capability to write, tune, and operate detections across your environment.

- [Detection Engineering](https://ridgelinecyber.com/training/courses/detection-engineering/) — rule architecture, threat modeling, detection lifecycle
- [SOC Operations](https://ridgelinecyber.com/training/courses/m365-security-operations/) — investigation playbooks, alert triage, response actions
- [Threat Hunting](https://ridgelinecyber.com/training/courses/threat-hunting-m365/) — hypothesis-driven hunting with KQL and VQL
- [Incident Response](https://ridgelinecyber.com/training/courses/practical-ir/) — containment, investigation, and recovery
- [Offensive Security for Defenders](https://ridgelinecyber.com/training/courses/offensive-security-for-defenders/) — attack techniques and their detection
- [Purple Team Operations](https://ridgelinecyber.com/training/courses/purple-teaming-for-blue-teams/) — technique validation and detection coverage
- [Windows Forensics](https://ridgelinecyber.com/training/courses/windows-endpoint-investigation/) — artifact analysis and timeline construction
- [Linux IR](https://ridgelinecyber.com/training/courses/linux-endpoint-investigation/) — Linux persistence, volatile evidence, and process forensics
- [Network Detection and Forensics](https://ridgelinecyber.com/training/courses/network-detection-forensics/) — network protocol analysis and IDS rules
- [Entra ID Security](https://ridgelinecyber.com/training/courses/entra-id-security/) — identity detection, Conditional Access, PIM governance
- [AWS Incident Detection and Response](https://ridgelinecyber.com/training/courses/aws-detection-and-response/): CloudTrail-based detection, IAM attack paths, and cloud incident response
- [Splunk Detection and Incident Response](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/): SPL detection engineering, CIM data models, and investigation
- [YARA](https://ridgelinecyber.com/training/courses/yara-rule-writing/) — rule development for malware classification
- [Malware Triage](https://ridgelinecyber.com/training/courses/malware-triage/) — static and dynamic analysis fundamentals

Free modules on every course. No account required to start.

## Contributing

Pull requests welcome. Every submission must follow the [detection format](DETECTION-FORMAT.md) and include all required fields — query, false positives, tuning notes, and validation steps. Raw queries without context will not be merged.

## License

[Apache 2.0](LICENSE) — deploy these detections in your environment, modify them, share them.

---

Built by [Ridgeline Cyber](https://ridgelinecyber.com/training) — practitioners who build detections in production, then teach others to do the same.
