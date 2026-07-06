# Kerberoasting: Anomalous RC4 TGS Requests for Service Accounts

Detects Kerberoasting attacks by identifying TGS (Ticket Granting Service) requests that use RC4 encryption for service accounts with SPNs. Attackers deliberately request RC4-encrypted service tickets because RC4 is crackable offline. A TGS encrypted with RC4 can be brute-forced to recover the service account's password without any further network interaction.

## ATT&CK

- **Technique:** T1558.003. Steal or Forge Kerberos Tickets: Kerberoasting
- **Tactic:** Credential Access

## Severity

**High.** RC4 TGS requests for service accounts with SPNs are the defining behavior of Kerberoasting. If the service account has a weak password, the attacker cracks it offline in hours. Service accounts often have privileged access. A cracked service account password frequently leads to domain admin.

## Data Sources

- Windows Security Event Log. Event ID 4769 (Kerberos Service Ticket Operations) on Domain Controllers
- Requires: Advanced Audit Policy → Account Logon → Audit Kerberos Service Ticket Operations (Success)
- Sentinel: `SecurityEvent` table with Windows Security Events data connector

## Query: KQL (Sentinel)

```kql
let lookback = 24h;
let rc4_etype = "0x17";
// Known service accounts that legitimately use RC4 (legacy apps)
let rc4_exceptions = dynamic([]);
// Stage 1: RC4 TGS requests — the Kerberoasting signal
let rc4Requests = SecurityEvent
| where TimeGenerated > ago(lookback)
| where EventID == 4769
| where ServiceName !endswith "$"          // Exclude machine accounts
| where ServiceName != "krbtgt"            // Exclude TGT requests
| where TicketEncryptionType == rc4_etype  // RC4 = 0x17
| where ServiceName !in (rc4_exceptions)
| extend RequestingAccount = TargetUserName
| extend RequestingDomain = TargetDomainName
| extend SourceIP = IpAddress
| project
    TimeGenerated,
    RequestingAccount,
    RequestingDomain,
    ServiceName,
    SourceIP,
    TicketEncryptionType,
    TicketOptions,
    Computer;
// Stage 2: Statistical analysis — how many services did each account request?
let kerberoastCandidates = rc4Requests
| summarize
    ServicesRequested = dcount(ServiceName),
    ServiceList = make_set(ServiceName, 20),
    TotalRequests = count(),
    FirstRequest = min(TimeGenerated),
    LastRequest = max(TimeGenerated),
    SourceIPs = make_set(SourceIP, 5)
    by RequestingAccount, RequestingDomain
| where ServicesRequested >= 3;
// Stage 3: Enrich — compare against AES baseline
// Legitimate Kerberos clients use AES (0x12). An account that switches
// to RC4 for multiple SPNs is highly suspicious.
let aesBaseline = SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID == 4769
| where TicketEncryptionType == "0x12"  // AES256
| where ServiceName !endswith "$"
| summarize AESRequests = count() by TargetUserName
| project RequestingAccount = TargetUserName, AESRequests;
kerberoastCandidates
| join kind=leftouter (aesBaseline) on RequestingAccount
| extend AESRequests = coalesce(AESRequests, 0)
| extend RC4Ratio = round(toreal(TotalRequests) / max_of(toreal(TotalRequests + AESRequests), 1), 2)
| project
    RequestingAccount,
    RequestingDomain,
    ServicesRequested,
    TotalRequests,
    RC4Ratio,
    ServiceList,
    SourceIPs,
    FirstRequest,
    LastRequest,
    SprayDurationMin = datetime_diff('minute', LastRequest, FirstRequest)
| sort by ServicesRequested desc
```

## Why This Detection Is Effective

Modern Active Directory environments use AES encryption by default. RC4 is a legacy fallback that exists for backward compatibility. When a client explicitly requests RC4 encryption for a TGS (setting the encryption type to 0x17 in the KRB_TGS_REQ), it's either a legacy application that can't handle AES, or an attacker requesting RC4 because it's crackable.

The three-stage approach provides high fidelity:
1. **RC4 filter**. Eliminates the vast majority of legitimate Kerberos traffic (which uses AES)
2. **Multi-service threshold**. Legitimate legacy apps request tickets for 1-2 specific services. Kerberoasting tools request tickets for every SPN in the domain. The threshold of 3+ services catches the attack pattern while allowing individual legacy app exceptions.
3. **AES baseline comparison**. An account that normally uses AES but suddenly switches to RC4 for multiple services is a compromised account being used for Kerberoasting.

## What Triggers This

1. Attacker compromises any domain user account (even a low-privilege user)
2. Attacker enumerates SPNs: `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName`
3. Attacker requests RC4-encrypted TGS tickets for each SPN using Rubeus, Impacket GetUserSPNs, or PowerView
4. Domain Controller issues the tickets encrypted with RC4 (the service account's NTLM hash)
5. Attacker takes the tickets offline and cracks them with hashcat (`-m 13100`)
6. The detection identifies the RC4 TGS requests for multiple services from a single account

## False Positives

1. **Legacy applications.** Applications built on older frameworks (Java 6/7, old .NET, legacy ERP systems) may request RC4 tickets because they don't support AES. Identify these applications and add their service accounts to `rc4_exceptions`.
2. **Linux Kerberos clients.** Some older Linux krb5 configurations request RC4 by default. Update `/etc/krb5.conf` to prefer AES: `default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96`.
3. **Domain Controller to DC replication.** Inter-DC Kerberos sometimes uses RC4 during specific operations. Excluded by the `ServiceName !endswith "$"` filter.
4. **Service ticket auto-renewal.** Windows services with long-running sessions renew their TGS periodically. These use the same service name repeatedly, not multiple different services. The `ServicesRequested >= 3` threshold filters them.

## Tuning Notes

- **Service count threshold.** 3 is conservative. Kerberoasting tools typically request 10-100+ service tickets. Set to 1 for maximum sensitivity (if your RC4 exceptions list is comprehensive) or 5+ to reduce noise in environments with legacy RC4 usage.
- **Disable RC4 tenant-wide.** The most effective tuning is eliminating the attack surface. If you can disable RC4 in your domain policy, any RC4 TGS request is an anomaly. Requires testing all applications first.
- **Monitor service account password age.** Kerberoasting targets service accounts with old passwords (more likely to be weak). Service accounts with passwords > 1 year old and SPNs registered are your highest-risk accounts.
- **Sentinel deployment:** Scheduled rule, 1-hour frequency. Entity mapping: `RequestingAccount` as Account, `SourceIPs` as IP. Include `ServiceList` in the alert for immediate context on which service accounts are targeted.

## Response

1. **Identify the compromised requesting account.** The `RequestingAccount` is either a compromised user or an attacker-controlled account. Disable it immediately.
2. **Reset passwords for all targeted service accounts.** Every service account in `ServiceList` should be assumed compromised. The attacker may have already cracked the tickets offline.
3. **Audit service account privileges.** Check what each targeted service account can access. If any are domain admin equivalent, treat this as a domain compromise.
4. **Investigate the source endpoint.** The `SourceIPs` shows where the Kerberoasting tool ran. This endpoint is compromised. Triage it for additional attacker activity.
5. **Long-term: implement managed service accounts (gMSA).** gMSAs have automatically rotated 120-character passwords that are uncrackable. Migrate SPNs from traditional service accounts to gMSAs.

## References

- MITRE ATT&CK: [T1558.003](https://attack.mitre.org/techniques/T1558/003/)
- Microsoft: [Detecting Kerberoasting Activity](https://learn.microsoft.com/en-us/defender-for-identity/persistence-privilege-escalation-lateral-movement-alerts#suspected-kerberos-spn-exposure-external-id-2410)
- SpecterOps: Tim Medin's original Kerberoasting research and modern tool analysis

## Learn More

- [Offensive Security for Defenders](https://ridgelinecyber.com/training/courses/offensive-security-for-defenders/). Kerberoasting execution, telemetry analysis, and detection engineering
- [Purple Team Operations](https://ridgelinecyber.com/training/courses/purple-teaming-for-blue-teams/). Kerberoasting as part of credential access technique validation
- [Detection Engineering: Identity Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). building detection for Active Directory credential attacks
