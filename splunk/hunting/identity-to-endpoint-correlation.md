# Identity-to-Endpoint Correlation: Account Compromise Reaching a Host

Correlates a compromised-identity signal with subsequent endpoint activity by the same user, joining the cloud sign-in story to what happened on the machine. An AiTM or risky sign-in is alarming on its own, but the decisive question is whether that account then did something on an endpoint, and this hunt answers it.

## ATT&CK

- **Technique:** Correlation across T1078.004, T1550.001, and T1059
- **Tactic:** Multiple. Identity compromise to host execution

## Severity

**High.** An identity signal that lands on endpoint execution is a confirmed pivot from cloud foothold to host activity, which is the point at which an account takeover becomes a hands-on intrusion.

## Data Sources

- Entra ID sign-in logs (`sourcetype="azure:monitor:aad"`) and endpoint process telemetry (CIM Endpoint or `sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`)
- Requires: a shared user identifier across identity and endpoint, and an `identity` lookup

## Query

```spl
sourcetype="azure:monitor:aad" category="SignInLogs" action="success" (risk="high" OR authentication_method="SatisfiedByClaimInToken")
| stats values(src_country) AS signin_countries, min(_time) AS compromise_time by user
| rename user AS upn
| eval user_short = lower(mvindex(split(upn,"@"),0))
| join type=inner user_short
    [ search sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
      (process_name="powershell.exe" OR process_name="cmd.exe" OR process_name="rundll32.exe" OR process_name="wmic.exe")
    | eval user_short = lower(user)
    | stats values(process_name) AS host_processes, values(host) AS hosts, min(_time) AS host_activity_time by user_short ]
| where host_activity_time >= compromise_time
| table upn, signin_countries, compromise_time, hosts, host_processes, host_activity_time
| sort compromise_time
```

## What Triggers This

A compromised account that then acted on a host:

- A high-risk or token-claim sign-in for a user
- Endpoint process activity by the same user after the sign-in time
- The host and processes touched, for scoping the intrusion

## False Positives

1. **Username-mapping mismatches.** Identity uses UPN and endpoint uses the local username; the join can misfire on shared or service names. Validate the mapping against your identity data.
2. **Coincidental activity.** A risk false positive aligning with routine endpoint work. Confirm the sign-in was genuinely anomalous.
3. **Admin remediation.** A responder using the account after the alert. Exclude known responder activity.

## Tuning Notes

- **Fix the identity join.** The username mapping is the fragile part; use the `identity` lookup to resolve UPN to host username reliably rather than the split heuristic.
- **This is a hunt, not a page.** Run it on a schedule and triage the correlated entities; it confirms scope rather than firing first.
- **Tighten the time gate.** Require endpoint activity within a defined window after the sign-in to strengthen the link.

## Validation

1. In a lab, generate a high-risk sign-in for a test user, then run endpoint activity as that user.
2. Confirm the user surfaces with both the sign-in context and the host activity, ordered by time.

## Learn More

- [Splunk Detection and Incident Response: Threat Hunting](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/). cross-source correlation from identity to endpoint
- [Threat Hunting in Microsoft 365](https://ridgelinecyber.com/training/courses/threat-hunting-m365/). stitching cloud and host telemetry
