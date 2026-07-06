# BEC Outbound Email: Payment Keywords to External Recipients

Detects outbound email containing payment-related keywords (wire transfer, bank details, routing number, invoice) sent to external recipients from compromised accounts. This is the monetization phase of BEC. The attacker has control of the mailbox and is directing payments.

## ATT&CK

- **Technique:** T1657, Financial Theft
- **Tactic:** Impact

## Severity

**Critical.** If this fires on a confirmed-compromised account, the attacker is actively attempting financial fraud. Response time is measured in minutes, not hours. The payment may already be in process.

## Data Sources

- Microsoft 365 Unified Audit Log, `OfficeActivity` table (MailSend operation)
- Requires: Exchange Online audit logging and Advanced Audit (E5) for MailItemsAccessed

## Query

```kql
let PaymentKeywords = dynamic([
    "wire transfer", "bank details", "routing number", "account number",
    "swift code", "iban", "ach transfer", "payment instructions",
    "updated banking", "new bank account", "change of bank",
    "remittance", "funds transfer", "pay invoice", "overdue invoice",
    "revised invoice", "updated invoice", "payment redirect"
]);
let UrgencyKeywords = dynamic([
    "urgent", "immediately", "time sensitive", "asap", "today",
    "do not delay", "end of day", "before close of business"
]);
EmailEvents
| where Timestamp > ago(1h)
| where EmailDirection == "Outbound"
| where RecipientEmailAddress !endswith "@contoso.com"  // adjust to your domain
| join kind=inner (
    EmailUrlInfo
    | project NetworkMessageId, UrlDomain
) on NetworkMessageId
| where Subject has_any (PaymentKeywords)
    or Subject has_any (UrgencyKeywords)
| project
    Timestamp,
    SenderFromAddress,
    RecipientEmailAddress,
    Subject,
    NetworkMessageId,
    SenderIPv4,
    AuthenticationDetails
| extend MatchedPaymentKeyword = extract(@"(?i)(wire transfer|bank details|routing number|account number|swift code|iban|updated banking|new bank account|revised invoice|payment redirect)", 1, Subject)
| where isnotempty(MatchedPaymentKeyword)
| sort by Timestamp desc
```

## What Triggers This

A compromised mailbox sends outbound email containing keywords associated with payment diversion:

- Wire transfer instructions, bank account details, routing numbers
- Invoice modifications, payment redirection requests
- Urgency language combined with financial terms

The attacker impersonates the account owner to redirect payments to attacker-controlled bank accounts. The recipient sees the email from the legitimate sender address, making it highly convincing.

## False Positives

1. **Legitimate financial communications.** Finance teams send payment-related emails routinely. Correlate with known finance department accounts and their normal communication patterns.
2. **Automated notifications.** Billing systems and accounting software send payment confirmations containing these keywords. Filter by sender application or service account.
3. **Volume baseline.** A finance user sending 5 payment emails per day is normal. The same user sending 50 is suspicious.

## Tuning Notes

- **Scope to compromised accounts.** This detection is most effective when combined with other BEC indicators (impossible travel, inbox rule creation, AiTM sign-in). Run it against accounts already flagged as potentially compromised rather than globally.
- **External-only filter.** Restrict to external recipients to reduce noise from internal financial communications.
- **Sentinel deployment:** NRT rule when used as part of a BEC investigation playbook. Scheduled rule (15 min) when used as a standalone detection.

## Validation

1. From a test account, send an email to an external test address containing "Please update the wire transfer details"
2. Verify the detection fires and captures the sender, recipient, subject, and matched keywords
3. Delete the test email

## Learn More

- [SOC Operations: Investigation Playbook Framework](https://ridgelinecyber.com/training/courses/m365-security-operations/). complete BEC investigation and response playbook
- [Detection Engineering: Email & Collaboration](https://ridgelinecyber.com/training/courses/detection-engineering/). BEC detection rule design and keyword tuning
