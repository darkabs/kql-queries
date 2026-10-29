# SharePoint Phishing via High-Volume Sharing Notifications from External Tenants

## Description

Detects distribution patterns associated with phishing campaigns that abuse **Microsoft SharePoint sharing notifications** to target users through legitimate cloud collaboration workflows.

The query examines `EmailEvents` for messages whose sender address contains `no-reply@sharepointonline.com`. It extracts the source tenant identifier from `InternetMessageId`, excludes the organization's own tenant, and identifies external tenants reaching more than a specified number of distinct recipients during the selected hunting period.

This detection focuses on source tenant behavior to help uncover phishing activity that blends into legitimate collaboration traffic. Analyzing sharing notifications collectively can reveal broad distribution patterns that are less apparent when reviewing individual messages.

## MITRE ATT&CK Mapping

- **Tactic:** Initial Access
- **Technique:** T1566 - Phishing
- **Subtechnique:** T1566.002 - Spearphishing Link

> **Mapping Note:** This mapping reflects phishing campaigns that use SharePoint sharing links as lures to direct recipients toward malicious content or further phishing steps. The query detects the associated tenant distribution pattern; it does not inspect links or confirm malicious intent for every result. Legitimate bulk sharing may produce similar activity. Review the source tenant, shared resources, message verdicts, recipient distribution, and associated click activity to validate findings.

## Query

```kql
EmailEvents
| where SenderFromAddress contains "no-reply@sharepointonline.com"
| extend tid = tostring(split(InternetMessageId, "tid_")[1])
| extend tenantID = tostring(split(tid, "-rh")[0])
| where tenantID != "<your tenantID>"
| summarize
    FirstEvent = min(Timestamp),
    LastEvent = max(Timestamp),
    Recipients = dcount(RecipientEmailAddress)
    by tenantID
| extend TimeDif = LastEvent - FirstEvent
| where Recipients > 10 // Specify a threshold
```

## Query Notes

- Replace `"<your tenantID>"` with your organization's tenant ID.
- Adjust the recipient threshold to reflect normal external collaboration activity in your environment.
- `Recipients` is an approximate count of distinct recipient addresses, not the number of emails or sharing invitations.
- The query runs over the selected hunting period. `TimeDif` shows the interval between the first and last observed events; it does not enforce a short-duration threshold.
- Tenant extraction assumes the observed `tid_...-rh` pattern in `InternetMessageId`. Validate this pattern against sample messages before relying on the extracted values. Missing or unexpected delimiters can produce empty or incorrect groupings.
- The sender-address filter alone does not verify that Microsoft generated the notification. The query does not check SPF, DKIM, DMARC, delivery status, or user interaction.

## References

- [MITRE ATT&CK: T1566.002 - Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [Microsoft Learn: EmailEvents table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table)

