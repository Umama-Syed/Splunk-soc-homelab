**Environment**
- Splunk Enterprise (single instance)
- Splunk Universal Forwarder on Windows host `AAULH5CG3125QZ9`
- Data source: `WinEventLog:Security`

**Objective**
Detect unusual bursts of Windows logon activity by identifying accounts with many successful logons in a short time window.

## Data and SPL
**Data filters**
- source="WinEventLog:Security"

- EventCode=4624` (successful logon)

 **Query**
index=* source="WinEventLog:Security" EventCode=4624

| bin _time span=5m

| stats count by _time, Account_Name, host

| where count >= 5

| sort _time, -count

 **High-level results**
- Certain service or machine accounts log in frequently in short bursts, which is expected for background services.
- Some user or tool-related accounts may also show periods with ≥ 5 logons in 5 minutes.

In a real SOC, such bursts could indicate:
- Misconfigured services looping authentications.
- Automated scripts re-authenticating frequently.
- Potential misuse or scripted access patterns that warrant review.

**SOC relevance**

- Even in environments where failed-logon auditing (EventCode 4625) is not enabled, the same technique used for brute-force detection can be applied to successful logons to:

- Reveal abnormal authentication patterns.
- Provide input for tuning SIEM rules and baselines.
- Feed into correlation rules (e.g., bursts of logons to sensitive hosts).

**What I learned**

- How to use bin to group authentication events into fixed time windows (5 minutes).
- How to aggregate by account and host and filter on thresholds (where count >= N).
- How to interpret logon bursts in the context of normal vs. suspicious behaviour.
- That the same SPL structure used for brute-force failed-logon detection can be reused on other event types (e.g. successful logons).
 
