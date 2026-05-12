**Environment**
- Splunk Enterprise (single instance)
- Splunk Universal Forwarder on Windows host `AAULH5CG3125QZ9`
- Data source: `WinEventLog:Security`

 

**Objective**
Identify which processes are most frequently executed per account, in order to spot anomalies (e.g., unusual binaries or unexpected high‑volume process activity for a given account).


## Data and SPL
**Data filters**
- `host="AAULH5CG3125QZ9"`
- `source="WinEventLog:Security"`
- `EventCode=4688` (process creation)

 **Query**
```spl
index=* host="AAULH5CG3125QZ9" source="WinEventLog:Security" EventCode=4688

| stats count by New_Process_Name, Account_Name

| where count > 5

| sort – count

** High‑level results**

(Counts and names summarised / redacted.)

Common Windows binaries such as cmd.exe, conhost.exe, svchost.exe, and various system agents appear with high counts, mostly under machine or service accounts.
Some processes are run heavily by the computer account (e.g. AAULH5CG3125QZ9$), which is expected for system‑level activity.
A small number of user or tool‑related processes show up with noticeable frequency; in a real SOC these would be reviewed to confirm they are expected.
 
**SOC relevance**
This type of view is useful for:

- Building a baseline of normal process activity for system vs. user accounts.
- Spotting potentially suspicious behaviour, such as:
- User accounts repeatedly launching tools that are unusual for their role.
- Rare binaries that suddenly appear with high frequency.

Supporting investigations:
- When an alert fires on a particular process, you can quickly check who usually runs it and how often.

In a production SOC, this could feed into:
- Detections that flag rare or newly‑seen New_Process_Name values.
- Rules excluding well‑known system processes while highlighting unexpected tools.
 

**What I learned**
How to extend a simple aggregation (stats count by Account_Name) into a two‑dimensional view (New_Process_Name + Account_Name).
How to use where count > N to focus on higher‑volume patterns instead of one‑off events.
How to interpret process frequency in the context of system accounts vs. user accounts.
How EventCode 4688 can support both baseline analysis and threat hunting.
 
