 **Environment**
- Splunk Enterprise (single instance)
- Splunk Universal Forwarder on Windows host `AAULH5CG3125QZ9`
- Data source: `WinEventLog:Security`

**Objective**
Identify accounts with high process‑creation activity using Windows Security logs (EventCode 4688), and build a simple detection in Splunk.

 
## Data and SPL

 **Data filters**
- host="AAULH5CG3125QZ9"
- source="WinEventLog:Security"
- EventCode=4688 (process creation)

 **Query**
index=* host="AAULH5CG3125QZ9" source="WinEventLog:Security" EventCode=4688

| stats count by Account_Name

| where count > 5

| sort – count

 
**High‑level results**

(Counts are approximate and redacted as needed.)
Several accounts generated more than 5 process‑creation events.
A small number of system / machine accounts were responsible for the majority of process creation.
One user account showed noticeably higher process‑creation activity than others, which would be worth monitoring in a real SOC.
 
**SOC relevance**
In a real SOC this type of search can be used to:
- Establish a baseline of normal process‑creation activity per account.
Detect anomalies such as:
- Low‑activity accounts suddenly creating many processes.
- User accounts behaving more like service accounts.

**What I learned**
How to filter Splunk searches by:
source="WinEventLog:Security"
Specific EventCode values (4688 for process creation)
How to aggregate events with stats count by Account_Name.
How to use where count > N and sort - count to turn raw logs into a simple detection.
How to interpret Windows Security logs in the context of process‑creation monitoring.
 
