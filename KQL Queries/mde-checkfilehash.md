# Search for a Filehash in your MDE environment

This query checks your environment for a specific file hash and gathers all related incidents and alerts to it

---

##  Description

This query does the following:
- Finds file activity for a specific file hash in the DeviceFileEvents table, matching against SHA256, SHA1, or MD5 hashes.
- Joins the file activity with alert evidence from the AlertEvidence table where the same file hash is involved.
- Retrieves detailed alert information from the AlertInfo table and presents a combined view of file activity and associated security alerts, sorted by time.

## KQL Query

```kusto
let fileHash = "replace with your filehash"; 
DeviceFileEvents
| where SHA256 == fileHash or SHA1 == fileHash or MD5 == fileHash
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, ReportId
| join kind=inner (
    AlertEvidence
    | where FileHash == fileHash
    | project AlertId, DeviceName, FileHash
) on DeviceName
| join kind=inner (
    AlertInfo
    | project AlertId, Title, Severity, Category, StartTime, EndTime
) on AlertId
| sort by Timestamp desc

