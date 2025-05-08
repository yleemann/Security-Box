# Search for Suspicious Use of Rundll32

This query detects suspicious use of rundll32.exe, which is often abused to execute DLLs or scripts in an attempt to evade detection.

---

## Description

This query does the following:

- Looks in the DeviceProcessEvents table for execution of rundll32.exe.
- Filters out common known-good command lines to reduce noise.
- Highlights potentially malicious rundll32 usage, useful in threat hunting and malware analysis.

## KQL Query

```kusto
DeviceProcessEvents
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine !has_any ("ieframe.dll", "shell32.dll", "dfshim.dll")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, ProcessCommandLine
| sort by Timestamp desc