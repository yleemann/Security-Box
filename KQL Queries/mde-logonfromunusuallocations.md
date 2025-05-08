# Detect Logon Events from Unusual Locations

This query identifies interactive logons from multiple geographic locations, helping detect potentially compromised accounts.

---

## Description

This query does the following:

- Filters the DeviceLogonEvents table for Interactive logons.
- Aggregates logon locations per user and device.
- Flags accounts logging in from more than one country.

## KQL Query

```kusto
DeviceLogonEvents
| where LogonType == "Interactive"
| summarize count(), make_set(RemoteIPCountry) by AccountName, DeviceName
| where array_length(set_RemoteIPCountry) > 1
| project AccountName, DeviceName, Countries=set_RemoteIPCountry