# Filtered ASR Rules Overview for Windows Devices

This Kusto Query Language (KQL) script retrieves and pivots **Attack Surface Reduction (ASR) rule configurations** from Microsoft Defender for Endpoint data. It filters results to only include **Windows devices**.

---

##  Description

This query does the following:
- Fetches ASR rule metadata (`DeviceTvmInfoGatheringKB`)
- Extracts the latest ASR rule state per onboarded Windows device
- Parses ASR configuration settings from the `AdditionalFields` JSON
- Joins rule metadata for friendly descriptions
- Pivots the result by rule description to show a per-device view

---

##  KQL Query

```kusto
let asrkb = materialize (
    DeviceTvmInfoGatheringKB
    | where Categories has "asr"
    | extend AsrRuleName = replace_regex(FieldName, "Asr", "")
    | project AsrRuleName, Description
);
DeviceInfo
| where OnboardingStatus == 'Onboarded'
| where isnotempty(OSPlatform)
| summarize arg_max(Timestamp, *) by DeviceName
| where OSPlatform startswith "Windows"
| project DeviceName, OSPlatform
| join kind=leftouter (
    DeviceTvmInfoGathering
    | extend AF = parse_json(AdditionalFields)
    | extend ASR1 = parse_json(AdditionalFields.AsrConfigurationStates)
    | project DeviceName, ASR1
    | mv-expand parse_json(ASR1)
    | extend ASRRule = tostring(bag_keys(ASR1)[0])
    | extend AsrRuleSetting = extract(@':"(.*?)"', 1, tostring(ASR1))
)
on $left.DeviceName == $right.DeviceName
| join kind=leftouter (asrkb)
on $left.ASRRule == $right.AsrRuleName
| project DeviceName, OSPlatform, Description, AsrRuleName, AsrRuleSetting
| summarize AsrRuleSet = parse_json(make_set(AsrRuleSetting)[0]) by DeviceName, Description
| where DeviceName contains "-w-" and DeviceName contains "-l-"
| evaluate pivot(Description, make_set(AsrRuleSet), DeviceName)
