# Identify Onboardable Windows Devices with Defender for Endpoint

This Kusto Query Language (KQL) script identifies **Windows devices that are not currently onboarded into Microsoft Defender for Endpoint (MDE)** but have been active recently — making them strong candidates for onboarding.

---

## Purpose

Helps security teams:
- Detect **coverage gaps** in their Defender for Endpoint deployment
- Prioritize onboarding of **eligible Windows devices**
- Ensure complete EDR visibility across the estate

---

## KQL Query

```kusto
DeviceInfo
| summarize LastSeen = arg_max(Timestamp, *) by DeviceName
| where OnboardingStatus != "Onboarded"
| where OSPlatform startswith "Windows"
| where LastSeen > ago(30d)  // seen in the last 30 days
| project DeviceName, OSPlatform, OnboardingStatus, LastSeen
| order by LastSeen desc
