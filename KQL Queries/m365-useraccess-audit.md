# Audit User Account Access Across All M365 Systems

This query checks the sign-in and access activity of a specific user account across all Microsoft 365 services.

---

## Description

This query does the following:

- Searches the `CloudAppEvents` and `IdentityLogonEvents` tables for activity by a specific user account.
- Covers all M365 workloads (Exchange Online, SharePoint, Teams, OneDrive, Entra ID, Power Platform, etc.).
- Summarises which applications and services the user accessed, along with login locations and device details.
- Surfaces both interactive and non-interactive sign-ins.

## KQL Query

### 1. Sign-in activity across all M365 apps (via Identity logon logs)

```kusto
let targetUser = "user@domain.com";  // replace with the target UPN
IdentityLogonEvents
| where Timestamp > ago(30d)
| where AccountUpn =~ targetUser
| summarize
    SignInCount = count(),
    LastSignIn = max(Timestamp),
    FirstSignIn = min(Timestamp),
    IPAddresses = make_set(IPAddress),
    Locations = make_set(Location),
    LogonTypes = make_set(LogonType)
    by Application, Protocol, AccountUpn
| project
    AccountUpn,
    Application,
    Protocol,
    SignInCount,
    FirstSignIn,
    LastSignIn,
    LogonTypes,
    IPAddresses,
    Locations
| order by SignInCount desc
```

### 2. Cloud app activity across M365 workloads

```kusto
let targetUser = "user@domain.com";  // replace with the target UPN
CloudAppEvents
| where Timestamp > ago(30d)
| where AccountId =~ targetUser or AccountDisplayName =~ targetUser
| summarize
    EventCount = count(),
    LastActivity = max(Timestamp),
    FirstActivity = min(Timestamp),
    Actions = make_set(ActionType)
    by Application, AccountDisplayName
| project
    AccountDisplayName,
    Application,
    EventCount,
    FirstActivity,
    LastActivity,
    Actions
| order by EventCount desc
```

### 3. Combined view — all applications the user touched

```kusto
let targetUser = "user@domain.com";  // replace with the target UPN
let signIns = IdentityLogonEvents
| where Timestamp > ago(30d)
| where AccountUpn =~ targetUser
| summarize
    SignInCount = count(),
    LastSeen = max(Timestamp)
    by Application;
let appActivity = CloudAppEvents
| where Timestamp > ago(30d)
| where AccountId =~ targetUser or AccountDisplayName =~ targetUser
| summarize
    ActivityCount = count(),
    LastSeen = max(Timestamp)
    by Application;
signIns
| join kind=fullouter appActivity on Application
| extend
    AppName = coalesce(Application, Application1),
    TotalSignIns = coalesce(SignInCount, 0),
    TotalActivities = coalesce(ActivityCount, 0),
    MostRecent = max_of(coalesce(LastSeen, datetime(null)), coalesce(LastSeen1, datetime(null)))
| project AppName, TotalSignIns, TotalActivities, MostRecent
| order by MostRecent desc
```

---

## Investigation: Eberhard Brammer (EBR) — Zugriffskontrolle seit 25.03.2026

> **Kontext:** EBR ist im ungekündigten Verhältnis, aktuell krankgeschrieben.
> Laut eigener Aussage hat er keinen Zugriff auf die Systeme.
> Ziel: Rekonstruieren, ob seit dem 25.03.2026 Anmeldungen über Teams und/oder Outlook stattgefunden haben.

### 4. Hat EBR sich seit 25.03. bei Teams oder Outlook angemeldet? (Sign-In Logs)

```kusto
let targetUser = "ebrammer@domain.com";  // UPN von Eberhard Brammer anpassen
let cutoffDate = datetime(2026-03-25);
IdentityLogonEvents
| where Timestamp >= cutoffDate
| where AccountUpn =~ targetUser
| where Application in~ ("Microsoft Teams", "Microsoft Outlook", "Microsoft Office", "Office 365 Exchange Online", "Microsoft 365")
| project
    Timestamp,
    AccountUpn,
    Application,
    Protocol,
    LogonType,
    IPAddress,
    Location
| order by Timestamp desc
```

### 5. Tatsächliche Aktivität in Teams und Outlook (Cloud App Events)

```kusto
let targetUser = "ebrammer@domain.com";  // UPN von Eberhard Brammer anpassen
let targetDisplayName = "Eberhard Brammer";  // Anzeigenamen anpassen
let cutoffDate = datetime(2026-03-25);
CloudAppEvents
| where Timestamp >= cutoffDate
| where AccountId =~ targetUser
    or AccountDisplayName =~ targetDisplayName
| where Application in~ (
    "Microsoft Teams",
    "Microsoft Exchange Online",
    "Microsoft Outlook",
    "Microsoft 365"
    )
| project
    Timestamp,
    AccountDisplayName,
    Application,
    ActionType,
    IPAddress,
    City,
    CountryCode,
    DeviceType,
    OSPlatform,
    UserAgent
| order by Timestamp desc
```

### 6. Gesamtübersicht — alle M365-Systeme die EBR seit 25.03. berührt hat

```kusto
let targetUser = "ebrammer@domain.com";  // UPN anpassen
let targetDisplayName = "Eberhard Brammer";
let cutoffDate = datetime(2026-03-25);
CloudAppEvents
| where Timestamp >= cutoffDate
| where AccountId =~ targetUser
    or AccountDisplayName =~ targetDisplayName
| summarize
    EventCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Actions = make_set(ActionType),
    IPs = make_set(IPAddress),
    Devices = make_set(DeviceType)
    by Application
| order by LastSeen desc
```

---

## Usage Notes

- Replace `"user@domain.com"` with the actual User Principal Name (UPN) of the account to audit.
- Adjust the `ago(30d)` lookback window as needed.
- **Query 1** uses `IdentityLogonEvents` — it shows which apps the user authenticated to, including protocol and logon type.
- **Query 2** uses `CloudAppEvents` — it shows actual actions the user performed in M365 apps.
- **Query 3** combines both views for a full picture of all M365 systems the user accessed.
- **Query 4** prüft gezielt, ob EBR sich seit 25.03. bei Teams/Outlook **angemeldet** hat.
- **Query 5** zeigt die tatsächliche **Aktivität** (E-Mails, Chats, Meetings, etc.) in Teams/Outlook — inkl. IP, Gerät und User-Agent.
- **Query 6** gibt eine **Gesamtübersicht** aller M365-Systeme, die EBR seit dem 25.03. berührt hat.
- These queries run in **Microsoft Defender XDR Advanced Hunting**.
- If you have the Entra ID connector enabled, you can replace `IdentityLogonEvents` with `AADSignInEventsBeta` for richer sign-in details (e.g. `ErrorCode`, `City`, `Country`, `ResourceDisplayName`).
