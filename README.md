# Lab 001 — Windows Event Logging with Splunk

## Objective

Collect and analyze Windows Security Event Logs using Splunk Enterprise and Splunk Universal Forwarder.

The goal of this lab is to understand how a SOC analyst can:

- Collect Windows authentication logs
- Identify successful logons
- Identify failed logons
- Investigate authentication-related fields
- Detect repeated failed logon attempts

## Environment

### Splunk Server

- OS: Ubuntu Server 24.04.5 LTS
- Splunk Enterprise: 10.4.3
- RAM: 8 GB
- CPU: 4 vCPU
- Storage: 80 GB
- Network: VirtualBox NAT

### Windows Endpoint

- OS: Windows 11
- Splunk Universal Forwarder: 10.4.3
- Hostname: SOC-WINDOWS-01
- Windows Event Logs collected:
  - Application
  - Security
  - System

### Data Flow

Windows 11
→ Splunk Universal Forwarder
→ TCP 9997
→ VirtualBox NAT
→ Splunk Enterprise
→ `index=main`

## Data Collection

Windows Security Event Logs were collected by Splunk Universal Forwarder and forwarded to Splunk Enterprise over TCP port 9997.

The collected events were stored in:

- Index: `main`
- Sourcetype: `WinEventLog:Security`

The Windows endpoint successfully generated authentication events that were visible in Splunk.

### Authentication Events Observed

The following Windows Security Event IDs were observed:

- Event ID 4624 — Successful logon
- Event ID 4625 — Failed logon

Event ID 4624 was used to examine successful authentication activity, while Event ID 4625 was used to investigate failed authentication attempts.

## Detection

### Detection: Multiple Failed Logons

The detection identifies repeated failed Windows authentication attempts for the `soclab` account.

The detection logic looks for:

- Windows Security Event ID `4625`
- Account: `soclab`
- Source network address
- 5 or more failed logons
- Within a 5-minute time window

### SPL Query

```spl
index=main sourcetype=WinEventLog:Security EventCode=4625 Account_Name="soclab" | bin _time span=5m | stats count as failures by _time Source_Network_Address | where failures >= 5
```

## Investigation

The failed authentication events were investigated using Windows Security Event ID 4625.

The following fields were reviewed:

| Field | Observed Value |
|---|---|
| Account Name | `soclab` |
| Logon Type | `2` |
| Source Network Address | `127.0.0.1` |
| Failure Reason | `Unknown user name or bad password` |
| Caller Process | `C:\Windows\System32\svchost.exe` |
| Computer Name | `SOC-WINDOWS-01` |

### Investigation Findings

The failed authentication events originated from the local host (`127.0.0.1`) and targeted the `soclab` account.

The failure reason indicates that the authentication attempt used an incorrect username or password.

The activity was generated intentionally as part of this lab to simulate failed authentication activity.

### Analyst Assessment

This event pattern demonstrates how a SOC analyst can use:

1. Account information
2. Authentication type
3. Source address
4. Failure reason
5. Process information

to investigate a Windows authentication alert.

## MITRE ATT&CK

The authentication failure pattern is relevant to:

- **T1110 — Brute Force**

The observed events alone do not prove a brute-force attack. In this lab, repeated failed logons were intentionally generated to test the detection.

## Response

Because the activity was intentionally generated for this lab, no remediation was required.

In a real SOC investigation, repeated failed authentication attempts would require additional context, such as:

- Source IP reputation
- Number and frequency of attempts
- Targeted accounts
- Whether successful logons occurred afterward
- Geographic or network context
- Related endpoint activity

## Lessons Learned

This lab demonstrated the basic workflow of Windows authentication monitoring with Splunk:

1. Windows generates Security Event Logs.
2. Splunk Universal Forwarder collects the events.
3. Events are forwarded to Splunk Enterprise over TCP port `9997`.
4. Splunk stores the events in the `main` index.
5. Event ID `4624` can be used to investigate successful logons.
6. Event ID `4625` can be used to investigate failed logons.
7. Authentication fields provide context for investigation.
8. Repeated failed logons can be detected using SPL aggregation.
9. A detection alert requires investigation and context before determining whether it represents malicious activity.

## Conclusion

This lab established a working Windows authentication monitoring pipeline using Splunk Enterprise and Splunk Universal Forwarder.

The lab successfully demonstrated log collection, authentication event analysis, and a basic threshold-based detection for repeated failed logons.