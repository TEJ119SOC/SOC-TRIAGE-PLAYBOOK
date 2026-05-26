🚪 Unauthorised Access Playbook

**MITRE ATT&CK Tactic:** Initial Access (TA0001) | Lateral Movement (TA0008) | Privilege Escalation (TA0004)  
**Techniques:** T1078 (Valid Accounts) | T1021 (Remote Services) | T1548 (Abuse Elevation Control)  
**Severity:** High – Critical  
**SLA:** Investigate within 30 minutes | Contain within 1 hour  

---

## 📌 Overview

Unauthorised access occurs when an individual gains access to systems, data, or resources without permission — whether through stolen credentials, misconfigured permissions, insider threat, or exploitation of a vulnerability. This playbook covers detection, scoping, containment, and escalation.

---

## 🚨 Alert Trigger Sources

- Microsoft Sentinel — anomalous login or access alert
- Azure AD Identity Protection — risky user or risky sign-in flagged
- Microsoft Defender for Cloud — suspicious resource access
- SIEM alert — access outside business hours or from unusual location
- DLP alert — sensitive data accessed or downloaded in bulk
- User or manager report — suspicious activity on an account

---

## 🔍 Step 1 — Initial Triage (5–10 mins)

| Field | What to Check |
|-------|--------------|
| Account name | Whose account was used? |
| Account type | Standard user, admin, service account? |
| Source IP | Internal network, VPN, or external? |
| Access location | Expected country/city for this user? |
| Resource accessed | What system, file, or application was accessed? |
| Time of access | Business hours or off-hours? |
| Access method | Web portal, VPN, RDP, API, SSH? |
| Prior alerts | Any recent brute force or phishing alerts for this user? |

**Escalate immediately if:**
- Admin or privileged account involved
- Sensitive data (PII, financial, IP) accessed or downloaded
- Access from a foreign country with no travel history
- Service account behaving like an interactive user
- Access following a recent phishing or brute force alert on same account

---

## 🔬 Step 2 — Sign-in & Access Log Analysis

```kql
// Review all sign-ins for a specific user
SigninLogs
| where UserPrincipalName == "user@domain.com"
| project TimeGenerated, IPAddress, Location, AppDisplayName, ResultType, RiskLevelDuringSignIn
| order by TimeGenerated desc
```

```kql
// Detect access from new or unusual country
SigninLogs
| where ResultType == "0"
| summarize Countries = make_set(Location) by UserPrincipalName
| where array_length(Countries) > 2
```

```kql
// Detect off-hours access (outside 08:00 - 18:00)
SigninLogs
| where ResultType == "0"
| extend Hour = datetime_part("hour", TimeGenerated)
| where Hour < 8 or Hour > 18
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName
```

```kql
// Check for bulk file access or download
OfficeActivity
| where Operation in ("FileDownloaded", "FileCopied", "FileAccessed")
| summarize FileCount = count() by UserId, bin(TimeGenerated, 1h)
| where FileCount > 50
| order by FileCount desc
```

---

## 👤 Step 3 — User Activity Review

```
Once you identify the suspicious session, review what the user did:

1. What resources were accessed?
   - SharePoint / OneDrive files?
   - Azure resources or management portal?
   - Internal applications or databases?

2. Were any changes made?
   - New accounts created?
   - Permissions modified or elevated?
   - Files deleted, modified, or exfiltrated?
   - Email forwarding rules created?
   - New MFA methods registered?

3. How long was the session active?

4. Were there any failed access attempts to higher-privilege resources?
   (attacker probing for privilege escalation paths)
```

---

## 🔐 Step 4 — Privilege & Permission Check

```
1. What groups and roles does this account belong to?
2. Does the account have more permissions than needed for their job?
3. Were any new roles or group memberships assigned recently?
4. Check Azure AD audit logs for role assignment changes:
```

```kql
AuditLogs
| where OperationName == "Add member to role"
| project TimeGenerated, InitiatedBy, TargetResources, Result
| order by TimeGenerated desc
```

---

## 🌐 Step 5 — Lateral Movement Check

```
Determine if the attacker moved beyond the initial access point:

1. Did the account authenticate to other internal systems after the
   suspicious login?
2. Check for RDP, SMB, WinRM, or SSH connections from the account
3. Look for PsExec or remote PowerShell usage
4. Check if any new local accounts were created on accessed systems
5. Review DNS queries — are new internal hostnames being resolved?

Event IDs to check (Windows Security Log):
- 4624 — Successful logon (check logon type: Type 3 = network, Type 10 = remote interactive)
- 4648 — Logon using explicit credentials
- 4672 — Special privileges assigned to new logon
- 4776 — Credential validation attempt
```

---

## 🚧 Step 6 — Containment Actions

| Action | When to Apply |
|--------|--------------|
| Disable compromised account | Unauthorised access confirmed |
| Revoke all active sessions | Immediately on confirmation |
| Force password reset | Always after account compromise |
| Remove newly added MFA devices | If attacker registered new device |
| Block source IP at firewall | External attacker IP identified |
| Isolate affected endpoint | If malware or persistence suspected |
| Revert permission changes | If attacker escalated privileges |
| Remove malicious inbox rules | If email forwarding rules found |
| Preserve logs before remediation | For forensic investigation |

---

## 📋 Step 7 — Escalation Criteria

**Escalate to Tier 2 if:**
- Admin or privileged account compromised
- Evidence of data exfiltration
- Lateral movement to other systems confirmed
- Persistence mechanism installed (new accounts, scheduled tasks)
- Insider threat suspected
- Scope of compromise is unclear or expanding

---

## 📝 Step 8 — Documentation & Closure

```
- Alert ID and trigger source
- Compromised account(s) — username and account type
- Source IP, geolocation, and access method
- Resources accessed — list all systems and data touched
- Timeline of attacker activity (first access → last action)
- Privilege escalation: Yes / No
- Lateral movement: Yes / No
- Data exfiltration: Yes / No / Unknown
- Containment actions applied with timestamps
- Escalated: Yes / No — if yes, to whom
- Final verdict: True Positive / False Positive
- Root cause (how was access gained?)
- Recommendations to prevent recurrence
```

---

## 🧪 Investigation Checklist

- [ ] Account type confirmed (standard / admin / service)
- [ ] Source IP checked on AbuseIPDB and VirusTotal
- [ ] Sign-in logs reviewed for full session timeline
- [ ] Resources accessed fully scoped
- [ ] Privilege escalation check completed
- [ ] Lateral movement check completed
- [ ] Data exfiltration check completed
- [ ] Inbox rules and MFA devices reviewed
- [ ] Account disabled and sessions revoked
- [ ] Password reset initiated
- [ ] Logs preserved before remediation
- [ ] Ticket fully documented with timeline and IOCs

---

## 📚 References

- [MITRE ATT&CK T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK TA0008 — Lateral Movement](https://attack.mitre.org/tactics/TA0008/)
- [Microsoft — Investigate Compromised Accounts](https://learn.microsoft.com/en-us/microsoft-365/security/defender/investigate-users)
- [CISA — Responding to Unauthorised Access](https://www.cisa.gov/insider-threat-mitigation)
