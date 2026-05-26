# 🔓 Brute Force / Password Spray Playbook

**MITRE ATT&CK Tactic:** Credential Access (TA0006)  
**Techniques:** T1110.001 (Brute Force) | T1110.003 (Password Spraying)  
**Severity:** Medium – High  
**SLA:** Investigate within 1 hour | Contain within 2 hours  

---

## 📌 Overview

Brute force and password spray attacks are among the most common credential-based threats in enterprise environments. While brute force targets a single account with many passwords, password spraying tries one common password across many accounts — designed to evade lockout policies.

This playbook covers detection, investigation, and containment of both attack types.

---

## 🚨 Alert Trigger Sources

- Microsoft Sentinel — multiple failed sign-in attempts rule
- Azure Active Directory — risky sign-in alert
- Microsoft Defender for Identity — brute force detection
- SIEM correlation rule — X failed logins within Y minutes
- Azure AD Identity Protection — leaked credentials alert

---

## 🔍 Step 1 — Initial Triage (5–10 mins)

| Field | What to Check |
|-------|--------------|
| Targeted account(s) | Single account (brute force) or many accounts (spray)? |
| Source IP | Internal or external? Known location? |
| Timestamp | When did the attempts start? Still ongoing? |
| Failed login count | How many attempts in what timeframe? |
| Successful login? | Did any attempt succeed? (Critical if yes) |
| User account type | Standard user or privileged / admin account? |
| Geolocation | Expected country or foreign IP? |

**Escalate immediately if:**
- A successful login followed failed attempts
- Privileged or admin account targeted
- Attempts originating from Tor exit node or known malicious IP
- Multiple accounts locked out simultaneously (spray indicator)

---

## 🔬 Step 2 — Log Analysis in Microsoft Sentinel

```kql
// Detect multiple failed sign-ins from same IP
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress, TargetAccount, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
| order by FailedAttempts desc
```

```kql
// Detect password spray — many accounts, few attempts each
SigninLogs
| where ResultType != "0"
| summarize AttemptedAccounts = dcount(UserPrincipalName), Attempts = count() by IPAddress, bin(TimeGenerated, 1h)
| where AttemptedAccounts > 5 and Attempts < 20
| order by AttemptedAccounts desc
```

```kql
// Check if any attempts succeeded after failures
SigninLogs
| where IPAddress == "<suspicious_IP>"
| project TimeGenerated, UserPrincipalName, ResultType, Location, AppDisplayName
| order by TimeGenerated asc
```

---

## 🌍 Step 3 — Source IP Investigation

```
1. Look up the source IP on:
   - AbuseIPDB — is it flagged for prior attacks?
   - VirusTotal — any malicious associations?
   - Shodan — what services is it running?
2. Check geolocation:
   - Is it from a country the user has never logged in from?
   - Is it a VPN, proxy, or Tor exit node?
3. Check if the same IP is targeting multiple accounts
   (strong indicator of password spray)
4. Check if IP has appeared in other alerts in the environment
```

---

## ✅ Step 4 — Successful Login Check

**This is the most critical step — run this immediately:**

```kql
// Check for successful login from suspicious IP
SigninLogs
| where IPAddress == "<suspicious_IP>"
| where ResultType == "0"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, AuthenticationDetails
```

**If a successful login is found:**
- What application was accessed? (Email, VPN, Azure Portal?)
- Was MFA completed or bypassed?
- What actions did the attacker take after logging in?
- Were any files accessed, emails forwarded, or rules created?

---

## 👤 Step 5 — Account & Session Review

```
For any account that had a successful login after brute force:

1. Review recent activity:
   - Email forwarding rules created?
   - Files downloaded or shared externally?
   - New MFA methods registered?
   - Admin roles assigned?

2. Check for impossible travel:
   - Login from India at 09:00, then UK at 09:15 = account compromise

3. Review all active sessions for the account

4. Check if attacker registered new MFA device to maintain persistence
```

---

## 🚧 Step 6 — Containment Actions

| Action | When to Apply |
|--------|--------------|
| Block source IP at firewall | Ongoing attack from identified IP |
| Lock affected user account | Successful login confirmed |
| Force password reset | Account accessed by attacker |
| Revoke all active sessions | Account compromise confirmed |
| Disable legacy authentication | If attack used legacy protocols (SMTP, IMAP) |
| Enable / enforce MFA | If account lacked MFA |
| Remove malicious inbox rules | If attacker created email forwarding rules |
| Alert user and manager | Always for confirmed compromise |

---

## 📋 Step 7 — Escalation Criteria

**Escalate to Tier 2 if:**
- Successful login confirmed from attacker IP
- Privileged or admin account accessed
- Evidence of post-compromise activity (data access, rule creation)
- Multiple accounts compromised in same campaign
- MFA bypass technique identified

---

## 📝 Step 8 — Documentation & Closure

```
- Alert ID and SIEM rule that triggered
- Source IP(s) and geolocation
- Targeted account(s) — usernames and account types
- Attack type: brute force or password spray
- Number of failed attempts and timeframe
- Successful login: Yes / No
- Post-compromise activity identified: Yes / No
- Containment actions applied with timestamps
- Escalated: Yes / No
- Final verdict: True Positive / False Positive
- Recommendations (MFA enforcement, IP block, account review)
```

---

## 🧪 Investigation Checklist

- [ ] Source IP checked on AbuseIPDB and VirusTotal
- [ ] Attack type confirmed: brute force or password spray
- [ ] Successful login check completed
- [ ] Post-compromise activity reviewed
- [ ] Impossible travel check done
- [ ] Active sessions reviewed and revoked if needed
- [ ] Source IP blocked at firewall
- [ ] Affected accounts locked / passwords reset
- [ ] MFA status reviewed for targeted accounts
- [ ] Ticket fully documented

---

## 📚 References

- [MITRE ATT&CK T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)
- [Microsoft — Investigate Risky Sign-ins in Azure AD](https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/)
- [AbuseIPDB](https://www.abuseipdb.com)
- [CISA — Protecting Against Password Spraying](https://www.cisa.gov/news-events/alerts/2018/03/27/alert-ta18-086a)
