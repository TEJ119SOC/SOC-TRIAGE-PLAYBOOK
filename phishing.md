# 🎣 Phishing Email Investigation Playbook

**MITRE ATT&CK Tactic:** Initial Access (TA0001)  
**Technique:** Spearphishing Link (T1566.002) | Spearphishing Attachment (T1566.001)  
**Severity:** Medium – High  
**SLA:** Investigate within 1 hour of alert trigger  

---

## 📌 Overview

Phishing is one of the most common initial access vectors in enterprise environments. This playbook covers the end-to-end process for investigating a suspicious email alert — from initial triage through containment, escalation, and closure.

---

## 🚨 Alert Trigger Sources

- Microsoft Sentinel — phishing alert from mail flow logs
- User-reported suspicious email (helpdesk ticket)
- Microsoft Defender for Office 365 — Safe Links / Safe Attachments alert
- Email gateway alert (blocked or quarantined message)

---

## 🔍 Step 1 — Initial Triage (5–10 mins)

Collect the following information before investigating:

| Field | What to Check |
|-------|--------------|
| Sender address | Does the domain match a known legitimate sender? |
| Reply-to address | Does it differ from the sender? (red flag) |
| Subject line | Urgency language? Password reset? Invoice? |
| Recipient | Targeted individual or mass distribution? |
| Timestamp | Business hours or off-hours send time? |
| Attachments | File name, extension (.exe, .zip, .docx with macros) |
| URLs | Hover to preview — does the display text match the actual URL? |

**Severity Indicators — escalate immediately if any present:**
- Executive or finance team targeted (CEO, CFO)
- Credential harvesting page linked
- Malicious attachment confirmed by sandbox
- Multiple users received the same email

---

## 🔬 Step 2 — Email Header Analysis

Extract and analyse the full email headers:

```
Check the following fields:
- Received: trace the email routing path
- Return-Path: should match the From address
- X-Originating-IP: look up in AbuseIPDB / VirusTotal
- SPF / DKIM / DMARC: all three should pass for legitimate mail
  - SPF FAIL = sender IP not authorised
  - DKIM FAIL = email body tampered in transit
  - DMARC FAIL = domain alignment failure
```

**Tools:**
- [MXToolbox Email Header Analyser](https://mxtoolbox.com/EmailHeaders.aspx)
- [Google Admin Toolbox](https://toolbox.googleapps.com/apps/messageheader/)

---

## 🔗 Step 3 — URL & Link Analysis

If the email contains a URL:

1. **Do NOT click the link directly**
2. Copy the URL and check in:
   - [VirusTotal](https://www.virustotal.com) — multi-engine URL scan
   - [URLScan.io](https://urlscan.io) — visual screenshot + DNS/IP info
   - [AbuseIPDB](https://www.abuseipdb.com) — IP reputation check
3. Note the following:
   - Is the domain newly registered? (< 30 days = high suspicion)
   - Does it spoof a known brand? (e.g. `micros0ft-login.com`)
   - Does it redirect to a credential harvesting page?
   - Is it flagged by any threat intel feeds?

---

## 📎 Step 4 — Attachment Analysis

If the email contains an attachment:

1. **Do NOT open the attachment on a production machine**
2. Note the file hash (MD5 / SHA256) if available from the mail gateway
3. Submit hash or file to:
   - [VirusTotal](https://www.virustotal.com) — AV engine scan
   - [Any.run](https://any.run) — interactive sandbox analysis
   - [Hybrid Analysis](https://www.hybrid-analysis.com) — behavioural sandbox
4. Look for:
   - Macros in Office documents
   - Executable files disguised as documents (e.g. `invoice.pdf.exe`)
   - Archive files containing scripts (.js, .vbs, .bat)

---

## 👤 Step 5 — User & Endpoint Check

If the user clicked the link or opened the attachment:

```
In Microsoft Sentinel / Defender:
1. Search for the user's sign-in logs — any suspicious logins?
2. Check for MFA prompts the user did not initiate
3. Look for impossible travel alerts (login from two countries)
4. Review endpoint logs for:
   - New processes spawned after email opened
   - PowerShell or cmd.exe execution
   - Outbound connections to suspicious IPs
   - New files created in Temp or AppData folders
```

---

## 🚧 Step 6 — Containment Actions

| Action | When to Apply |
|--------|--------------|
| Quarantine the email from all mailboxes | Always for confirmed phish |
| Block sender domain at mail gateway | Confirmed malicious sender |
| Block malicious URL at proxy / firewall | Confirmed malicious link |
| Reset user credentials | User clicked link / entered credentials |
| Isolate endpoint | Malware execution confirmed |
| Revoke active sessions | Account compromise suspected |
| Notify user | Always — educate on what happened |

---

## 📋 Step 7 — Escalation Criteria

**Escalate to Tier 2 if:**
- User confirmed credentials were entered
- Malware execution detected on endpoint
- Multiple users affected by same campaign
- Executive or privileged account targeted
- Data exfiltration activity detected

---

## 📝 Step 8 — Documentation & Closure

Record the following in your ticketing system (ServiceNow / JIRA):

```
- Alert ID and source
- Sender, recipient, subject, timestamp
- IOCs identified (URLs, IPs, file hashes, domains)
- Analysis summary (what tools used, what was found)
- Actions taken (containment steps applied)
- Escalated: Yes / No — if yes, to whom
- Final verdict: True Positive / False Positive / Benign
- Lessons learned or detection gaps identified
```

---

## 🧪 IOC Checklist

- [ ] Sender email address checked
- [ ] Reply-to address checked
- [ ] Email headers analysed (SPF/DKIM/DMARC)
- [ ] Originating IP checked on AbuseIPDB
- [ ] URLs submitted to VirusTotal and URLScan
- [ ] Attachments submitted to sandbox
- [ ] User endpoint reviewed in EDR
- [ ] Sign-in logs reviewed for compromise
- [ ] Containment actions applied
- [ ] Ticket updated with all findings

---

## 📚 References

- [MITRE ATT&CK T1566 — Phishing](https://attack.mitre.org/techniques/T1566/)
- [Microsoft — Investigate Phishing with Defender for Office 365](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/)
- [CISA Phishing Guidance](https://www.cisa.gov/phishing)
