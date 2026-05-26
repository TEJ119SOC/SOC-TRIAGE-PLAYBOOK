# 🎯 Severity Classification Matrix

A reference guide for classifying and prioritising security incidents in a SOC environment. Consistent severity classification ensures the right response time, actions, and escalation path for every alert.

---

## 📊 Severity Levels

| Level | Label | Colour | Response Time | Example Scenarios |
|-------|-------|--------|--------------|-------------------|
| P1 | Critical | 🔴 Red | Immediate | Ransomware active, domain admin compromised, data exfiltration in progress |
| P2 | High | 🟠 Orange | < 1 hour | Malware execution confirmed, successful login after brute force, lateral movement detected |
| P3 | Medium | 🟡 Yellow | < 4 hours | Phishing email opened, brute force with no success, suspicious process on endpoint |
| P4 | Low | 🟢 Green | < 24 hours | Failed login attempts below threshold, policy violation, informational alert |

---

## 🔴 P1 — Critical

**Definition:** Active, confirmed attack with significant business impact or imminent risk of major damage.

**Characteristics:**
- Attack is ongoing or has just succeeded
- Core business systems, data, or operations are at risk
- Irreversible damage may occur without immediate action

**Examples:**
- Ransomware encrypting files across multiple hosts
- Domain Controller or Active Directory compromise
- Data exfiltration actively in progress
- Complete account takeover of C-suite executive
- Destructive malware (wiper) detected

**Required Actions:**
- Contain immediately — isolate affected systems
- Escalate to Tier 2 and Tier 3 without delay
- Notify SOC Manager and Incident Response team
- Preserve all logs and evidence before remediation
- Initiate formal incident response procedure

---

## 🟠 P2 — High

**Definition:** Confirmed security incident with clear threat to the environment — not yet causing widespread damage but requires urgent investigation and containment.

**Characteristics:**
- True positive confirmed
- Single system or account compromised
- Potential for escalation if not contained quickly

**Examples:**
- Malware execution confirmed on endpoint
- Successful login following brute force attack
- Phishing link clicked and credentials entered
- Privileged account accessed from unusual location
- Lateral movement detected between two internal hosts
- Active C2 communication from endpoint

**Required Actions:**
- Investigate and contain within 1 hour
- Escalate to Tier 2 if scope is unclear
- Apply containment actions (isolate, disable account, block IP)
- Document all findings and IOCs in ticket
- Monitor for escalation to P1

---

## 🟡 P3 — Medium

**Definition:** Suspicious activity that may indicate a threat but is not yet confirmed as a true positive. Requires investigation to determine severity.

**Characteristics:**
- Alert may be true positive or false positive
- Limited impact if confirmed
- No confirmed compromise yet

**Examples:**
- Phishing email received but link not clicked
- Brute force attempts with no successful login
- Suspicious process execution — under investigation
- User accessing resources outside normal pattern
- Port scan detected from internal host
- Single failed MFA prompt not initiated by user

**Required Actions:**
- Investigate within 4 hours
- Determine true positive or false positive
- Apply containment if confirmed true positive
- Escalate to P2 or P1 if evidence of compromise found
- Document findings and close or escalate ticket

---

## 🟢 P4 — Low

**Definition:** Informational or low-risk events that require logging and review but pose minimal immediate threat.

**Characteristics:**
- Very likely false positive or benign activity
- No confirmed malicious intent
- Useful for trend tracking and tuning

**Examples:**
- Single failed login attempt
- User accessing a blocked website (policy violation)
- Outdated software detected on endpoint
- Informational vulnerability scan result
- Low-severity CVE with no active exploitation
- Audit log anomaly with no associated alert

**Required Actions:**
- Review within 24 hours
- Document and close if benign
- Tune detection rule if recurring false positive
- Track for patterns — multiple P4s may indicate a P3 or higher

---

## 📈 Severity Escalation Triggers

An incident should be **escalated to the next severity level** if any of the following are confirmed:

| Current Level | Escalate To | Trigger |
|--------------|-------------|---------|
| P4 → P3 | Medium | Repeated alerts suggest coordinated activity |
| P3 → P2 | High | True positive confirmed, compromise suspected |
| P2 → P1 | Critical | Lateral movement, data exfiltration, or widespread impact confirmed |

---

## 🏷️ Classification by Incident Type

| Incident Type | Default Severity | Escalate If |
|--------------|-----------------|-------------|
| Phishing email (not clicked) | P3 | Executive targeted, credential harvest link |
| Phishing email (clicked, credentials entered) | P2 | Active session hijack confirmed |
| Malware detected (quarantined) | P3 | Execution confirmed before quarantine |
| Malware executing actively | P2 | Lateral movement or C2 active → P1 |
| Brute force (no success) | P3 | Admin account targeted |
| Brute force (successful login) | P2 | Privileged account or data accessed → P1 |
| Unauthorised access | P2 | Data exfiltration or privilege escalation → P1 |
| Ransomware any stage | P1 | Always P1 |
| Insider threat suspected | P2 | Data theft confirmed → P1 |

---

## 📝 Classification Notes

- **When in doubt, classify higher** — it is always better to over-escalate and stand down than to under-escalate and miss a critical incident
- **Re-classify as investigation progresses** — an alert that starts as P3 may become P1 within minutes
- **False positives still get documented** — record why the alert was a false positive to support detection tuning
- **All P1 and P2 incidents require a formal incident report** upon closure

---

## 📚 References

- [NIST SP 800-61 — Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [CISA Incident Severity Schema](https://www.cisa.gov/cyber-incident-severity-schema)
