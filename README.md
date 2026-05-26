# SOC-TRIAGE-PLAYBOOK
# 🛡️ SOC Triage Playbook

A collection of incident response playbooks and triage procedures for common Security Operations Centre (SOC) scenarios, built from real-world experience as a SOC Analyst Level 1.

These playbooks are aligned to the **MITRE ATT&CK framework** and designed to support Tier 1 analysts in detecting, triaging, and escalating security incidents efficiently.

---

## 📂 Playbooks Included

| Playbook | MITRE Tactic | Severity |
|----------|-------------|----------|
| [Phishing Email Investigation](./playbooks/phishing.md) | Initial Access (TA0001) | Medium–High |
| [Malware Detection & Response](./playbooks/malware.md) | Execution (TA0002) | High–Critical |
| [Brute Force / Password Spray](./playbooks/brute-force.md) | Credential Access (TA0006) | Medium |
| [Unauthorised Access](./playbooks/unauthorised-access.md) | Lateral Movement (TA0008) | High |

---

## 🔁 Standard Triage Workflow

```
Alert Triggered
      ↓
1. Identify & Classify
      ↓
2. Investigate (logs, IOCs, context)
      ↓
3. Determine: True Positive or False Positive?
      ↓
4a. False Positive → Document & Close
4b. True Positive → Contain & Escalate
      ↓
5. Incident Report & Lessons Learned
```

---

## 🧰 Tools Referenced

- **SIEM:** Microsoft Sentinel, Splunk
- **EDR:** CrowdStrike Falcon
- **Threat Intel:** VirusTotal, AbuseIPDB, MXToolbox
- **Ticketing:** ServiceNow, JIRA
- **Framework:** MITRE ATT&CK

---

## 📋 Severity Classification

| Level | Label | Response Time | Action |
|-------|-------|--------------|--------|
| P1 | Critical | Immediate | Contain + escalate to Tier 2 now |
| P2 | High | < 1 hour | Investigate + escalate if confirmed |
| P3 | Medium | < 4 hours | Investigate + monitor |
| P4 | Low | < 24 hours | Log + review |

---

## 👤 Author

**Sai Teja Adapa** — SOC Analyst Level 1  
[LinkedIn](https://www.linkedin.com/in/tejaadapa23) | [Email](mailto:tejadapa2309@gmail.com)

> These playbooks reflect procedures followed in a real enterprise SOC environment using Microsoft Sentinel and are intended as reference material for fellow analysts and learners.
