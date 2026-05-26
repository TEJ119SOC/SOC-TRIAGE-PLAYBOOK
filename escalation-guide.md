# 📞 Escalation Guide

A reference guide for Tier 1 SOC analysts on when, how, and to whom to escalate security incidents. Clear escalation ensures the right people are engaged at the right time — minimising response time and business impact.

---

## 🏗️ SOC Tier Structure

```
┌─────────────────────────────────────────────┐
│              SOC Manager / CISO              │  ← P1 Major Incidents
├─────────────────────────────────────────────┤
│         Tier 3 — Threat Intelligence        │  ← Advanced Analysis
│              & Detection Engineering        │     New TTPs, Hunting
├─────────────────────────────────────────────┤
│         Tier 2 — Incident Responders        │  ← Confirmed Incidents
│              & Senior Analysts              │     Deep Investigation
├─────────────────────────────────────────────┤
│         Tier 1 — SOC Analysts               │  ← Alert Triage
│              (You are here)                 │     First Response
└─────────────────────────────────────────────┘
```

---

## ⏱️ When to Escalate

### Escalate to Tier 2 when:
- Alert is confirmed as a **true positive**
- **Privileged or admin account** is involved
- **Lateral movement** is detected or suspected
- **Data exfiltration** is detected or suspected
- Incident scope is **unclear or expanding**
- Containment actions are **outside Tier 1 authority**
- Malware is **actively executing** and spreading
- You have investigated for **30+ minutes** without a clear verdict
- **Multiple systems** are affected

### Escalate to Tier 3 when:
- Unknown malware family or **zero-day exploit** suspected
- Attack technique is **not covered by existing playbooks**
- **Detection gap** identified — attacker evaded current rules
- **Threat hunting** is required across the environment
- Advanced persistent threat (APT) activity suspected

### Escalate to SOC Manager when:
- **P1 Critical incident** confirmed
- **Business operations impacted** or at risk
- **Media, legal, or regulatory** implications suspected
- **Insider threat** involving HR or legal sensitivity
- Incident requires **external communication** (customers, partners, regulators)

---

## 📋 What to Prepare Before Escalating

Never escalate without this information ready — it saves time and avoids back-and-forth:

```
✅ Alert ID and SIEM rule name
✅ Affected user(s) — username, account type, department
✅ Affected system(s) — hostname, IP, OS
✅ Timeline — when did the alert fire? When did activity begin?
✅ What you have investigated so far
✅ IOCs identified — IPs, hashes, domains, file paths
✅ Containment actions already taken
✅ Your current severity assessment (P1 / P2 / P3)
✅ Why you are escalating — what triggered the decision
```

---

## 📞 Escalation Communication Template

Use this structure when handing off to Tier 2 verbally or via ticket:

```
"I am escalating [INCIDENT TYPE] — Ticket [ID].

Affected account: [USERNAME] | Account type: [STANDARD / ADMIN]
Affected host: [HOSTNAME] | IP: [IP ADDRESS]
Alert triggered: [TIME] | Activity began: [TIME]

Summary: [2–3 sentences describing what happened]

IOCs identified: [LIST]

Actions taken so far: [LIST]

Reason for escalation: [SPECIFIC TRIGGER — e.g. successful login confirmed,
lateral movement detected, scope unclear]

Current severity: [P1 / P2]"
```

---

## 🚨 P1 Critical Incident — Immediate Escalation Steps

If you confirm or strongly suspect a P1 incident:

1. **Do not wait** — escalate immediately, even with incomplete information
2. **Call Tier 2 directly** — do not rely on ticket alone for P1
3. Notify **SOC Manager** in parallel
4. **Preserve logs** — do not remediate before Tier 2 reviews
5. Begin documenting a **live incident timeline** as events unfold
6. Keep the ticket updated in **real time**

---

## 🔁 Escalation vs. Handoff

| Type | Description |
|------|-------------|
| **Escalation** | You need Tier 2 expertise — incident exceeds Tier 1 scope. You stay involved and support. |
| **Handoff** | End of shift — passing an open investigation to the next analyst. Full context must be documented in the ticket. |

### Shift Handoff Checklist:
- [ ] Ticket updated with all findings so far
- [ ] Current status clearly stated (investigating / contained / escalated)
- [ ] Outstanding actions listed — what still needs to be done
- [ ] IOCs documented in ticket
- [ ] Incoming analyst verbally briefed if P1 or P2

---

## 📁 Ticket Documentation Standards

Every escalated or closed ticket must contain:

| Field | Required |
|-------|----------|
| Alert source and ID | ✅ |
| Affected user and system | ✅ |
| Timeline of events | ✅ |
| IOCs (IPs, hashes, domains) | ✅ |
| Investigation steps taken | ✅ |
| Containment actions applied | ✅ |
| Escalation details (to whom, when, why) | ✅ if escalated |
| Final verdict | ✅ |
| Lessons learned / tuning recommendations | ✅ for TP |

---

## ⚠️ Common Escalation Mistakes to Avoid

- ❌ **Escalating too late** — if in doubt, escalate early
- ❌ **Escalating without context** — always prepare your summary first
- ❌ **Remediating before preserving evidence** — always snapshot / export logs first
- ❌ **Closing a P2 as false positive without Tier 2 review** — get a second opinion on ambiguous cases
- ❌ **Not updating the ticket in real time** — the ticket is the single source of truth
- ❌ **Assuming containment is complete** — always verify actions worked

---

## 📚 References

- [NIST SP 800-61 — Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [Microsoft Sentinel Incident Management](https://learn.microsoft.com/en-us/azure/sentinel/incident-investigation)
