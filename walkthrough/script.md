# Walkthrough Video Script

> **Target length:** 6–7 minutes. Recruiters skim; do not exceed 8.
> **Tool:** Loom, OBS, or screen recorder of choice. Upload to YouTube unlisted, link from README.
> **Status:** skeleton — populated in Phase 6.

---

## Beats (with target durations)

### 0:00–0:30 — Hook
> "I'm [name]. This is a fully reproducible Active Directory lab in AWS where I emulate three lateral movement techniques, detect them with Sigma rules, and document the investigation as a SOC analyst would. Everything you see is in the repo linked below."

### 0:30–1:30 — Architecture (1 min)
- Show README architecture diagram
- Call out: 4 hosts, private subnet for Windows, Wazuh as SIEM, Kali as the attacker
- One sentence on cost discipline ("auto-stop nightly, budgets at $25, terraform destroy after every session")

### 1:30–3:00 — Live attack (1.5 min)
- Show terminal: SSH to Kali
- Run T1021.006 WinRM atomic
- Cut to Wazuh dashboard: alert fires
- Highlight the rule name and the matching event

### 3:00–5:00 — Investigation (2 min)
This is the meat. Walk through:
- Initial alert
- Pivot: who is the user, what host, what source
- Sysmon process tree showing wsmprovhost → powershell → encoded command
- Decode the encoded command live
- IOC list

### 5:00–6:00 — The artifacts (1 min)
- Switch to repo
- Open the Sigma rule — point out the ATT&CK tags
- Open the IR report — show the timeline and the NIST 800-61 mapping
- Open the GHA workflow run — show CI green

### 6:00–6:45 — Wrap (45s)
> "What this lab proves: I can stand up a detection environment, run authorized adversary emulation, write production-quality detection rules, investigate end-to-end, and document findings against both ATT&CK and NIST. Repo and full IR report are linked. Happy to walk through any part of this in an interview."

---

## Recording checklist
- [ ] Hide bookmarks bar and personal tabs
- [ ] Increase terminal font to 16+
- [ ] Use a fresh AWS profile name (no account IDs visible)
- [ ] Practice once before recording
- [ ] Don't apologize for anything in the video — edit instead
