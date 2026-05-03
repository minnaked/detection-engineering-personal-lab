# detection-engineering-personal-lab
Home lab for detection engineering practice using Sysmon, Wazuh, and Python

# Detection Engineering Home Lab

## About
Built by Mahesh Inna Kedage — Looking to transition from 18+ years of 
network/security support, test engineering (ExtraHop NDR, Riverbed, 
Cisco) into Detection Engineering.

This repo documents my hands-on detection engineering practice 
using a home lab built from scratch.

**Certifications in progress:** CySA+ | GCIA | ZDTE
**Core background:** CISSP, CCNA, CCNP(Switching), packet analysis, NDR/SIEM operations

---

## Lab Architecture

| Component | Role | Host |
|---|---|---|
| Wazuh OVA 4.x | SIEM / Alert Engine | Intel i5 12GB RAM |
| Windows 11 VM (VirtualBox) | Target endpoint | Intel i5 12GB RAM |
| Sysmon (SwiftOnSecurity config) | Endpoint telemetry | Win 11 VM |
| AMD Host (Ryzen 5000, 24GB) | Attacker simulation / Python scripting | Physical |
| Atomic Red Team | TTP simulation framework | Win 11 VM |
| Python 3 | Alert triage + detection tooling | AMD Host |

**Network:** All VMs on 192.168.1.0/24 host-only network  
**SIEM Indexer:** OpenSearch (bundled with Wazuh OVA)  
**Log shipping:** Wazuh agent → UDP 1514 → Wazuh Manager → OpenSearch

---

## Detections Built

### MITRE ATT&CK Dashboard — May 3, 2026
![MITRE ATT&CK Dashboard](detections/evidence/mitre-attack-dashboard-2026-05-03.png)

## Live Detection Evidence
### Custom Rules Firing in Production

| Rule ID | MITRE | Tactic | Level | Technique | Status |
|---|---|---|---|---|
| 100002 | T1033 | Discovery | 10 | whoami execution | ✅ Live |
| 100003 | T1033 | Discovery | 12 | whoami from PowerShell | ✅ Live |
| 100004 | T1055 | Defense Evasion | 14 | Process injection | ✅ Live |
| 100005 | T1082 | Discovery | 10 | systeminfo execution | ✅ Live |
| 100006 | T1082 | Discovery | 10 | renamed binary evasion | ✅ Live |
| 100007 | T1082 | Discovery | 10 | systeminfo via commandLine | ✅ Live |
| 100008 | T1082 | Discovery | 12 | systeminfo from PowerShell | ✅ Live |

### Detection Engineering Notes
- Rule 100003/100008: High fidelity (level 12) — PowerShell parent 
  indicates post-exploitation context, not normal admin activity
- Rule 100006: Evasion-resistant — catches renamed systeminfo.exe 
  using PE header originalFileName field
- Rule 100007: Catches ART simulation where cmd.exe wraps systeminfo

## Python Tooling

`python-tools/fetch_alert.py` — Queries Wazuh OpenSearch API 
directly, retrieves latest alert by rule ID, extracts key triage 
fields (timestamp, agent, process, user) and performs automated 
triage logic.

**Sample output:**

[+] Connecting to Wazuh Brain at 192.168.1.12...
[SUCCESS] Alert Found!
Time:    2026-04-24T10:29:20.447Z
Target:  windows11Detect
Process: C:\Windows\System32\whoami.exe
User:    WINDOWS11DETECT\vboxuser
[CRITICAL] Automated Triage: Confirmed Lab Activity.
