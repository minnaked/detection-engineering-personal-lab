# detection-engineering-personal-lab
Home lab for detection engineering practice using Sysmon, Wazuh, and Python

# Detection Engineering Home Lab

## About
Built by Mahesh Inna Kedage — Looking to transition from 18+ years of 
network/security support, test engineering (ExtraHop NDR, Riverbed, 
Cisco) into Detection Engineering.

This repo documents my hands-on detection engineering practice 
using a home lab built from scratch.

**Certifications in progress:** CySA+ | Post-hire: GCIA  
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

| ID | Technique | MITRE | Severity | Status |
|---|---|---|---|---|
| 100002 | whoami.exe execution | T1033 | Medium (10) | ✅ Live |
| 100003 | whoami from PowerShell | T1033 | High (12) | ✅ Live |
| 100004 | Process Injection (0x1FFFFF) | T1055 | Critical (14) | ✅ Live |

---

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
