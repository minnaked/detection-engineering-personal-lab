# Threat Detection Portfolio
### Wazuh · Sysmon · MITRE ATT&CK · Python · Sigma

> Translating 18+ years of Network and Security Engineering into Detection-as-Code.
> Custom detection rules validated with real attack simulation — not vendor defaults.

---

## About This Portfolio

Senior security engineer with deep experience in NDR, network protocol analysis, and security platform operations. This repository demonstrates hands-on detection engineering capability — writing, testing, and documenting threat detections mapped to MITRE ATT&CK.

**Core principle:** Every detection here was built from a real attack log, tested against a live SIEM, and documented with evidence. No theoretical rules.

**Background:** ExtraHop NDR (detection validation, false positive analysis, SOC integration) · Riverbed APM/NPM · Cisco · NUS MTech · CISSP · CySA+ in progress

---

## Lab Architecture

```
Attacker Simulation          Endpoint Telemetry         Detection & Response
──────────────────           ──────────────────         ────────────────────
Atomic Red Team         →    Sysmon (Event ID 1,3,      Wazuh SIEM
(335 MITRE techniques)       8,10,11,12,13,22)     →    Custom XML Rules
                             Wazuh Agent                OpenSearch Indexer
                             Win 11 VM                  Python Triage Tool
                             (windows11Detect)          Sigma Rule Conversion
```

| Component | Version | Role |
|---|---|---|
| Wazuh OVA | 4.14.4 | SIEM — rule engine, alert indexing, dashboard |
| Sysmon | Latest | Endpoint telemetry — process, network, registry events |
| OpenSearch | Bundled | Log indexing and search |
| Atomic Red Team | 335 techniques | TTP simulation and detection validation |
| Python 3 | 3.13 | Alert triage automation via OpenSearch API |
| Sigma CLI | 3.0.2 | Platform-agnostic rule conversion |

---

## Detections Built

All rules tested with Atomic Red Team. Alert evidence in each detection folder.

| Rule ID | Technique | MITRE | Detection Method | Sysmon EID | Level |
|---|---|---|---|---|---|
| 100002 | whoami execution | T1033 | Image field match | 1 | 10 |
| 100003 | whoami from PowerShell | T1033 | Parent process chain | 1 | 12 |
| 100004 | Process injection — full memory rights | T1055 | grantedAccess 0x1FFFFF | 10 | 14 |
| 100005 | systeminfo execution | T1082 | Image field match | 1 | 10 |
| 100006 | systeminfo — renamed binary evasion | T1082 | OriginalFileName (PE header) | 1 | 10 |
| 100007 | systeminfo via cmd wrapper | T1082 | commandLine field | 1 | 10 |
| 100008 | systeminfo from PowerShell | T1082 | Parent process chain | 1 | 12 |
| 100009 | CreateRemoteThread | T1055 | Sysmon Event ID 8 | 8 | 14 |
| 100010 | RemoteThread into sensitive process | T1055 | targetImage match | 8 | 15 |

**MITRE ATT&CK Coverage:** Discovery (T1033, T1082) · Defense Evasion · Process Injection (T1055)

---

## Detection Engineering Approach

### Why Layered Rules

Most detections match one field — the binary name on disk. Attackers rename binaries to bypass this. My detections use three layers:

```
Layer 1 — Image field
Catches standard execution.
systeminfo.exe running → alert.

Layer 2 — OriginalFileName (PE header)
Catches renamed binary evasion.
OriginalFileName is compiled into the binary.
Attackers cannot change it without recompiling.
Renaming systeminfo.exe to svchost32.exe
does not change OriginalFileName — alert still fires.

Layer 3 — commandLine field
Catches wrapper invocations.
cmd.exe /c systeminfo → alert fires
even when binary is called indirectly.
```

One technique. Three detection paths. Harder to evade. Lower false negative rate.

### Detection Lifecycle

```
1. Simulate    Atomic Red Team runs the TTP on Win 11 VM
2. Capture     Sysmon captures process, network, registry events
3. Analyse     Identify key fields — image, commandLine, parentImage
4. Write       Wazuh XML rule + Sigma YAML rule
5. Test        wazuh-logtest validates rule logic
6. Deploy      local_rules.xml — restart wazuh-manager
7. Validate    Alert fires in Wazuh dashboard
8. Document    Log evidence + rule + MITRE mapping on GitHub
```

---

## Detection Rules — Example

**T1082 — Renamed Binary Evasion (Rule 100006)**

```xml
<rule id="100006" level="10">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^1$</field>
    <field name="win.eventdata.originalFileName"
           type="pcre2">(?i)sysinfo\.exe$</field>
    <description>T1082 - systeminfo renamed binary
    detected on $(win.system.computer) by
    $(win.eventdata.user) — evasion attempt
    </description>
    <mitre>
        <id>T1082</id>
    </mitre>
    <group>sysmon_event1,discovery,t1082,evasion_resistant</group>
</rule>
```

**Why OriginalFileName matters:** If an attacker renames `systeminfo.exe` to avoid filename-based detection, the image field changes but OriginalFileName — stored in the PE header and compiled into the binary — remains unchanged. This rule catches the evasion that image-only rules miss.

---

## Sigma Rules

Every detection has a Sigma YAML rule alongside the Wazuh XML — write once, convert to any platform.

```yaml
title: SystemInfo Renamed Binary Execution
id: b7f3a2c1-4d8e-4f9b-a1c2-8e7d6f5a4b3c
status: experimental
description: |
    Detects systeminfo.exe execution using OriginalFileName
    field — catches renamed binary evasion attempts.
    MITRE T1082 System Information Discovery.
author: Mahesh Inna Kedage
date: 2026/05/08
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        OriginalFileName: 'sysinfo.exe'
    condition: selection
falsepositives:
    - None known
level: medium
tags:
    - attack.discovery
    - attack.t1082
```

**Converted to four platforms:**

| Platform | Format |
|---|---|
| Wazuh / OpenSearch | Lucene query |
| Splunk | SPL |
| Elastic | EQL |
| IBM QRadar | AQL |

See `detections/T1082-systeminfo/sigma-conversions.md` for all outputs.

---

## Python Alert Triage Tool

**Problem:** Manual dashboard review creates alert fatigue — analysts miss real detections in noise.

**Solution:** `python-tools/fetch_alert.py` queries the Wazuh OpenSearch API directly, retrieves alerts by rule ID, and extracts structured triage output.

```python
# Sample output
[+] Querying Wazuh at 192.168.1.12...
[ALERT FOUND]
Time:    2026-05-08T06:35:31Z
Agent:   windows11Detect
Rule:    T1053.005 - Scheduled Task Created by vboxuser
Process: C:\Windows\System32\schtasks.exe
Parent:  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User:    WINDOWS11DETECT\vboxuser
Path:    C:\Users\vboxuser\AppData\Local\Temp\
[TRIAGE] Suspicious — schtasks from PowerShell in Temp directory
```

**Engineering details:**
- Queries OpenSearch REST API with rule ID filter
- Parses nested JSON alert structure
- Extracts IOC fields — process, parent, user, path
- Triage logic flags high-confidence detections
- Next: VirusTotal hash enrichment, pytest validation

---

## Repository Structure

```
detection-engineering-lab/
├── README.md
├── detections/
│   ├── T1033-whoami/
│   │   ├── README.md           ← Detection writeup
│   │   ├── wazuh-rule.xml      ← Wazuh XML rules
│   │   ├── sigma-rule.yml      ← Sigma YAML
│   │   └── sigma-conversions.md ← 4 platform outputs
│   ├── T1082-systeminfo/
│   │   └── (same structure)
│   └── T1055-injection/
│       └── (same structure)
├── python-tools/
│   └── fetch_alert.py
├── lab-setup/
│   ├── wazuh-pipeline.yml      ← Sigma field mapping
│   └── architecture.md
└── docs/
    └── troubleshooting.md
```

---

## Lab Troubleshooting — Real Engineering Record

Real problems solved during lab build — not a clean tutorial environment.

| Issue | Root Cause | Fix |
|---|---|---|
| Disk full at 97% | logall=yes writing all events (~1GB/hour) | Set logall=no, add logrotate |
| Indexer OOM killed | JVM heap 2964MB exhausted 6GB RAM | Reduced to 1g, added 4GB swap |
| wazuh-db failed to start | global.db deleted with queue/ directory | RPM force reinstall restored DB |
| wazuh-apid failed | rbac.db owned by root after permission change | chown -R wazuh:wazuh on security/ |
| Rules not firing | Two root XML elements in local_rules.xml | Combined into single group element |
| Internet routing broken | eth1 static default route conflicting NAT | Removed eth1 gateway, kept eth2 NAT |

---

## What Is Next

```
In progress:
→ T1053.005 Scheduled Task detection rules
→ T1059.001 PowerShell encoded command detection
→ T1547.001 Registry Run Key persistence
→ MITRE ATT&CK Navigator coverage heatmap
→ Python triage tool with VirusTotal enrichment
→ pytest detection validation suite
```

---

## Contact

**Mahesh Inna Kedage**
Senior Security Engineer | NDR · Network Analysis · Detection Engineering

- 18+ years network and security engineering
- ExtraHop NDR — detection validation, SOC integration, false positive analysis
- Riverbed APM/NPM — Professional Services and Escalation Engineering
- NUS MTech Software Engineering (Singapore)
- CISSP | CySA+ in progress | CCNP

📧 maheshinnakedage@yahoo.com
🔗 [LinkedIn](https://www.linkedin.com/in/maheshinnakedage)
🐙 [GitHub](https://github.com/minnaked)

---

*Every detection in this repository was built from a real attack log, tested in a live SIEM, and documented with evidence. The troubleshooting record above reflects real engineering — not a scripted tutorial.*
