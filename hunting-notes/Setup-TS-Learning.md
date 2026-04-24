---

## Troubleshooting Log (Real TS Experience)

### Issue 1: Wazuh agent connected but no Sysmon events in dashboard
**Symptom:** 2 agents active, wazuh-alerts-* index showed 0 Sysmon events  
**Root cause:** `logall` and `logall_json` were set to `no` in manager ossec.conf  
**Fix:** Set both to `yes`, restart wazuh-manager and filebeat  
**Lesson:** Wazuh only indexes rule matches by default — all-log archiving needs explicit enablement

### Issue 2: UDP connection drops between agent and manager
**Symptom:** Agent log showed repeated `Server unavailable. Setting lock`  
**Root cause:** TCP was intermittently dropping; switched protocol to UDP  
**Fix:** Changed `<protocol>udp</protocol>` in both agent and manager ossec.conf  
**Lesson:** UDP is stateless — better for log shipping in lab environments; production uses TCP with TLS

### Issue 3: wazuh-archives-* index pattern not found in dashboard
**Symptom:** Index pattern creation failed — no matching indices  
**Root cause:** Filebeat archives module was disabled (`archives: enabled: false`)  
**Fix:** Edited `/etc/filebeat/filebeat.yml`, set `archives: enabled: true`, restarted filebeat  
**Lesson:** Filebeat has separate pipelines for alerts vs archives — both need enabling

### Issue 4: Custom rules not firing for whoami
**Symptom:** whoami visible in Event Viewer and archives.log but no alert  
**Root cause:** Initial rule used wrong field path and no eventID filter  
**Fix:** Used `win.system.eventID: ^1$` + `win.eventdata.image` with pcre2 regex  
**Lesson:** Wazuh rule field names must exactly match the parsed JSON structure

---

## Key Learnings

- Sysmon Event ID 1 (Process Create) is the primary telemetry for execution detection
- Detection rules need both telemetry (what happened) and context (why it matters)
- `wazuh-logtest` is essential for testing rules without running real attacks
- Archives log = all events; Alerts log = only rule matches
- Python + OpenSearch API enables custom triage automation beyond the dashboard

---

## References
- [MITRE ATT&CK T1033](https://attack.mitre.org/techniques/T1033/)
- [Sysmon SwiftOnSecurity Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Atomic Red Team](https://github.com/redcanaryco/invoke-atomicredteam)
- [Wazuh Documentation](https://documentation.wazuh.com)
