# Target MITRE ATT&CK Techniques

**Author:** Devyanshi (devyanshisecurityhq)  
**Date:** 2026-10-05  
**Total Techniques:** 5 (initial batch)

---

## Technique 1: PowerShell Execution

- **ATT&CK ID:** T1059.001
- **Tactic:** Execution
- **Description:** Adversaries abuse PowerShell to execute commands, scripts, and payloads.
- **Dataset Evidence:** `datasets/EVTX-ATTACK-SAMPLES/Execution/exec_sysmon_1_lolbin_pcalua.evtx`
- **Log Source:** Sysmon Event ID 1 (Process Creation)
- **Detection Fields:** Image, CommandLine, ParentImage
- **Severity:** Medium

---

## Technique 2: LSASS Memory Dump

- **ATT&CK ID:** T1003.001
- **Tactic:** Credential Access
- **Description:** Adversaries access LSASS process memory to extract credentials (Mimikatz, comsvcs.dll, etc.).
- **Dataset Evidence:** `datasets/EVTX-ATTACK-SAMPLES/Credential Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx`
- **Log Source:** Sysmon Event ID 10 (Process Access)
- **Detection Fields:** TargetImage, SourceImage, GrantedAccess
- **Severity:** Critical

---

## Technique 3: Scheduled Task Persistence

- **ATT&CK ID:** T1053.005
- **Tactic:** Persistence, Privilege Escalation
- **Description:** Adversaries create scheduled tasks to maintain persistence.
- **Dataset Evidence:** `datasets/EVTX-ATTACK-SAMPLES/Execution/exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx`
- **Log Source:** Windows Security Event ID 4698 / Sysmon Event ID 1
- **Detection Fields:** TaskName, Command, ParentImage
- **Severity:** High

---

## Technique 4: Rundll32 (Signed Binary Proxy Execution)

- **ATT&CK ID:** T1218.011
- **Tactic:** Defense Evasion
- **Description:** Adversaries abuse rundll32.exe to execute malicious DLLs or JavaScript.
- **Dataset Evidence:** `datasets/EVTX-ATTACK-SAMPLES/Execution/exec_sysmon_1_rundll32_pcwutl_LaunchApplication.evtx`
- **Log Source:** Sysmon Event ID 1 (Process Creation)
- **Detection Fields:** Image, CommandLine, ParentImage
- **Severity:** High

---

## Technique 5: WMI Execution

- **ATT&CK ID:** T1047
- **Tactic:** Execution
- **Description:** Adversaries abuse Windows Management Instrumentation (WMI) to execute commands remotely.
- **Dataset Evidence:** `datasets/EVTX-ATTACK-SAMPLES/Execution/exec_wmic_xsl_internet_sysmon_3_1_11.evtx`
- **Log Source:** Sysmon Event ID 1 / 3 (Process Creation / Network)
- **Detection Fields:** Image, CommandLine, DestinationIp
- **Severity:** High

---

## Summary Table

| # | Technique | ATT&CK ID | Tactic | Severity |
|---|---|---|---|---|
| 1 | PowerShell | T1059.001 | Execution | Medium |
| 2 | LSASS Memory Dump | T1003.001 | Credential Access | Critical |
| 3 | Scheduled Task | T1053.005 | Persistence | High |
| 4 | Rundll32 | T1218.011 | Defense Evasion | High |
| 5 | WMI Execution | T1047 | Execution | High |

---

## References

- MITRE ATT&CK: https://attack.mitre.org/techniques/
- Sigma HQ Rules: https://github.com/SigmaHQ/sigma
