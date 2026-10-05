# Data Dictionary — RDRS Detection Engineering Engagement

**Author:** Devyanshi (devyanshisecurityhq)  
**Date:** 2026-10-05  
**Engagement:** Cyberion Defense Labs — Detection Engineering & Threat Hunting

---

## 1. Datasets Selected

### 1.1 EVTX-ATTACK-SAMPLES
- **Source:** https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
- **Type:** Windows Event Logs (EVTX format)
- **Size:** ~6 MB (2178 objects)
- **Description:** Real Windows event log samples mapped to MITRE ATT&CK techniques.
- **Coverage:** Execution, Credential Access, Persistence, Lateral Movement, Defense Evasion, Discovery, Command and Control, Privilege Escalation

### 1.2 Mordor
- **Source:** https://github.com/OTRF/Mordor
- **Type:** Pre-recorded adversary emulation datasets
- **Size:** ~530 MB
- **Description:** Real attack telemetry from red team simulations (Sysmon, Windows Security, etc.)

---

## 2. Log Sources

### 2.1 Sysmon (System Monitor)
- **Provider:** Microsoft-Windows-Sysmon
- **Channel:** Microsoft-Windows-Sysmon/Operational
- **Format:** EVTX

**Key Event IDs:**
| Event ID | Description | Detection Use |
|---|---|---|
| 1 | Process Creation | Detect suspicious process execution |
| 3 | Network Connection | Detect C2 beaconing, lateral movement |
| 7 | Image Loaded | Detect DLL injection, LOLBins |
| 10 | Process Access | Detect LSASS access, credential dumping |
| 11 | File Created | Detect dropped payloads |
| 13 | Registry Value Set | Detect persistence, defense evasion |
| 17/18 | Pipe Created/Connected | Detect named pipe C2 |

### 2.2 Windows Security
- **Provider:** Microsoft-Windows-Security-Auditing
- **Channel:** Security
- **Format:** EVTX

**Key Event IDs:**
| Event ID | Description | Detection Use |
|---|---|---|
| 4624 | Successful Logon | Detect valid account abuse, lateral movement |
| 4625 | Failed Logon | Detect brute force, password spray |
| 4648 | Explicit Credential Logon | Detect credential theft |
| 4662 | Directory Service Access | Detect DCSync |
| 4672 | Special Privileges Assigned | Detect privilege escalation |
| 4688 | Process Creation | Detect suspicious execution |
| 4720 | User Account Created | Detect persistence |
| 4742 | Computer Account Changed | Detect Zerologon |
| 4771 | Kerberos Pre-Auth Failed | Detect password spray |
| 4776 | NTLM Authentication | Detect credential attacks |

### 2.3 PowerShell
- **Provider:** Microsoft-Windows-PowerShell
- **Channel:** Microsoft-Windows-PowerShell/Operational
- **Format:** EVTX

**Key Event IDs:**
| Event ID | Description | Detection Use |
|---|---|---|
| 4103 | Module Logging | Detect PowerShell commands |
| 4104 | Script Block Logging | Detect malicious scripts |

---

## 3. Fields (Sysmon Event ID 1 — Process Creation)

| Field | Description | Detection Value |
|---|---|---|
| UtcTime | Event timestamp | Timeline reconstruction |
| ProcessGuid | Unique process GUID | Process tracking |
| ProcessId | Process ID | Process correlation |
| Image | Full path of executable | Detect LOLBins, suspicious paths |
| CommandLine | Full command line | Detect suspicious arguments |
| CurrentDirectory | Working directory | Detect unusual locations |
| User | User account | Detect privilege context |
| ParentImage | Parent process path | Detect parent-child anomalies |
| ParentCommandLine | Parent command line | Detect macro → cmd → powershell chains |
| IntegrityLevel | Process integrity | Detect privilege escalation |
| Hashes | MD5/SHA256/IMPHASH | IOC matching |

---

## 4. Detection Standpoint Summary

### What We Can Detect
- **Execution:** LOLBins (rundll32, regsvr32, mshta), suspicious PowerShell, WMI abuse
- **Credential Access:** LSASS memory access, Mimikatz, DCSync, password spray
- **Persistence:** Scheduled tasks, registry run keys, services
- **Lateral Movement:** PsExec, WMI, RDP, SMB
- **Defense Evasion:** Process injection, signed binary proxy execution
- **Command and Control:** Network connections, named pipes, DNS

### What We Cannot Detect (from these datasets)
- Initial Access (phishing, exploit kits) — no email/web logs
- Exfiltration (data transfer) — no DLP/proxy logs
- Full network traffic — limited to Sysmon Event 3

---

## 5. References

- MITRE ATT&CK: https://attack.mitre.org/
- Sigma Specification: https://github.com/SigmaHQ/sigma-specification
- EVTX-ATTACK-SAMPLES: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
- Mordor: https://github.com/OTRF/Mordor
