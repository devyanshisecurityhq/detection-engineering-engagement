# Threat Hunt 01 — LSASS Memory Access

**Hunt ID:** HUNT-001  
**Analyst:** Devyanshi (devyanshisecurityhq)  
**Date:** 2026-10-05  
**ATT&CK Technique:** T1003.001 (OS Credential Dumping: LSASS Memory)  
**Status:** CONFIRMED

---

## 1. Hypothesis

A compromised host on the network is attempting to dump LSASS process memory to extract credentials. This would be visible as unusual process access to `lsass.exe` (Sysmon Event ID 10) from processes that are not typical system or security tools.

---

## 2. Method

### Data Sources
- **Dataset:** EVTX-ATTACK-SAMPLES
- **File:** `Credential Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx`
- **Log Source:** Sysmon Event ID 10 (Process Access)
- **Fields Analyzed:** SourceImage, TargetImage, GrantedAccess, CallTrace, UtcTime

### Analysis Approach
1. Parsed the EVTX file using `python-evtx` library
2. Filtered events where `TargetImage` ends with `lsass.exe`
3. Grouped by `SourceImage` to identify who accessed LSASS
4. Examined `GrantedAccess` masks for credential-dumping patterns
5. Reviewed call traces for suspicious DLL paths

### Tooling
- Python 3.14
- `python-evtx` library
- Custom script: `scripts/analyze_lsass.py`

---

## 3. Findings

### Event Count
- Total events parsed: **1**
- LSASS access events: **1**

### Source Process (Who accessed LSASS)

| Count | Source Image |
|---|---|
| 1 | `C:\Users\IEUser\Desktop\mimikatz_trunk\Win32\mimikatz.exe` |

**Analysis:** The source process is `mimikatz.exe` running from a user's Desktop directory (`C:\Users\IEUser\Desktop\mimikatz_trunk\Win32\`). Mimikatz is a well-known credential-dumping tool. Running from a user-writable Desktop path is highly suspicious — legitimate security tools are typically installed in `Program Files`.

### Granted Access Masks

| Count | GrantedAccess | Meaning |
|---|---|---|
| 1 | `0x1010` | PROCESS_QUERY_INFORMATION + PROCESS_VM_READ |

**Analysis:** `0x1010` allows reading LSASS process memory — a classic credential-dumping access pattern.

### Event Detail

| Field | Value |
|---|---|
| Time | 2019-03-17 19:37:11.641 |
| SourceImage | `C:\Users\IEUser\Desktop\mimikatz_trunk\Win32\mimikatz.exe` |
| TargetImage | `C:\Windows\system32\lsass.exe` |
| GrantedAccess | `0x1010` |
| CallTrace | `ntdll.dll`, `KERNELBASE.dll`, then Desktop path |

---

## 4. Conclusion

**CONFIRMED — True Positive**

The evidence confirms that **Mimikatz** was executed from a user's Desktop and accessed LSASS process memory with the `0x1010` access mask (read + query). This is a textbook credential-dumping attack.

**ATT&CK Mapping:**
- **T1003.001** — OS Credential Dumping: LSASS Memory

**Detection Coverage:**
- Rule `T1003.001_lsass_memory_dump.yml` **would detect this event** (TargetImage = lsass.exe, GrantedAccess includes 0x1010).
- Rule `T1003.001_comsvcs_credential_dump.yml` **would NOT detect** (different execution method).
- Rule `T1003.001_procdump_credential_dump.yml` **would NOT detect** (different tool).

---

## 5. Recommendations

1. **Containment:** Isolate the affected host from the network.
2. **Eradication:** Remove `mimikatz.exe` and investigate how it was delivered.
3. **Credential Reset:** Assume all credentials on this host are compromised — force password reset for all accounts that logged into this host.
4. **Detection Tuning:** Ensure EDR/AV blocks `mimikatz.exe` execution from user-writable paths.
5. **Hunting Expansion:** Hunt for other processes accessing LSASS with high-privilege access masks across the environment.

---

## 6. Evidence

- **EVTX File:** `datasets/EVTX-ATTACK-SAMPLES/Credential Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx`
- **Script:** `scripts/analyze_lsass.py`
- **Reproducible:** Yes — run `python3 scripts/analyze_lsass.py` to reproduce.
