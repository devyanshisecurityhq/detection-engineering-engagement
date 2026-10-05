# Threat Hunt 02 — PowerShell Download Cradle

**Hunt ID:** HUNT-002  
**Analyst:** Devyanshi (devyanshisecurityhq)  
**Date:** 2026-10-05  
**ATT&CK Technique:** T1059.001 (Command and Scripting Interpreter: PowerShell)  
**Status:** RULED OUT

---

## 1. Hypothesis

An attacker is using PowerShell download cradle techniques (DownloadString, Invoke-WebRequest, Net.WebClient) to fetch and execute remote payloads on a compromised host.

---

## 2. Method

### Data Sources
- **Dataset:** EVTX-ATTACK-SAMPLES
- **Folder:** `Execution/` (34 EVTX files)
- **Log Source:** Sysmon Event ID 1 (Process Creation)
- **Fields Analyzed:** Image, CommandLine, ParentImage, User

### Analysis Approach
1. Parsed all 34 EVTX files in the Execution folder using `python-evtx`
2. Filtered events where `Image` contains `powershell.exe` or `pwsh.exe`
3. Searched CommandLine for known download cradle keywords:
   - `DownloadString`, `DownloadFile`, `DownloadData`
   - `Invoke-WebRequest`, `IWR`, `curl`, `wget`
   - `Net.WebClient`, `Start-BitsTransfer`, `Invoke-RestMethod`
   - `FromBase64String`, `IEX`, `Invoke-Expression`
4. Extracted any URLs found in command lines
5. Documented findings

### Tooling
- Python 3.14
- `python-evtx` library
- Custom script: `scripts/analyze_powershell.py`

---

## 3. Findings

### Event Count
- Total events parsed: **541**
- PowerShell events: **1**
- Download cradle matches: **0**

### The One PowerShell Event

| Field | Value |
|---|---|
| File | `execution_evasion_visual_studio_prebuild_event.evtx` |
| EventID | 1 (Process Creation) |
| Image | `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` |
| CommandLine | `powershell.exe start-process notepad.exe` |
| ParentImage | `C:\Windows\SysWOW64\cmd.exe` |

**Analysis:** This is a benign Visual Studio pre-build event that launches Notepad. It does not use any download cradle technique. No URLs were found in any command lines.

### URLs Found
- **None**

---

## 4. Conclusion

**RULED OUT — No Evidence of Download Cradle Activity**

The hypothesis is **not confirmed**. The Execution dataset contains only one PowerShell invocation, and it is a benign `start-process notepad.exe` command from a Visual Studio build event. No download cradle patterns (DownloadString, Invoke-WebRequest, Net.WebClient) were observed.

**ATT&CK Mapping:**
- **T1059.001** — PowerShell (searched, not found)

**Why This Matters:**
Negative hunt results are valuable. This rules out a common attack pattern in this dataset and confirms that our detection rules for download cradles would not have generated false positives against this telemetry.

**Detection Coverage:**
- Rule `T1059.001_powershell_download_cradle.yml` — **No matches** (as expected)
- Rule `T1059.001_powershell_execution.yml` — **Would match** (PowerShell execution detected)

---

## 5. Recommendations

1. **Dataset Limitation:** The EVTX-ATTACK-SAMPLES Execution folder does not contain download cradle activity. To test this detection rule properly, use Mordor datasets or Atomic Red Team telemetry.
2. **Rule Validation:** The download cradle rule remains untested against real attack telemetry — consider generating telemetry locally with Atomic Red Team (T1059.001).
3. **Positive Finding:** Move on to investigate other techniques (e.g., LSASS access from Hunt 01).

---

## 6. Evidence

- **EVTX Files:** `datasets/EVTX-ATTACK-SAMPLES/Execution/*.evtx` (34 files)
- **Script:** `scripts/analyze_powershell.py`
- **Reproducible:** Yes — run `python3 scripts/analyze_powershell.py` to reproduce.
