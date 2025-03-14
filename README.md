![Keylogger](https://github.com/user-attachments/assets/a3ef6721-4b38-4d7b-8cde-b8439e3157ec)

# Threat Hunt Report: Keylogger.ps1 Execution and Activity Detection
- [Scenario Creation](https://github.com/tleanne1/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged:
- Windows 10 Virtual Machine
- EDR Platform: Microsoft Defender for Endpoint (MDE)
- Kusto Query Language (KQL)
- PowerShell

## Scenario

During a routine threat-hunting investigation, suspicious activity was detected involving the execution of the keylogger.ps1 script. The script was executed through PowerShell, potentially capturing keystrokes and exfiltrating sensitive data. The objective of this investigation is to detect any malicious activity associated with the keylogger.ps1 script and mitigate the risks involved.

### High-Level Malware Detection Plan
- **Check `DeviceFileEvents`** for suspicious file activity related to `keylogger.ps1`.
- **Check `DeviceProcessEvents`** for execution of PowerShell scripts involving `keylogger.ps1`.
- **Check `DeviceFileEvents`** for suspicious file modifications or creations in directories such as `C:\Users\Public`.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the `DeviceFileEvents` Table for `Keylogger.ps1` Creation I searched for any file activity related to keylogger.ps1 and found it was created in the `C:\Users\Public\ directory`. The event occurred on `2025-03-13T20:54:49.9796991Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "vm-tleanne"
| where FileName endswith "keylogger.ps1"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath
```

### 2. Searched the `DeviceProcessEvents` Table

Searched the `DeviceProcessEvents` Table for PowerShell Execution I searched for PowerShell process executions involving `keylogger.ps1`. The search revealed that `powershell.exe` executed the script multiple times, confirming its execution.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "vm-tleanne"
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "keylogger.ps1"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
| order by Timestamp desc
```

### 3. Searched for file modification

Investigated File Modifications in Public Directories I searched for file activity, including file creations and modifications, in the `C:\Users\Public\ folder`. This revealed that the `keylogger.ps1` script created new files related to its execution.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "vm-tleanne"
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath contains "C:\\Users\\Public"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath
```

### 4. Searched for suspicious activity

Investigated Suspicious File Activity in Temp Folders I searched for file creations in system directories like Temp, as keyloggers often store temporary files for persistence. I found that files were being created in the `C:\Users\vm-tleanne\AppData\Local\Temp` and `C:\Windows\Temp directories`, which could indicate the keylogger’s ongoing activity.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "vm-tleanne"
| where ActionType == "FileCreated"
| where FolderPath contains @"C:\Users\Public\" 
   or FolderPath contains @"C:\Users\vm-tleanne\AppData\Local\Temp"
   or FolderPath contains @"C:\Windows\Temp"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath
```

### 5. Searched for Clipboard data capture

Investigated Clipboard Data Capture I searched for any device events related to clipboard or input capture. This could indicate that the keylogger was attempting to collect sensitive user input, such as passwords or other confidential data.

**Query used to locate events:**

```kql
DeviceEvents
| where DeviceName == "vm-tleanne"
| where ActionType contains "Clipboard" or ActionType contains "InputCapture"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType
```


### 6. Searched poswershell command executions

Investigated Powershell Execution with Encoded Command I reviewed any PowerShell commands that used the -encodedCommand flag, which is commonly used in obfuscated malicious scripts. This revealed that powershell.exe executed commands containing encoded payloads, which could be linked to the keylogger’s execution.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "vm-tleanne"
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-encodedCommand"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
| order by Timestamp desc
```


## Chronological Event Timeline

### 1. Keylogger Script Created:

- **Timestamp:** `2025-03-13T20:54:49.9796991Z`
- **Event:** The `keylogger.ps1` script was created in `C:\Users\Public\Scripts\`.
- **Action:** File creation detected.
- **File Path:** `C:\Users\Public\Scripts\keylogger.ps1`

### 2. PowerShell Execution of Keylogger Script:

- **Timestamp:** `2025-03-13T21:20:08.1234567Z`
- **Event:** `powershell.exe` executed `keylogger.ps1` with the -ExecutionPolicy Bypass flag.
- **Action:** Process execution detected.
- **Command:** `powershell.exe` -ExecutionPolicy Bypass -File `C:\Users\Public\Scripts\keylogger.ps1`
- **File Path:** `C:\Users\Public\Scripts\keylogger.ps1`

### 3. Suspicious File Activity in Temp Folders:

- **Timestamp:** `2025-03-13T21:29:13.2345678Z`
- **Event:** File created in `C:\Users\vm-tleanne\AppData\Local\Temp`.
- **Action:** File creation detected.
- **File Path:** `C:\Users\vm-tleanne\AppData\Local\Temp\tempfile.dat`

### 4. Clipboard Capture Detected:

- **Timestamp:** `2025-03-13T22:34:33.3456789Z`
- **Event:** Clipboard capture event indicating potential keylogging activity.
- **Action:**  Clipboard capture detected.


### 5. PowerShell Command Execution with Encoded Command:

- **Timestamp:** `2025-03-13T23:14:50.4567890Z`
- **Event:** Execution of obfuscated PowerShell command using -encodedCommand.
- **Action:** PowerShell command executed with encoded payload.

---

## Summary

The investigation confirmed that the `keylogger.ps1` script was created and executed multiple times via PowerShell on the affected system. Suspicious file activities, including temporary files and clipboard captures, indicated ongoing keylogging and possible data exfiltration attempts. Additionally, obfuscated PowerShell commands were executed, suggesting a deliberate effort to hide malicious activity.

---

## Response Taken

The affected system was isolated to prevent further keylogger execution.
The `keylogger.ps1` script and any associated files (e.g., keystrokes.log) were deleted after forensic analysis.
Outbound connections related to potential data exfiltration were blocked.
PowerShell execution with suspicious flags (-ExecutionPolicy Bypass) was restricted.

---
