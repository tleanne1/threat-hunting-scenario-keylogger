![Keylogger](https://github.com/user-attachments/assets/a3ef6721-4b38-4d7b-8cde-b8439e3157ec)



## Threat Hunt Report: Keylogger.ps1 Detection
- [Scenario Creation](https://github.com/tleanne1/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machine (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint (MDE)
- Kusto Query Language (KQL)
- PowerShell

## Scenario

A malicious PowerShell script (`keylogger.ps1`) was detected on the system. The script appears to capture and log keystrokes, posing a significant security risk. The goal is to identify and mitigate the malicious activity associated with `keylogger.ps1`.

### High-Level Malware Detection Plan

- **Check `DeviceFileEvents`** for file creation and modification related to keylogger.ps1.
- **Check `DeviceProcessEvents`** for PowerShell script execution involving keylogger.ps1.
- **Check `DeviceRegistryEvents`** for persistence mechanisms.

---

## Steps Taken

### 1. Searched the DeviceFileEvents Table

I searched for any file activity related to `keylogger.ps1` and found that it was created in the `C:\Users\Public\Scripts\` directory. The event occurred at `2025-03-10T14:32:25.5678901Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "win10-tleanne"
| where FileName endswith "keylogger.ps1"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath
```

### 2. Searched the DeviceProcessEvents Table for PowerShell Execution

I searched for processes related to the execution of `keylogger.ps1`. The search confirmed that `powershell.exe` executed the script using the -ExecutionPolicy Bypass argument.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "win10-tleanne"
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "keylogger.ps1"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
| order by Timestamp desc
```

### 3. Investigated Registry Persistence

I searched the DeviceRegistryEvents table for any suspicious registry changes that could indicate persistence. The search revealed an entry where `keylogger.ps1` was added to the `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` registry key.

**Query used to locate events:**

```kql
DeviceRegistryEvents
| where DeviceName == "win10-tleanne"
| where RegistryKey contains "CurrentVersion\\Run"
| where RegistryValueName == "Keylogger"
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueData
| order by Timestamp desc
```

## Chronological Event Timeline

### 1. Script Creation: keylogger.ps1

- **Timestamp:** 2`025-03-10T14:32:25.5678901Z`
- **Event:** The script `keylogger.ps1` was created.
- **Action:** File creation detected.
- **File Path:** `C:\Users\Public\Scripts\keylogger.ps1`

### 2. PowerShell Execution: keylogger.ps1

- **Timestamp:** `2025-03-10T14:33:12.4567890Z`
- **Event:** `powershell.exe` executed keylogger.ps1 using a bypass argument.
- **Action:** Process execution detected.
- **Command:** powershell.exe -ExecutionPolicy Bypass -File keylogger.ps1

### 3. Persistence Mechanism: Registry Key

- **Timestamp:** `2025-03-10T14:35:45.1234567Z`
- **Event:** Registry modification to persist `keylogger.ps1` execution on reboot.
- **Action:** Registry value creation detected.
- **Registry Key:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- **Value Data:** `powershell.exe` -ExecutionPolicy Bypass -File `C:\Users\Public\Scripts\keylogger.ps1`

---

## Summary

The system was compromised by the `keylogger.ps1` script, which logged user keystrokes and established persistence through the Windows Registry. The script was executed multiple times via PowerShell with a bypass argument to avoid security restrictions.

---

## Response Taken

The affected system was isolated to prevent further compromise.

The `keylogger.ps1` script and registry entries were deleted after forensic analysis.

All outbound connections related to keylogger activity were blocked.

Findings were reported to the security team for further investigation and preventive measures.

---
