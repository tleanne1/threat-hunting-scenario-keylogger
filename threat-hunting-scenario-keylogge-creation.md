# Threat Event (Keylogger.ps1 Execution)
**Suspicious Keylogger.ps1 Execution Detected**

## Steps the "Bad Actor" took to Create Logs and IoCs:
1. **Keylogger.ps1 Script Created:**
   - The attacker created the `keylogger.ps1` script, typically located in the `C:\Users\Public\Scripts\` directory.
2. **PowerShell Execution:**
   - PowerShell was used to execute the script. A command such as:
     ```
     powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\Scripts\keylogger.ps1
     ```
   was likely executed, running the script in the background with elevated privileges.
3. **File Modifications:**
   - The attacker created new files and modified existing files in system directories like `C:\Users\vm-tleanne\AppData\Local\Temp` and `C:\Windows\Temp` to facilitate persistence and concealment.
4. **Clipboard and Input Capture:**
   - Suspicious device events related to clipboard and input capture activities were triggered, possibly to collect sensitive information like passwords and private data.
5. **Encoded Command Execution:**
   - PowerShell commands executed with `-encodedCommand` flags, typically used for obfuscation, were detected, hinting at efforts to hide malicious activity.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting TOR download and installation, as well as the shopping list creation and deletion. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the silent installation of TOR as well as the TOR browser and service launching.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect TOR network activity, specifically tor.exe and firefox.exe making connections over ports to be used by TOR (9001, 9030, 9040, 9050, 9051, 9150).|

---

## Related Queries:
```kql
// Keylogger.ps1 Script Created in Public Folder
DeviceFileEvents
| where DeviceName == "vm-tleanne"
| where FileName endswith "keylogger.ps1"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath

// PowerShell Executed with keylogger.ps1
DeviceProcessEvents
| where DeviceName == "vm-tleanne"
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "keylogger.ps1"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
| order by Timestamp desc

// Suspicious File Modifications in Public Folders
DeviceFileEvents
| where DeviceName == "vm-tleanne"
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath contains "C:\\Users\\Public"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath

// File Creation in Temp Directories (Persistence & Concealment)
DeviceFileEvents
| where DeviceName == "vm-tleanne"
| where ActionType == "FileCreated"
| where FolderPath contains @"C:\Users\Public\" 
   or FolderPath contains @"C:\Users\vm-tleanne\AppData\Local\Temp"
   or FolderPath contains @"C:\Windows\Temp"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath

// Clipboard Capture or Input Capture Detected
DeviceEvents
| where DeviceName == "vm-tleanne"
| where ActionType contains "Clipboard" or ActionType contains "InputCapture"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType

// Obfuscated PowerShell Command with Encoded Payload
DeviceProcessEvents
| where DeviceName == "vm-tleanne"
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-encodedCommand"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
| order by Timestamp desc
```

---

## Created By:
- **Author Name**: Tracey B
- **Author Contact**: https://www.linkedin.com/in/tleanne/
- **Date**: March 13, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `March  13, 2025`  | `Tracey B`   
