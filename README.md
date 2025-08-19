<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/ericjohnson4/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md) 

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-08-18T21:44:48.3856564Z`. These events began at `2025-08-18T21:11:19.7649735Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "eric-mde-test-3"  
| where InitiatingProcessAccountName == "erijoh0124"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2025-08-18T21:11:19.7649735Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1436" height="386" alt="image" src="https://github.com/user-attachments/assets/697cea97-81ba-4ec5-841e-5634be5f0b15" />



---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.5.exe". Based on the logs returned, at `2025-08-18T21:03:07.8734808Z`, an employee on the "eric-mde-test-3" device ran the file `tor-browser-windows-x86_64-portable-14.5.5.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "eric-mde-test-3"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.5.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1419" height="425" alt="image" src="https://github.com/user-attachments/assets/0bb84560-09c3-4ce7-9227-f1dae9f363d7" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "erijoh0124" actually opened the TOR browser. There was evidence that they did open it at `2025-08-18T21:03:53.6602682Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "eric-mde-test-3"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1419" height="353" alt="image" src="https://github.com/user-attachments/assets/4513d0a7-3e08-4c56-a9d8-8f7796603860" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-08-18T21:19:02.9934926Z`, an employee on the "eric-mde-test-3" device successfully established a connection to the remote IP address ` 89.190.6.9` on port `9030`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\erijoh0124\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "eric-mde-test-3"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1437" height="356" alt="image" src="https://github.com/user-attachments/assets/e987f31c-4e44-46a1-97b9-4616955db7d6" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-08-18T21:11:19.7649735Z`
- **Event:** The user "erijoh0124" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.5.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\erijoh0124\Downloads\tor-browser-windows-x86_64-portable-14.5.5 (1).exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-08-18T21:03:07.8734808Z`
- **Event:** The user " erijoh0124" executed the file ``tor-browser-windows-x86_64-portable-14.5.5.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\erijoh0124\Downloads\tor-browser-windows-x86_64-portable-14.5.5.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-08-18T21:03:53.6602682Z`
- **Event:** User "erijoh0124" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\erijoh0124\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-08-18T21:19:02.9934926Z`
- **Event:** A network connection to IP `89.190.6.9` on port `9030` by user "erijoh0124" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\erijoh0124\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-08-18T21:19:01.4831995Z` - Connected to `66.179.248.50` on port `443`.
  - `2025-08-18T21:19:34.0536856Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "erijoh0124" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-08-18T21:44:48.3856564Z`
- **Event:** The user "erijoh0124" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\erijoh0124\Desktop\tor-shopping-list.txt`

---

## Summary

The user "erijoh0124" on the "eric-mde-test-3" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `eric-mde-test-3` by the user `erijoh0124`. The device was isolated, and the user's direct manager was notified.

---
