
# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/prestoncaffey/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

Searched for any file that had the string "tor" in it and discovered what looks like the user "oopsuser" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-07-21T04:48:18.7754634Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "oopst-hreat-hun"
| where FileName contains "tor"
| where InitiatingProcessAccountName == "oopsuser"
| where Timestamp >= datetime(2025-07-21T04:48:18.7754634Z)
| where FileName !contains "tutorial"
| project FileName, FolderPath, Timestamp, ActionType, SHA256, Account = InitiatingProcessAccountName
```
<img width="1159" height="536" alt="image" src="https://github.com/user-attachments/assets/0f475236-f8b6-483a-8a3e-7c08510f238d" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2025-07-21T04:51:50.7754634Z`, "oopsuser" on the "oopst-hreat-hun" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command (/S) that triggered a silent installation

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "oopst-hreat-hun"
| where Timestamp >= datetime(2025-07-21T04:48:18.7754634Z)
| where AccountName == "oopsuser"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.4.exe"
| project AccountName, FileName, FolderPath, Timestamp, ActionType, SHA256, Account = InitiatingProcessAccountName, ProcessCommandLine
```
<img width="1185" height="137" alt="image" src="https://github.com/user-attachments/assets/94dd39eb-e57d-4197-826c-3ae43d5cf38d" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "oopsuser" actually opened the TOR browser. There was evidence that they did open it at `2025-07-21T04:51:18.7754634Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "oopst-hreat-hun"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser")
| project Timestamp, AccountName, ActionType, FileName, FolderPath, InitiatingProcessVersionInfoInternalFileName
```
<img width="1157" height="430" alt="image" src="https://github.com/user-attachments/assets/52be48f0-2cf6-4635-85c1-6d79d0e1115e" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-07-21T04:48:18.7754634Z`, "oopsuser" on the "oopst-hreat-hun" device successfully established a connection to the remote IP address `
95.216.209.129` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\oopsuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "oopst-hreat-hun"
| where InitiatingProcessAccountName == "oopsuser"
| where RemotePort in ("9001", "9040", "9050", "9051", "9150", "9151")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
```
<img width="1162" height="195" alt="image" src="https://github.com/user-attachments/assets/75abb48a-9d3f-4605-a63c-c44fa18fec0e" />



---

## Chronological Event Timeline 

###  1. Tor Installer Download

Time: 2025-07-20 23:48:18 UTC
Action: File renamed (likely indicating a completed download)
File: tor-browser-windows-x86_64-portable-14.5.4.exe
Location: C:\Users\oopsuser\Downloads\
Summary: The user downloaded the Tor Browser portable installer.

### 2. Silent Tor Installation (Process Launch)

Time: 2025-07-20 23:51:50 UTC
Action: Process created
Command: tor-browser-windows-x86_64-portable-14.5.4.exe /S
Location: C:\Users\oopsuser\Downloads\
Summary: The user executed the installer with a silent switch, indicating an automated setup.

### 3. Suspicious File Creation

Time: 2025-07-21 00:25:40 UTC
Action: File renamed
File: tor shopping list.txt
Location: C:\Users\oopsuser\Desktop\
Summary: A text file titled like a checklist related to Tor was created, possibly indicating planning or use intent.

### 4. Tor Browser Execution

Time: Multiple instances after 2025-07-21 00:26:00 UTC
Action: Processes created
Files:
tor.exe
firefox.exe
Location: C:\Users\oopsuser\Desktop\Tor Browser\Browser\TorBrowser\
Summary: The user launched the Tor service (tor.exe) and the Tor Browser frontend (firefox.exe).

### 5. Network Connection via Tor

Time: 2025-07-21 00:53:22 UTC
Action: Connection succeeded
Remote Address: 95.216.209.129 on port 9001
Remote URL: https://www.2hkkwbhj.com
Process: tor.exe
Summary: The system successfully connected to a known Tor relay node over the standard Tor port, confirming active Tor circuit formation.

---

## Summary

The user oopsuser downloaded the Tor Browser portable installer just before midnight on July 20, 2025. Within minutes, they silently installed the browser (/S flag), placing its files directly onto their Desktop. A file named tor shopping list.txt appeared, suggesting possible intent or planning tied to Tor usage .They then executed both the Tor backend (tor.exe) and frontend (firefox.exe) binaries .Around 04:53 UTC, the system connected to a Tor network node via the known port 9001, successfully forming an outbound encrypted Tor circuit. Additional HTTPS (port 443) activity was also logged, suggesting browsing activity may have occurred within the Tor session.

---

## Response Taken

TOR usage was confirmed on the endpoint oopst-hreat-hun by user oopsuser. The device was isolated and the user's direct manager was notified.

---
