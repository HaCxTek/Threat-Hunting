<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/HaCxTek/Threat-Hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-04-13T15:27:29.7703985Z`. These events began at `2025-04-13T15:20:13.5873717Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "hacx-mde-vm"
| where InitiatingProcessAccountName == "employee1"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-04-13T15:20:13.5873717Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![image](https://github.com/user-attachments/assets/6dc2a233-8da6-4e46-9a54-7fff261daba8)

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents within `ProcessCommandLine` for anything containing the string "tor-browser-windows-x86_64-portable-14.0.9.exe". Based on the logs returned, at `2025-04-13T15:22:39.3329279Z`, an employee on the "hacx-mde-vm" device ran the file `tor-browser-windows-x86_64-portable-14.0.9.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "hacx-mde-vm"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.9.exe"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/5541f02e-9df8-4d9b-9b8c-d82a92c60a24)



---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee1" actually opened the TOR browser. There was evidence that they did open it at `2025-04-13T15:23:43.0187231Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "hacx-mde-vm"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exse")
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/eb1b0450-27e1-4a47-93ff-f34d4d3c080e)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-04-13T15:23:55.6579151Z`, an employee on the "hacx-mde-vm" device successfully established a connection to the remote IP address `147.135.114.245` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee1\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "hacx-mde-vm"
| where InitiatingProcessAccountName == "employee1"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project  Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/a9d1142f-ceb5-4a47-b0ea-cb62c2a53b40)


---

# 🕒 Timeline of Events

## 🧩 Tor Browser Installation & Execution  
**2025-04-13T11:22:39Z**  
`tor-browser-windows-x86_64-portable-14.0.9.exe` was executed from the **Downloads** folder. This suggests the initiation of a silent install by user `employee1`.

---

## ⚙️ Process Activity from Tor Browser Launch  
**2025-04-13T11:23:44Z to 11:23:48Z**  
Multiple processes of `firefox.exe` (Tor Browser) and `tor.exe` were created from the Tor installation directory:  
`C:\Users\employee1\Desktop\Tor Browser\Browser\TorBrowser\...`  

These entries reflect the startup routines and background threads associated with launching the Tor Browser and initializing its service.

---

## 🌐 Network Activity Over Tor

**2025-04-13T11:23:53Z**  
Connection attempt to external IP `162.247.74.202` over port **443** using `tor.exe`.

**2025-04-13T11:23:55Z**  
Two connections to `147.135.114.245` on port **9001** (known Tor network relay port) via `tor.exe`, one with a known .onion-related URL:  
`https://www.7fswpheajip.com`

**2025-04-13T11:24:03Z**  
Loopback connection to `127.0.0.1:9150` via `firefox.exe`. This suggests **Tor proxy configuration** is in use—the browser is routing traffic through the Tor service.

---

## 📦 Tor-Related File Activity

**2025-04-13T15:20:13Z**  
Initial Tor-related file activity started. Various Tor-related files began appearing in the user's **Desktop** folder.

**2025-04-13T15:27:29Z**  
A file named `tor-shopping-list` was created on the Desktop, indicating potential user interaction with or intent to use the Tor network for specific purposes.


---

## 🧾 Summary of Tor Browser Activity – April 13, 2025

User `employee1` on VM `hacx-mde-vm` downloaded and executed a **Tor Browser installer** on the morning of **April 13, 2025**.

---

The installer triggered a **silent install**, and shortly after, multiple **Tor-related processes** (`firefox.exe`, `tor.exe`) were observed running.

---

A series of **network connections** typical of Tor behavior followed, including:
- Outbound connections to **Tor relays** over port `9001`
- Proxy usage via **loopback (127.0.0.1)**

---

Later that day, there was **desktop file activity**, including the creation of a file titled `tor-shopping-list`, which might warrant deeper content inspection.

---

This strongly indicates **deliberate use of the Tor Browser** on the monitored machine, potentially with intent to **anonymize activity** or access **hidden services**.


---

## 🛡️ Response Taken

**TOR usage** was confirmed on endpoint `hacx-mde-vm` by user `employee1`.

The device was **isolated**, and the user's **direct manager** was notified.


---
