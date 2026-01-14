# Notes: Wireshark Essentials

This my public notes regarding my experiences with **Wireshark** basics and common network analysis knowledge.

**Date**: January 14, 2026  
**Source**: Video Lectures & Personal Practice

---

## Research Overview

**Wireshark** is a free and open-source software for computer network scanning and monitoring. It makes the analysis of computer networks **significantly** more comfortable and informative by providing deep visibility into traffic patterns.

---

### 1. Lab Environment Setup

* **Linux**: On Kali Linux, Wireshark is pre-installed. It can be launched via terminal using **$ wireshark &**, which opens the interface selection window (eth0, bluetooth-monitor, etc.)

* **Windows/WSL2**: For maximum compatibility when using WSL2, installing on the Windows host is preferred.
  1. Download the Windows x64 Installer from www.wireshark.org.
  2. Select the active interface (e.g., "Wi-Fi") to begin capturing.

---

### 2. Operational Workflow

Analyzing a packet capture isn't about looking at every packet; it’s about **pattern matching**. A standard session follows these steps:  
* Start capturing packets.
* Generate traffic (e.g., searching on Google).
* Stop capturing and save the session (e.g., **test234.pcapng**).
* Dive into the interface components: capture filters, display filters, colorizing, and profiles.

---

## Technical Cheat Sheet
### Common Offensive Scenarios

* **Credential Hunting**: Searching for plaintext credentials in unencrypted traffic.
* **Recon & Discovery**: Identifying if the network is being actively scanned.
* **Lateral Movement**: Monitoring how an attacker moves between machines (pivoting).
* **Exploit Verification**: Debugging failed exploits by analyzing malformed packets and server responses.

---

### Pattern Identification

Scenario	Indicators & Traffic Patterns:  
* **Auth Exfiltration**:	Look for **POST /login.php** or **POST /wp-login.php**, etc. Inspect the body for sequences like e.g. **uname: admin** and **pass: Winter2024!**.
* **Port Scanning**: A "wall" of **[SYN] packets** from a single source to multiple IPs or ports (e.g., 192.168.1.5 -> .10, .11, .12 on Port 80).
* **SMB Exploitation**: Look for **SMB2 traffic** with "Create Request" for suspicious files like **PSEXESVC.exe** or random strings in **C:\Windows**.
* **Exploit Debugging**: Analyze the route of the exploit and the specific server response codes to troubleshoot failures.

---

## Personal Insights & Conclusions

> **Author's Perspective**:
> When you first see the running lines of IPs and hex data, it’s normal to think "what is going on here?" However, once you familiarize yourself with display filters and protocol hierarchy, the noise clears.
>
> **From an Offensive Security standpoint**,
> Wireshark is the ultimate "truth" in the wire. If an exploit fails, the answer is in the packets. If a user authenticates over HTTP/FTP/Telnet, their identity is mine. As a Junior Red Team specialist, mastering these patterns is essential for verifying my impact and staying stealthy.

---

## Sources

* **YouTube ~1h lecture #1 about Wireshark essentials**: https://youtu.be/byL8VMEMC0M
* **YouTube ~1h lecture #2 about Wireshark essentials**: https://youtu.be/a_4MjV_-7Sw
* **YouTube ~0.3h extra lecture #3 for consolidation of Wireshark essential info**: https://youtu.be/qTaOZrDnMzQ
* **Wireshark cheat sheet**: https://www.stationx.net/how-to-use-wireshark-to-capture-network-traffic

---

*Notes compiled based on open video materials.*

