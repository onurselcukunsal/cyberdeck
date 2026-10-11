# 📡 Cyber-Deck | Passive Wi-Fi Reconnaissance & Framework Tools

A modular, multi-threaded **Python framework** built using **Scapy** and **Rich** libraries for passive Wi-Fi traffic monitoring, transmitter hardware classification, and real-time RSSI signal analysis over the `802.11` protocol layer.

This toolkit is designed for security auditors, red team specialists, and network researchers to perform non-intrusive wireless reconnaissance without broadcasting a single packet, remaining completely invisible to surrounding intrusion detection systems (IDS).

---

## 🎯 Core Features & Capabilities

- **Asynchronous Packet Capture:** Implements multi-threaded `AsyncSniffer` execution routines to guarantee low-overhead packet processing and zero packet drops.
- **Real-Time TUI Dashboard:** Features a high-performance Terminal User Interface (TUI) with interactive live-updating tables for signal monitoring.
- **Granular Frame Classification:** Dissects IEEE 802.11 frames to identify and classify Management, Control, and Data sub-types (e.g., Probe Requests, Beacons, Authentication sequences).
- **Dynamic RSSI Signal Tracking:** Monitors decibel-milliwatts (dBm) signal anomalies via RadioTap headers to map relative transmitter proximity.
- **Thread-Safe State Persistence:** Atomically flushes historical network node logs into structured `.csv` format every 5 seconds utilizing non-blocking file-replacement methods (`.tmp` swapping).

---

## 📁 Repository Structure

| File Name | Interface Type | Primary Use Case |
| :--- | :--- | :--- |
| `mac_hunter_core.py` | CLI (Command Line) | Lightweight, headless logging optimized for background operations and long-term remote deployments. |
| `mac_hunter_live.py` | TUI (Terminal UI) | Real-time interactive field operations, dynamic node assessment, and visual signal tracking. |

---

## 🚀 Installation & Environment Setup

These tools are native-optimized to run on enterprise Linux configurations (e.g., **Fedora Workstation**, Kali Linux) with high-gain packet injection wireless chipsets (e.g., Atheros, Ralink).

### 1. System Dependencies
Install core networking and package utilities via your native package manager (example for Fedora/DNF):
```bash
sudo dnf install -y nmap aircrack-ng python3-pip
```

### 2. Python Dependencies
Clone this repository and install required modules using `pip`:
```bash
pip install scapy rich
```

---

## 💻 Technical Usage Instructions

### Step 1: Initialize Wireless Interface into Monitor Mode
Identify your high-gain external wireless adapter and shift its operational state from Managed to Monitor mode using the `aircrack-ng` suite:
```bash
# Locate your wireless interface (e.g., wlan1)
iwconfig

# Spin up monitor mode kernel interface
sudo airmon-ng start wlan1
```
*(Note: This routine renames your interface layer to `wlan1mon` as configured inside the scripts).*

### Step 2: Fire Up the Recon Framework
Execute the scripts with administrative privileges to unlock raw pocket capture socket bounds (`PF_PACKET`):

**For long-term headless CSV recording:**
```bash
sudo python3 mac_hunter_core.py
```

**For real-time operational TUI dashboard monitoring:**
```bash
sudo python3 mac_hunter_live.py
```

---

## 📊 Technical Architecture Overview

The backend processing flow utilizes a non-blocking consumer/producer architecture:
1. **RadioTap Dissection:** Extracts hardware-level signal characteristics directly from the physical layer (`dBm_AntSignal`).
2. **State Machine Management:** Tracks unique client MAC boundaries via memory-mapped dictionary keys, logging granular properties like `first_seen`, `packet_count`, and dynamic set unions of active `frame_types`.
3. **Atomic Safe IO Handling:** To prevent file corruption during multi-threaded executions, data is temporarily staged onto a `.tmp` partition before triggering an atomic `.replace()` switch to finalize changes securely onto the main disk layout.

---

## ⚠️ Legal & Ethical Disclaimer
This project is strictly developed for educational purposes, defensive analysis, and authorized enterprise network auditing. Operating these scripts against public wireless nodes or without explicit authorization from system owners constitutes a direct violation of international cyber law. The author assumes absolutely zero liability for any misuse or damages resulting from this codebase.
