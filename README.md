# Cyber-Deck | Passive Wi-Fi Reconnaissance Toolkit

This repository contains custom, modular Python tools built with **Scapy** and **Rich** to perform passive Wi-Fi monitoring, transmitter address analysis, and packet classification over the `8002.11` protocol stack.

### Tools Included:
- **mac_hunter_core.py:** Low-overhead passive sniffer optimized for background execution and sequential CSV state logging.
- **mac_hunter_live.py:** Multi-threaded TUI dashboard providing real-time RSSI (signal strength) tracking and asynchronous frame sub-type classification.
