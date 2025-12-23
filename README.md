# 🔥 Personal Firewall Using Python

## 📌 Project Overview
This project demonstrates the implementation of a lightweight **personal firewall** using **Python and Scapy**.  
It focuses on monitoring live network traffic, applying rule-based filtering, and logging suspicious activity, similar to basic **SOC (Security Operations Center)** firewall monitoring.

This project is designed for **beginners and cybersecurity freshers** to understand how firewalls and packet inspection work at a fundamental level.

---

## 🎯 Objectives
- Monitor real-time network traffic
- Filter packets based on IP addresses and ports
- Log suspicious traffic for security analysis
- Gain hands-on exposure to network security concepts

---

## 🛠️ Tools & Technologies
- **Python 3**
- **Scapy** (packet sniffing)
- **Linux (Ubuntu)** – lab environment
- **iptables** (conceptual understanding)

---

## ⚙️ Features
- Real-time packet capture
- Rule-based IP blocking
- Port-based traffic filtering
- Security event logging
- Beginner-friendly and modular code structure

---


---

## ▶️ How It Works
1. The firewall listens to network packets using Scapy.
2. Each packet is analyzed for source IP, destination IP, and port.
3. Predefined rules are applied to identify blocked IPs and ports.
4. Suspicious traffic is logged for auditing and investigation.
5. Allowed traffic is displayed in real time.

---

## ▶️ How to Run
```bash
sudo python3 firewall.py

