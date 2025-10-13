# 🔴 DeadNet - Network Security Testing Tool

> **DeadNet Attacker** is a Windows-based network security testing tool designed to make wireless or wired networks unresponsive during authorized penetration testing. This tool utilizes various network attack techniques, such as ARP Poisoning (IPv4), IPv6 Router Advertisement Spoofing, Dead Router Attack, and source IP spoofing to test network resilience and response to real attacks.
>
> This is a Windows fork version of the repository: https://github.com/flashnuke/deadnet

---

## 📋 What is DeadNet Attacker?

DeadNet Attacker is a Python application specifically designed for Windows 10/11. With a modern web interface and full control through a browser, DeadNet can be used by IT security professionals to:
- Temporarily disable network connectivity during testing (DoS Test)
- Test security system detection against ARP and NDP attacks
- Simulate network attacks with controlled intensity and attack parameters
- Test network awareness against IP/MAC spoofing

> **WARNING: Use only on networks you own or have written permission for! Misuse of this tool is illegal!**

---

## 🚀 Installation

### 1. Prerequisites

- **Windows 10/11**
- **Python 3.8 or newer**
  - Download at [python.org](https://www.python.org/downloads/)
  - Make sure to check "Add Python to PATH" during installation
- **Npcap** (required for Scapy on Windows)
  - Download at [npcap.com](https://npcap.com/#download)
  - Install with "WinPcap API-compatible Mode" option
  - Restart PC after installation

### 2. DeadNet Installation

1. **Clone or download the repository**
   ```bash
   cd Deadnet_Attacker
   ```
2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```
3. **Run the launcher**
   ```bash
   launcher.cmd
   ```
   - Launcher automatically: requests admin rights, checks Npcap, and opens the web control panel at `http://localhost:5000`

---

## 🎮 How to Use

1. **Open browser to `http://localhost:5000`**
   - The DeadNet Control Panel will appear

2. **Select Network Interface**
   - Choose the network adapter you want to use for the attack

3. **Choose Attack Mode**
   - ARP Poisoning (IPv4)
   - IPv6 RA Spoofing
   - Dead Router Attack
   - (Can select one or more)

4. **Set Attack Intensity**
   - Slow (10s interval): stealthy, minimal detection
   - Medium (5s): default mode
   - Fast (2s): aggressive
   - Maximum (1s): full speed
   - Custom: interval as needed (0.5-60s)

5. **Advanced Options (Optional)**
   - Fake Local IP: automatic/self-generated IP spoofing
   - Fake MAC Address: automatic/self-generated MAC spoofing

6. **Start / Stop Attack**
   - Click **START** to begin, **STOP** to end
   - Monitor statistics: packet count, attack cycles, duration
   - Monitor activity logs in real-time

---

## 🔧 Brief Technical Explanation

- **ARP Poisoning**: Sends fake ARP to all hosts, replacing gateway MAC with random MAC.
- **IPv6 RA Spoofing**: Sends fake router advertisements (lifetime=0) so hosts consider the router dead.
- **Dead Router Attack**: Sniffs & responds to all RA from real router with fake RA, hosts cannot update router list.
- **Fake IP/MAC**: Attack packets can use fake IP/MAC to mislead network logs.

The entire process runs multi-threaded, efficiently, and supports real-time monitoring via the web panel.

---

## ⚠️ Legal & Ethics

- **Only for LEGITIMATE testing and with PERMISSION**
- **Do not use to damage/attack networks without permission**
- Full responsibility lies with the user

---

## 📚 Reference Sources

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [ARP Spoofing Explained](https://www.imperva.com/learn/application-security/arp-spoofing/)
- [IPv6 Security Guide](https://www.cisco.com/c/en/us/products/security/ipv6-security.html)

---

**By using DeadNet Attacker, you agree to act ethically, legally, and professionally.**

---
