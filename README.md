# 🔴 DeadNet - Network Security Testing & Defense Tool

> **DeadNet** is a Windows-based network security tool that combines **offensive testing (Attacker)** and **defensive monitoring (Defender)** in a single unified interface. Test network resilience with ARP Poisoning, IPv6 RA Spoofing, Dead Router attacks, while simultaneously detecting and countering these threats in real-time.
>
> This is an enhanced Windows fork of: https://github.com/flashnuke/deadnet

![DeadNet Screenshot](https://github.com/user-attachments/assets/aca06067-555f-4efa-a4bf-8a972f93bacb)

---

## 📋 What is DeadNet?

DeadNet is a Python application specifically designed for Windows 10/11. With a modern web interface built with Vite + TailwindCSS, DeadNet can be used by IT security professionals to:

### Attacker Module
- Temporarily disable network connectivity during testing (DoS Test)
- Test security system detection against ARP and NDP attacks
- Simulate network attacks with controlled intensity and attack parameters
- Test network awareness against IP/MAC spoofing

### Defender Module
- Real-time packet monitoring and threat detection
- Detect ARP spoofing, IPv6 RA spoofing, and Dead Router attacks
- Auto-flag suspicious IPs and MAC addresses
- Counter-attack capability (KICK) to disconnect attackers

> **WARNING: Use only on networks you own or have written permission for! Misuse of this tool is illegal!**

---

## 🚀 Installation

### 1. Prerequisites

- **Windows 10/11**
- **Python 3.8 or newer**
  - Download at [python.org](https://www.python.org/downloads/)
  - Make sure to check "Add Python to PATH" during installation
- **Node.js 18 or newer**
  - Download at [nodejs.org](https://nodejs.org/)
  
  (Optional, already tested without npcap it worked)
- **Npcap** (required for Scapy on Windows)
  - Download at [npcap.com](https://npcap.com/#download)
  - Install with "WinPcap API-compatible Mode" option
  - Restart PC after installation

### 2. DeadNet Installation

1. **Clone or download the repository**
```bash
git clone https://github.com/risunCode/Deadnet-Windows.git
cd Deadnet-Windows
```

2. **Run the launcher and install dependencies**
```bash
launcher.cmd
```
- Select option `[5] Install Dependencies`
- This will:
  - Create a Python virtual environment (`.venv`)
  - Install all Python packages locally (not globally)
  - Install Node.js dependencies
  - Build web assets

3. **Start DeadNet**
- Select option `[1]` WebView or `[3]` Browser mode
- Launcher automatically requests admin rights and opens the control panel

---

## 🎮 How to Use

### Starting DeadNet

**Option 1: Using Launcher (Recommended)**
- Double-click `launcher.cmd`
- Select mode: WebView (desktop window) or Browser
- Control panel opens automatically

**Option 2: Command Line**
```bash
python main.py [options]

Options:
  -b, --browser    Run in browser mode
  -w, --webview    Run in WebView mode (default on Windows)
  -p, --port PORT  Server port (default: 5000)
  --no-open        Don't auto-open browser
```

### Using the Attacker

1. **Select Network Interface**
   - Choose the network adapter you want to use for the attack

2. **Choose Attack Mode**
   - ARP Poisoning (IPv4)
   - IPv6 RA Spoofing
   - Dead Router Attack
   - (Can select one or more)

3. **Set Attack Intensity**
   - Slow (10s interval): stealthy, minimal detection
   - Medium (5s): default mode
   - Fast (2s): aggressive
   - Maximum (1s): full speed

4. **Advanced Options (Optional)**
   - Fake Local IP: automatic/self-generated IP spoofing
   - Target IPs: attack specific hosts only
   - CIDR Length: subnet configuration

5. **Start / Stop Attack**
   - Click **START** to begin, **STOP** to end
   - Monitor statistics: packet count, attack cycles, duration
   - Monitor activity logs in real-time

### Using the Defender

1. **Select Network Interface**
   - Choose the interface to monitor

2. **Start Monitoring**
   - Click **START MONITORING**
   - Real-time alerts appear as threats are detected

3. **View Flagged Threats**
   - Switch to "Flagged Threats" tab
   - See all suspicious IPs and MACs

4. **Counter-Attack (KICK)**
   - Click **KICK** on any flagged IP
   - Defender will attempt to disconnect the attacker

---

## 🎨 Themes

DeadNet includes 4 built-in themes:

| Theme | Description |
|-------|-------------|
| **Hacker** | Green terminal style (default) |
| **Maroon** | Red/dark theme |
| **Defender** | Blue security theme |
| **Pure Dark** | Minimal monochrome |

---

## 🔧 Technical Details

### Attack Mechanisms

- **ARP Poisoning**: Sends fake ARP to all hosts, replacing gateway MAC with random MAC.
- **IPv6 RA Spoofing**: Sends fake router advertisements (lifetime=0) so hosts consider the router dead.
- **Dead Router Attack**: Sniffs & responds to all RA from real router with fake RA, hosts cannot update router list.
- **Fake IP/MAC**: Attack packets can use fake IP/MAC to mislead network logs.

### Detection Algorithms

- **ARP Spoofing Detection**: Tracks IP-to-MAC mappings, detects changes
- **Broadcast Reply Detection**: Identifies ARP replies to broadcast (poisoning indicator)
- **Multi-IP MAC Detection**: Flags MACs claiming multiple IPs
- **Random MAC Detection**: Identifies attack tool signatures
- **IPv6 Dead Router Detection**: Detects router lifetime 0 attacks
- **RA Flood Detection**: Identifies excessive router advertisements

### Severity Levels

- 🔴 **CRITICAL** - Confirmed attacks (ARP spoofing, Dead Router)
- 🟠 **HIGH** - Highly suspicious activity
- 🟡 **MEDIUM** - Potentially suspicious
- 🔵 **LOW** - Minor anomalies

---

## 📦 Build Executable

To build a standalone `.exe` file:

1. Run `launcher.cmd`
2. Select option `[4] Build Executable (.exe)`
3. Wait for build to complete
4. Find `DeadNet.exe` in the `dist` folder

---

## 📁 Project Structure

```
Deadnet-Windows/
├── main.py              # Unified backend server
├── launcher.cmd         # Windows launcher (run/build/install)
├── launcher.sh          # Linux launcher
├── requirements.txt     # Python dependencies
├── package.json         # Node.js dependencies
├── backend/
│   ├── attacker.py      # Attack orchestrator
│   ├── detector.py      # Packet detection engine
│   ├── database.py      # Threat database
│   ├── network_utils.py # Network utilities
│   └── defines.py       # Constants
├── src/
│   ├── index.html       # Main HTML
│   ├── css/style.css    # Tailwind styles
│   └── js/main.js       # Frontend logic
└── dist/                # Built web assets & executable
```

---

## 🔌 API Endpoints

### Attacker API
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | Attack status |
| GET | `/api/logs` | Activity logs |
| GET | `/api/interfaces` | Network interfaces |
| POST | `/api/start` | Start attack |
| POST | `/api/stop` | Stop attack |

### Defender API
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/defender/status` | Monitor status |
| GET | `/api/defender/alerts` | Security alerts |
| GET | `/api/defender/flagged` | Flagged addresses |
| POST | `/api/defender/start` | Start monitoring |
| POST | `/api/defender/stop` | Stop monitoring |
| POST | `/api/defender/disconnect_ip` | Counter-attack (KICK) |

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

## 👏 Credits

- Original [DeadNet](https://github.com/flashnuke/deadnet) by [@flashnuke](https://github.com/flashnuke)
- Windows fork & enhancements by [@risunCode](https://github.com/risunCode)

---

**By using DeadNet, you agree to act ethically, legally, and professionally.**
