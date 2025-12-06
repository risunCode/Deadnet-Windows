# 🔴 DeadNet - Network Security Testing & Defense Tool

> **Make a wireless network unresponsive**
>
> Tested on Kali Nethunter | Works for both IPv6 and IPv4

**DeadNet** is a cross-platform network security tool that combines **offensive testing (Attacker)** and **defensive monitoring (Defender)** in a single unified interface. Test network resilience with ARP Poisoning, IPv6 RA Spoofing, Dead Router attacks, while simultaneously detecting and countering these threats in real-time.

> This is an enhanced fork of: https://github.com/flashnuke/deadnet

## 📸 Screenshots

| Attacker | Defender | About |
|:--------:|:--------:|:-----:|
| ![attacker](https://github.com/user-attachments/assets/c4af7053-99a0-4bcf-9850-ef10a8cbdf52) | ![defender](https://github.com/user-attachments/assets/a11019ed-2bf8-4b3a-ad92-ccf67fe298e7) | ![about](https://github.com/user-attachments/assets/af839672-fe69-4a43-bd8a-82c061396233) |

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

> **WARNING: Use only on networks you own or have written permission for! Misuse of this tool is illegal!**

---

## 🔬 How it Works

### IPv6

In IPv6, the ARP mechanism was ditched due to several reasons, one of them being lack of security. Instead there is **Neighbor/Router Discovery Protocol**, which will be exploited in this attack.

**Dead Router Attack** - This attack periodically sends a spoofed RA (router discovery) packet with the gateway's link-local address to the multicast address on the local link, which signals that the router is dead. This would prevent the hosts from forwarding traffic to the gateway. Furthermore, a scapy method is running on a separate thread in the background, sniffing traffic. It immediately invalidates all incoming RA packets from routers by sending spoofed ones that indicate the router is not operational (`routerlifetime=0`).

### IPv4

**ARP Attack** - Continuously sends spoofed ARP packets (using scapy) to every host on the network, poisoning its ARP table. The gateway is mapped to an incorrect MAC address and therefore the traffic never reaches its true destination, making the network unresponsive. Furthermore, the gateway also receives an ARP packet from each host that contains a spoofed MAC address.

### WiFi Deauth (Alternative)

There's another way to perform a DoS attack on wireless networks **WITHOUT HAVING CREDENTIALS**, and that is by sending de-auth packets. This requires a network adapter that supports packet injection. If no credentials are present and you insist on using DeadNet, it's possible to run a dictionary-attack using a wordlist in combination with another tool that cracks WiFi handshakes to gain credentials first.

---

## 📦 Requirements

### Operating System

Works on **Windows, Linux, Mac, and Android (Termux with root)**. 

| Platform | Support | Notes |
|----------|---------|-------|
| Windows 10/11 | ✅ Full | WebView + Browser mode |
| Linux | ✅ Full | Browser mode (WebView optional) |
| Mac | ✅ Full | Browser mode |
| Android (Termux) | ✅ Full | Requires root, Browser mode only |

### Virtual Machine

⚠️ If running from a VM, the network adapter **must be set to Bridged mode** for the attacks to work properly.

### Dependencies

Install 3rd party libraries by running:

```bash
pip install -r requirements.txt
```

Required packages:
- `scapy` - Packet manipulation
- `netifaces` - Network interface info
- `flask` - Web server
- `flask-cors` - CORS support
- `pywebview` - Desktop window (optional)

---
 
## 🚀 Installation

### Windows / Linux / Mac

```bash
# Clone repository
git clone https://github.com/risunCode/Deadnet-Windows.git
cd Deadnet-Windows

# Run launcher
# Windows:
launcher.cmd

# Linux/Mac:
chmod +x launcher.sh && sudo ./launcher.sh
```

### Android (Termux)

**Requirements:** [Termux](https://f-droid.org/packages/com.termux/) from F-Droid + Rooted device (Magisk/KernelSU)

**One-Line Install:**
```bash
pkg update && pkg install -y python git wget clang libffi openssl && wget -qO- https://raw.githubusercontent.com/risunCode/Deadnet-Windows/main/install-android.sh | bash
```

**Run DeadNet:**
```bash
cd ~/deadnet && su -c "$(which python) main.py --browser"
```
Then open browser: `http://127.0.0.1:5000`

<details>
<summary><b>📋 Manual Installation (click to expand)</b></summary>

**Step 1: Install dependencies**
```bash
pkg update && pkg install -y python git wget clang libffi openssl
```

**Step 2: Install Python packages**
```bash
pip install scapy netifaces flask flask-cors
```

**Step 3: Clone repository**
```bash
git clone https://github.com/risunCode/Deadnet-Windows.git ~/deadnet
```

**Step 4: Run**
```bash
cd ~/deadnet && su -c "$(which python) main.py --browser"
```

</details>

<details>
<summary><b>🗑️ Uninstall (click to expand)</b></summary>

```bash
rm -rf ~/deadnet && sed -i '/alias deadnet/d' ~/.bashrc
```

</details>

---

## 🚀 Usage

### Starting DeadNet

**Option 1: Using Launcher (Recommended)**
```bash
# Windows
launcher.cmd

# Linux/Mac
sudo ./launcher.sh

# Android (Termux)
deadnet
```

**Option 2: Command Line**
```bash
python main.py [options]

Options:
  -b, --browser    Run in browser mode
  -w, --webview    Run in WebView mode (default on Windows)
  -p, --port PORT  Server port (default: 5000)
  --no-open        Don't auto-open browser
```

---

## 🔌 API Endpoints

### Attacker API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | Get attack status & statistics |
| GET | `/api/logs` | Get activity logs |
| GET | `/api/interfaces` | List network interfaces |
| POST | `/api/start` | Start attack |
| POST | `/api/stop` | Stop attack |

### Defender API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/defender/status` | Get monitor status |
| GET | `/api/defender/alerts` | Get security alerts |
| GET | `/api/defender/flagged` | Get flagged IPs/MACs |
| POST | `/api/defender/start` | Start monitoring |
| POST | `/api/defender/stop` | Stop monitoring |
| POST | `/api/defender/unflag` | Remove flagged address |
| POST | `/api/defender/clear_flags` | Clear all flags |

### System API

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/shutdown` | Panic exit - stop all & shutdown |
| POST | `/api/minimize` | Minimize window |

--- 

## 🎨 Themes

| Theme | Description |
|-------|-------------|
| **Hacker** | Green terminal style (default) |
| **Maroon** | Red/dark theme |
| **Defender** | Blue security theme |
| **Pure Dark** | Minimal monochrome |

---

## ⚠️ Disclaimer

**This tool is only for testing and can only be used where strict consent has been given. Do not use it for illegal purposes!**

It is the end user's responsibility to obey all applicable local, state and federal laws. I assume no liability and am not responsible for any misuse or damage caused by this tool and software.

---

## 📜 License

Distributed under the **GNU General Public License v3.0**.

---

## 👏 Credits

- Original [DeadNet](https://github.com/flashnuke/deadnet) by [@flashnuke](https://github.com/flashnuke)
- Enhanced fork by [@risunCode](https://github.com/risunCode)

---

**By using DeadNet, you agree to act ethically, legally, and professionally.**
