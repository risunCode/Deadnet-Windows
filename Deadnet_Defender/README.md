# Deadnet Defender 🛡️

**Network Security Monitoring Tool**

Deadnet Defender is a defensive security tool that monitors network traffic in real-time to detect and flag suspicious network activity, including:

- **ARP Poisoning Detection** - Identifies ARP spoofing attacks and cache poisoning attempts
- **IPv6 RA Spoofing Detection** - Detects malicious IPv6 Router Advertisements
- **Dead Router Attack Detection** - Identifies attempts to disable legitimate routers
- **MAC Address Anomaly Detection** - Flags suspicious MAC address patterns
- **Real-time Threat Intelligence** - Automatically flags suspicious IPs and MAC addresses

## Features 🚀

### Real-time Monitoring
- Live packet capture and analysis
- Instant detection of suspicious activity
- Real-time statistics and metrics
- Web-based monitoring dashboard

### Advanced Detection Engine
- **ARP Spoofing Detection** - Detects when IP addresses change MAC addresses
- **Broadcast Reply Detection** - Identifies ARP replies sent to broadcast addresses
- **Multi-IP MAC Detection** - Flags MACs claiming multiple IP addresses
- **ARP Flood Detection** - Detects excessive gratuitous ARP packets
- **Random MAC Detection** - Identifies randomly generated MAC addresses
- **IPv6 Dead Router Detection** - Detects router lifetime 0 attacks
- **IPv6 RA Spoofing** - Identifies spoofed router advertisements
- **IPv6 RA Flood Detection** - Detects excessive RA packets

### Threat Intelligence
- Automatic flagging of suspicious IPs and MAC addresses
- Incident tracking and history
- Persistent database of flagged addresses
- Severity classification (Critical, High, Medium, Low)

### Web Dashboard
- Beautiful, modern UI with TailwindCSS
- Real-time updates (1-second refresh)
- Live security alerts feed
- Flagged addresses management
- Statistics and metrics visualization

## Requirements 📋

- **Windows 10/11** (Administrator privileges required)
- **Python 3.8+**
- **Npcap** (WinPcap alternative for Windows)
  - Download from: https://npcap.com/

## Installation 🔧

1. **Install Npcap** (Required for packet capture on Windows)
   ```
   Download and install from https://npcap.com/
   Make sure to install with "WinPcap API-compatible Mode" enabled
   ```

2. **Clone or download this tool**
   ```
   Already in: Deadnet Defender/
   ```

3. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

## Usage 🎯

### Starting the Defender

**Option 1: Using Launcher (Recommended)**
1. Double-click `launcher.cmd` (auto-runs as Administrator)
2. Web dashboard opens automatically at `http://localhost:5001`

**Option 2: Manual Start**
1. Run as Administrator:
   ```bash
   python main.py
   ```
2. Open browser and navigate to: `http://localhost:5001`

**Using the Dashboard**
1. Select your network interface from the dropdown
2. Click "START" button
3. Monitor real-time alerts and statistics
4. View flagged threats in the "Flagged Threats" tab
5. Use KICK button to counter-attack detected threats

### Web Dashboard

The web dashboard provides:

- **Control Panel** - Start/stop monitoring, select network interface
- **Live Statistics** - Real-time packet counts, flagged addresses, uptime
- **Security Alerts** - Live feed of detected threats with severity levels
- **Flagged Addresses** - View and manage flagged IPs and MAC addresses
  - View incident history
  - **KICK (Force Disconnect)** - Counter-attack to forcefully disconnect attackers from network
  - Unflag false positives
  - Clear all flags

### Detection Severity Levels

- **🔴 CRITICAL** - Confirmed attacks (ARP spoofing, Dead Router, RA spoofing)
- **🟠 HIGH** - Highly suspicious activity (Multi-IP MACs, Random MAC patterns)
- **🟡 MEDIUM** - Potentially suspicious (ARP floods, Invalid MACs)
- **🔵 LOW** - Minor anomalies

## How It Works 🔍

### Detection Process

1. **Packet Capture** - Captures all network traffic on the selected interface
2. **Packet Analysis** - Each packet is analyzed by the detection engine
3. **Threat Detection** - Multiple detection algorithms identify suspicious patterns
4. **Alert Generation** - Suspicious activity generates alerts with severity levels
5. **Auto-Flagging** - IPs and MACs involved in attacks are automatically flagged
6. **Database Storage** - All alerts and flags are stored persistently

### Counter-Attack Process (KICK Feature)

When you click **KICK** on a flagged IP, Defender launches a multi-vector counter-attack:

1. **ARP Poisoning Counter** - Sends fake ARP replies with random MAC addresses
   - Poisons target's ARP cache (fake gateway MAC)
   - Poisons gateway's ARP cache (fake target MAC)
   - Breaks bidirectional communication

2. **Gratuitous ARP Confusion** - Broadcasts conflicting ARP announcements
   - Multiple random MACs claiming the target IP
   - Confuses all network devices
   - Prevents reconnection

3. **ICMP Disruption** - Sends ICMP Destination Unreachable packets
   - Breaks existing TCP connections
   - Prevents new connections

**Result**: Target is forcefully disconnected from network and cannot reconnect until ARP caches are cleared!

### Detection Algorithms

#### ARP Monitoring
- Tracks legitimate ARP mappings (IP ↔ MAC)
- Detects when IPs change MAC addresses (spoofing)
- Identifies broadcast ARP replies (common in poisoning)
- Monitors for excessive gratuitous ARP packets
- Flags MACs claiming multiple IPs

#### IPv6 Monitoring
- Tracks legitimate IPv6 routers
- Detects router lifetime 0 packets (Dead Router)
- Identifies RA spoofing (routers changing MACs)
- Monitors for RA floods
- Validates prefix information

#### MAC Analysis
- Identifies invalid MAC addresses
- Detects randomly generated MACs (attack tool signatures)
- Tracks MAC-to-IP relationships
- Monitors for MAC address anomalies

## Database 💾

Deadnet Defender maintains a persistent JSON database (`defender_data.json`) containing:

- **Flagged IPs** - Suspicious IP addresses with incident history
- **Flagged MACs** - Suspicious MAC addresses with incident history
- **Alerts** - Historical record of all security alerts
- **Statistics** - Cumulative monitoring statistics

## API Endpoints 🔌

The tool provides a REST API for integration:

- `GET /api/status` - Get current monitoring status
- `GET /api/alerts` - Get recent security alerts
- `GET /api/flagged` - Get flagged IPs and MACs
- `GET /api/interfaces` - Get available network interfaces
- `POST /api/start` - Start monitoring
- `POST /api/stop` - Stop monitoring
- `POST /api/unflag` - Remove flag from address
- `POST /api/clear_flags` - Clear all flags
- `POST /api/disconnect_ip` - **⚡ Force disconnect attacker via counter-attack**

## Use Cases 🎓

### Network Security Monitoring
- Deploy on critical network segments
- Monitor for ARP poisoning attacks
- Detect rogue DHCP servers
- Identify IPv6 attacks

### Penetration Testing
- Detect your own attack tools (quality assurance)
- Test IDS/IPS systems
- Validate defensive measures
- Security awareness training

### Research & Education
- Study network attack patterns
- Analyze attack signatures
- Learn defensive techniques
- Network forensics

## Important Notes ⚠️

- **Administrator privileges are REQUIRED** for packet capture and counter-attacks
- **Npcap must be installed** on Windows systems
- The tool can actively counter-attack detected threats (KICK feature)
- **KICK feature launches aggressive counter-attacks** to disconnect attackers
- False positives may occur in certain network configurations
- Review flagged addresses before taking action
- **Use KICK responsibly** - it performs active network attacks

## Security Considerations 🔐

- This tool is for **defensive purposes only**
- Use only on networks you own or have permission to monitor
- Respect privacy and legal requirements
- Do not use for unauthorized network monitoring
- Keep the database file secure (contains network intelligence)

## Troubleshooting 🔧

### "Permission Denied" errors
- Ensure you're running as Administrator
- Check Npcap installation

### "No interfaces found"
- Verify Npcap is installed correctly
- Check Windows Firewall settings
- Ensure network adapters are enabled

### Web dashboard not accessible
- Check if port 5001 is available
- Verify firewall allows connections to port 5001
- Try accessing via 127.0.0.1:5001

## Technical Details 💻

- **Backend**: Python 3, Flask, Scapy
- **Frontend**: HTML5, TailwindCSS, JavaScript
- **Detection Engine**: Custom packet analysis algorithms
- **Database**: JSON-based persistent storage
- **Architecture**: Web-based real-time monitoring

## Credits 👏

**Based on**: [DeadNet](https://github.com/flashnuke/deadnet) by @flashnuke  
**Web Interface**: [@risuncode](https://github.com/risuncode)

Part of the **Deadnet Project** - Network Security Testing & Defense

## License 📄

Educational and authorized security testing purposes only.

---

**Protect your network. Monitor in real-time. Stay secure.** 🛡️
