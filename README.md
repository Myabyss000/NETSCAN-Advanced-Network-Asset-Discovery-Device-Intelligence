# 📡 NETSCAN — Advanced Network Asset Discovery & Device Intelligence

> *"It's always DNS. Except when it's BGP. Or an unmanaged switch under someone's desk."*

**NETSCAN** is a professional-grade execution environment for network reconnaissance, asset classification, and security auditing. It combines passive packet analysis with active probing techniques to construct a high-fidelity map of local network topology.

Designed for security professionals, sysadmins, and that one guy who *really* needs to know why his ping is 400ms (spoiler: it's the 4K stream).

---

## ⚠️ DISCLOSURE & WARNING

**This tool is not a toy.** It utilizes active scanning techniques (ARP sweeps, TCP connect scanning, service fingerprinting) that can trigger IDS/IPS alerts and may be prohibited on corporate or public networks.

> **Use strictly on networks you own or have explicit authorization to audit.** The author assumes no liability for your sudden career change to "Freelance Defendant".

---

## 🛠️ Technical Architecture

NETSCAN operates on a modular architecture leveraging `Scapy` for raw socket manipulation:

-   **Passive Sniffer**: Promiscuous mode capture using BPF filters to analyze broadcast/multicast traffic (mDNS, SSDP, DHCP, NetBIOS).
-   **Active Scanner**: Multi-threaded ARP sweeps and targeted TCP port scanning for service discovery.
-   **Heuristic Classifier**: A weighted scoring engine that correlates 6+ signals (OUI, open ports, OS fingerprint, hostname patterns) to identify device types with confidence intervals.
-   **VPN Heuristics**: Traffic analysis engine detecting encrypted tunnel signatures (OpenVPN, WireGuard, IKEv2) based on flow patterns and ports.

---

## 📋 Features

| Feature | Description |
| :--- | :--- |
| **Hybrid Discovery** | Combines noisy active scanning with stealthy passive listening for maximum visibility. |
| **OS Fingerprinting** | Infers OS from TCP window sizes, TTLs, and service banners. |
| **Protocol Analysis** | Parses mDNS (Bonjour), SSDP (UPnP), NetBIOS, and LLMNR for granular hostname resolution. |
| **Privacy Audit** | Specifically hunts for surveillance devices (RTSP streams, ONVIF) with a high-confidence alerting system. |
| **Deduplication** | Intelligent IP-based tracking handles multi-interface devices and DHCP churn. |

---

## 🚀 Installation & Deployment

### Prerequisites
-   **Windows 10/11** (Linux support is theoretical but unproven; mileage may vary).
-   **Python 3.8+**
-   **Npcap** (Required for Windows packet capture). [Download here](https://nmap.org/npcap/).
    -   *Critical:* Install with **"WinPcap API-compatible Mode"** enabled, or enjoy the silence.

### Setup

```powershell
# 1. Clone the repository
git clone https://github.com/yourusername/netscan.git
cd netscan

# 2. Initialize environment (recommended to avoid polluting your global site-packages)
python -m venv venv
.\venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 💻 Operation Modes

Execute via: `python main.py`

### 1. 🔇 Passive Mode (Stealth)
**Methodology:** Pure packet capture. Zero active packet injection.
**Use Case:** High-security environments where active scanning triggers SIEM alerts.
**Limit:** Cannot detect quiet devices (e.g., IoT standby). Patience required.

### 2. 📡 Active Mode (Discovery)
**Methodology:** ARP broadcast sweep + SYN/Connect scan.
**Use Case:** Rapid topology mapping.
**Note:** Noisy. Will definitely annoy specific firewall configurations.

### 3. ⚡ Hybrid Mode (Recommended)
**Methodology:** Active scan for baseline → Passive listen for enrichment.
**Why:** Best of both worlds. Resolves hostnames via NetBIOS/mDNS often missed by active scanning alone.

### 4. 🌐 Multi-Network Mode
**Methodology:** Enumerates all local interfaces (WiFi, Ethernet, VPN adapters) and performs active scanning coverage on all detectable subnets simultaneously.
**Use Case:** When you are the bridge between the Corporate LAN and the Guest WiFi (we won't tell).

### 5. 🔒 VPN Watch
**Methodology:** Passive heuristic analysis of transport layer headers.
**Target:** Identifies devices tunneling traffic via OpenVPN (1194), WireGuard (51820), or IPsec (4500).
**False Positive Mitigation:** Strict packet thresholding and exclusion of common HTTPS (443) traffic.

---

## 📊 Classification Engine

Devices are classified based on a weighted confidence score (0-100%):

-   **Definitive Signals (40pts):** Hostnames like `LAPTOP-`, `iPhone`.
-   **Primary Ports (30pts):** Port 554 (RTSP) for Cameras.
-   **OUI Match (25pts):** MAC address vendor lookup.
-   **Behavioral (15pts):** `.1` Gateway IP, Random MAC randomization.

*If it looks like a duck, quacks like a duck, but communicates on port 554 active RTSP... it's a security camera.*

---

## 🔧 Troubleshooting

**"No interfaces found"**
-   Did you install Npcap? Did you install it *correctly*?
-   Are you running as **Administrator**? Raw sockets require privilege.

**"Laptop detected as Router"**
-   This usually means `NetBIOS` resolution failed and the classifier fell back to heuristics. Ensure firewall isn't blocking UDP 137.

**"It crashed."**
-   Detailed stack trace or it didn't happen.

---

## 🚫 Limitations

Before you start debugging your router's firmware:
*   **Offline Devices**: Passive mode obviously cannot detect devices that are powered off or radio-silent (e.g., IoT devices in deep sleep).
*   **Network Isolation**: Cannot see devices on other VLANs or Wi-Fi networks unless your adapter is specifically bridged or you are in Multi-Net mode with physical access.
*   **Probabilistic Results**: Classification is a best-effort heuristic, not a mathematical proof. A toaster running Linux might look like a server.
*   **Physical Verification**: Digital signals can be spoofed. Always combine scan results with actual physical inspection if you suspect a rogue device.

---

## 📝 License

MIT License. Modify, distribute, break things. Just don't blame me when your NetSec team knocks on your door.

---
*Built by Arghya Adhikary. Coffee-powered.*
