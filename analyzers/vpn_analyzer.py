"""
VPN Usage Detection Analyzer
=============================
Detects when devices on the local network are using VPN connections.
Works by analyzing outgoing traffic for VPN protocol signatures and ports.
IMPORTANT: Only high-confidence VPN ports are tracked to avoid false positives.
"""

import scapy.all as scapy
from analyzers.base import BaseAnalyzer
import time


# Known VPN ports - ONLY high-confidence ones to avoid false positives
# Removed: 443 (HTTPS), 500 (common IPsec), 8443 (common HTTPS alt)
VPN_SIGNATURES = {
    # OpenVPN - very specific port
    1194: {"name": "OpenVPN", "protocol": "udp/tcp", "confidence": "high"},
    
    # WireGuard - very specific port
    51820: {"name": "WireGuard", "protocol": "udp", "confidence": "high"},
    
    # IKEv2/IPsec NAT-T (4500 is more reliable than 500)
    4500: {"name": "IKEv2-NAT", "protocol": "udp", "confidence": "high"},
    
    # L2TP - usually combined with IPsec
    1701: {"name": "L2TP", "protocol": "udp", "confidence": "medium"},
    
    # PPTP (legacy but specific)
    1723: {"name": "PPTP", "protocol": "tcp", "confidence": "high"},
    
    # SoftEther VPN
    5555: {"name": "SoftEther", "protocol": "tcp", "confidence": "medium"},
    
    # Shadowsocks (common proxy/VPN)
    8388: {"name": "Shadowsocks", "protocol": "tcp", "confidence": "medium"},
}

# Track VPN traffic per device
vpn_traffic_tracker = {}


class VPNDetectionAnalyzer(BaseAnalyzer):
    """Analyzer that detects VPN usage on the network."""
    
    def __init__(self, device_manager):
        super().__init__(device_manager)
        self.vpn_detections = {}  # MAC -> {port, protocol, count, first_seen, last_seen}
        self.detection_threshold = 10  # Need 10+ packets to confirm (was 3 - too low)
        self.flagged_devices = set()  # Only flag once per session
    
    def process_packet(self, packet):
        """Process packet to detect VPN traffic."""
        
        # Need Ethernet, IP, and transport layer
        if not packet.haslayer(scapy.Ether):
            return
        if not packet.haslayer(scapy.IP):
            return
            
        src_mac = packet[scapy.Ether].src.lower()
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        
        # Check UDP traffic
        if packet.haslayer(scapy.UDP):
            sport = packet[scapy.UDP].sport
            dport = packet[scapy.UDP].dport
            self._check_vpn_port(src_mac, src_ip, dport, "UDP")
            self._check_vpn_port(src_mac, src_ip, sport, "UDP")
        
        # Check TCP traffic
        elif packet.haslayer(scapy.TCP):
            sport = packet[scapy.TCP].sport
            dport = packet[scapy.TCP].dport
            self._check_vpn_port(src_mac, src_ip, dport, "TCP")
            self._check_vpn_port(src_mac, src_ip, sport, "TCP")
    
    def _check_vpn_port(self, mac, ip, port, protocol):
        """Check if port matches known VPN signatures."""
        
        if port not in VPN_SIGNATURES:
            return
        
        vpn_info = VPN_SIGNATURES[port]
        now = time.time()
        
        # Initialize tracking for this MAC
        if mac not in self.vpn_detections:
            self.vpn_detections[mac] = {}
        
        # Track this VPN protocol detection
        key = f"{port}_{vpn_info['name']}"
        if key not in self.vpn_detections[mac]:
            self.vpn_detections[mac][key] = {
                "port": port,
                "name": vpn_info["name"],
                "protocol": protocol,
                "confidence": vpn_info["confidence"],
                "count": 0,
                "first_seen": now,
                "last_seen": now
            }
        
        detection = self.vpn_detections[mac][key]
        detection["count"] += 1
        detection["last_seen"] = now
        
        # Only flag as VPN after threshold reached (avoid false positives)
        # Also only flag once per MAC+VPN combination
        flag_key = f"{mac}_{port}"
        if detection["count"] >= self.detection_threshold and flag_key not in self.flagged_devices:
            self.flagged_devices.add(flag_key)  # Mark as flagged
            
            vpn_tag = f"🔒VPN:{vpn_info['name']}"
            self.device_manager.update_device(mac, ip=ip, service=vpn_tag)
    
    def get_vpn_devices(self):
        """Get list of devices detected using VPNs."""
        vpn_devices = []
        
        for mac, detections in self.vpn_detections.items():
            for key, info in detections.items():
                if info["count"] >= self.detection_threshold:
                    vpn_devices.append({
                        "mac": mac,
                        "vpn_name": info["name"],
                        "port": info["port"],
                        "confidence": info["confidence"],
                        "packet_count": info["count"],
                        "first_seen": info["first_seen"],
                        "last_seen": info["last_seen"]
                    })
        
        return vpn_devices


def detect_vpn_ports_active(ip, timeout=1):
    """
    Actively scan a device for open VPN ports.
    Returns list of detected VPN ports.
    """
    import socket
    
    detected = []
    
    for port, info in VPN_SIGNATURES.items():
        # Skip low confidence ports for active scan (too many false positives)
        if info["confidence"] == "low":
            continue
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                detected.append({
                    "port": port,
                    "name": info["name"],
                    "confidence": info["confidence"]
                })
        except:
            pass
    
    return detected
