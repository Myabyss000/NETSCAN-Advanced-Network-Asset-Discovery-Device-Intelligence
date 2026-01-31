"""
Enhanced Passive Network Sniffer
================================
Captures and analyzes broadcast/multicast traffic to identify devices.
Now includes VPN detection, LLMNR, and improved detection.
"""

import scapy.all as scapy
from analyzers.arp_analyzer import ARPAnalyzer
from analyzers.dhcp_analyzer import DHCPAnalyzer
from analyzers.mdns_analyzer import MDNSAnalyzer
from analyzers.ssdp_analyzer import SSDPAnalyzer
from analyzers.netbios_analyzer import NetBIOSAnalyzer
from analyzers.vpn_analyzer import VPNDetectionAnalyzer
import threading
import time


class PassiveSniffer:
    def __init__(self, device_manager, interface=None, enable_vpn_detection=True):
        self.device_manager = device_manager
        self.interface = interface
        self.enable_vpn_detection = enable_vpn_detection
        
        # Core analyzers
        self.analyzers = [
            ARPAnalyzer(device_manager),
            DHCPAnalyzer(device_manager),
            MDNSAnalyzer(device_manager),
            SSDPAnalyzer(device_manager),
            NetBIOSAnalyzer(device_manager),
        ]
        
        # VPN analyzer (optional but enabled by default)
        self.vpn_analyzer = None
        if enable_vpn_detection:
            self.vpn_analyzer = VPNDetectionAnalyzer(device_manager)
            self.analyzers.append(self.vpn_analyzer)
        
        self.sniffer_thread = None
        self.stop_sniffer = threading.Event()
        self.packet_count = 0
        self.last_packet_time = 0

    def packet_callback(self, packet):
        try:
            self.packet_count += 1
            self.last_packet_time = time.time()
            
            for analyzer in self.analyzers:
                try:
                    analyzer.process_packet(packet)
                except:
                    pass
                    
            # Also extract basic info from any IP packet
            self._extract_basic_info(packet)
            
        except Exception as e:
            pass

    def _extract_basic_info(self, packet):
        """Extract basic device info from any packet."""
        try:
            # Get MAC and IP from any packet with Ether and IP layers
            if packet.haslayer(scapy.Ether) and packet.haslayer(scapy.IP):
                src_mac = packet[scapy.Ether].src.lower()
                src_ip = packet[scapy.IP].src
                
                # Skip broadcast/multicast
                if src_mac.startswith("ff:") or src_mac.startswith("01:"):
                    return
                if src_ip.startswith("224.") or src_ip == "255.255.255.255":
                    return
                
                # Update device if we have a valid MAC
                if src_mac and len(src_mac) == 17:
                    self.device_manager.update_device(src_mac, ip=src_ip)
                    
        except:
            pass

    def start(self):
        """Start passive sniffing with comprehensive filter."""
        # Comprehensive BPF filter for maximum device detection:
        # - ARP: Device announcements
        # - DHCP (67, 68): IP assignments and device hostnames
        # - mDNS (5353): Service discovery (Apple, Chromecast, printers)
        # - SSDP (1900): UPnP discovery (smart TVs, media devices)
        # - NetBIOS (137, 138): Windows names and workgroups
        # - LLMNR (5355): Local link multicast name resolution
        # - DNS (53): Can reveal hostnames
        # - VPN Ports: OpenVPN (1194), WireGuard (51820), IKEv2 (500, 4500)
        
        if self.enable_vpn_detection:
            # VPN ports: OpenVPN(1194), WireGuard(51820), IKEv2-NAT(4500), L2TP(1701), PPTP(1723)
            # Removed: 443 (HTTPS causes false positives), 500 (common IPsec)
            bpf_filter = (
                "arp or "
                "(udp and (port 67 or port 68 or port 5353 or port 1900 or "
                "port 137 or port 138 or port 5355 or port 53 or "
                "port 1194 or port 51820 or port 4500 or port 1701)) or "
                "(tcp and (port 80 or port 8080 or port 1194 or port 1723))"
            )
        else:
            bpf_filter = (
                "arp or "
                "(udp and (port 67 or port 68 or port 5353 or port 1900 or "
                "port 137 or port 138 or port 5355 or port 53)) or "
                "(tcp and (port 80 or port 8080))"
            )
        
        self.sniffer = scapy.AsyncSniffer(
            iface=self.interface,
            prn=self.packet_callback,
            filter=bpf_filter,
            store=0
        )
        self.sniffer.start()
    
    def get_vpn_devices(self):
        """Get list of devices detected using VPNs."""
        if self.vpn_analyzer:
            return self.vpn_analyzer.get_vpn_devices()
        return []

    def stop(self):
        if self.sniffer:
            self.sniffer.stop()
    
    def get_stats(self):
        """Return sniffing statistics."""
        return {
            "packets": self.packet_count,
            "last_packet": self.last_packet_time
        }
