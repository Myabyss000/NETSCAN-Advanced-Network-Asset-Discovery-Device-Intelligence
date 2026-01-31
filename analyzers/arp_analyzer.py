import scapy.all as scapy
from .base import BaseAnalyzer

class ARPAnalyzer(BaseAnalyzer):
    def process_packet(self, packet):
        if scapy.ARP in packet:
            # Opcode 1 is Request, 2 is Reply. Both contain sender info.
            # We are interested in the source of the packet.
            
            # ARP packet structure:
            # hwsrc: sender MAC
            # psrc: sender IP
            src_mac = packet[scapy.ARP].hwsrc
            src_ip = packet[scapy.ARP].psrc
            
            if src_mac and src_ip:
                self.device_manager.update_device(src_mac, ip=src_ip)
