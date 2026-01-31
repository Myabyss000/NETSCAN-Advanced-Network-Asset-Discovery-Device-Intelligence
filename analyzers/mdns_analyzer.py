"""
Enhanced mDNS Analyzer
======================
Extracts device information from Multicast DNS traffic.
Now extracts TXT records for device model info.
"""

import scapy.all as scapy
from .base import BaseAnalyzer


class MDNSAnalyzer(BaseAnalyzer):
    def process_packet(self, packet):
        """Process mDNS packets to extract device information."""
        
        if not scapy.DNS in packet:
            return
            
        src_mac = None
        src_ip = None
        
        if packet.haslayer(scapy.Ether):
            src_mac = packet[scapy.Ether].src.lower()
        
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            
        if not src_mac:
            return

        dns_layer = packet[scapy.DNS]
        
        # Process answer records
        if dns_layer.ancount and dns_layer.ancount > 0:
            self._process_records(dns_layer.an, dns_layer.ancount, src_mac, src_ip)
        
        # Process additional records
        if dns_layer.arcount and dns_layer.arcount > 0:
            self._process_records(dns_layer.ar, dns_layer.arcount, src_mac, src_ip)

    def _process_records(self, records, count, src_mac, src_ip):
        """Process DNS resource records."""
        for i in range(count):
            try:
                rr = records[i]
                rrname = self._decode(rr.rrname)
                
                # PTR Record (12) - Service type -> instance name
                if rr.type == 12:
                    rdata = self._decode(rr.rdata)
                    
                    # Service types like _googlecast._tcp.local
                    if "_tcp" in rrname or "_udp" in rrname:
                        self.device_manager.update_device(src_mac, service=rrname)
                        if rdata:
                            self.device_manager.update_device(src_mac, service=rdata)

                # SRV Record (33) - Instance name -> target host
                elif rr.type == 33:
                    target = self._decode(rr.target)
                    if target:
                        # Clean up hostname (remove .local. suffix)
                        hostname = target.replace('.local.', '').replace('.local', '')
                        self.device_manager.update_device(src_mac, hostname=hostname)

                # A Record (1) - Hostname -> IP
                elif rr.type == 1:
                    if src_ip:
                        self.device_manager.update_device(src_mac, ip=src_ip)

                # TXT Record (16) - Often contains device model info
                elif rr.type == 16:
                    self._process_txt_record(rr, src_mac)
                    
            except Exception:
                pass

    def _process_txt_record(self, rr, src_mac):
        """Extract device info from TXT records."""
        try:
            # TXT rdata can be a list or bytes
            if hasattr(rr, 'rdata'):
                rdata = rr.rdata
                if isinstance(rdata, (list, tuple)):
                    for item in rdata:
                        self._parse_txt_item(item, src_mac)
                else:
                    self._parse_txt_item(rdata, src_mac)
        except:
            pass

    def _parse_txt_item(self, item, src_mac):
        """Parse individual TXT record item for device info."""
        try:
            text = self._decode(item)
            if not text:
                return
                
            text_lower = text.lower()
            
            # Common TXT record keys that identify devices
            # Apple devices: model=iPhone14,3
            if text.startswith('model='):
                model = text.split('=', 1)[1]
                self.device_manager.update_device(src_mac, service=f"model:{model}")
                
                # Infer OS from Apple model strings
                if 'iphone' in text_lower or 'ipad' in text_lower or 'mac' in text_lower:
                    self.device_manager.update_device(src_mac, os="Apple iOS/macOS")
            
            # Device name
            elif text.startswith('fn=') or text.startswith('name='):
                name = text.split('=', 1)[1]
                self.device_manager.update_device(src_mac, hostname=name)
            
            # Chromecast/Google devices
            elif text.startswith('md='):
                model = text.split('=', 1)[1]
                self.device_manager.update_device(src_mac, service=f"model:{model}")
            
            # Roku devices
            elif 'roku' in text_lower:
                self.device_manager.update_device(src_mac, service="roku_device")
                
        except:
            pass

    def _decode(self, data):
        """Safely decode bytes to string."""
        if data is None:
            return None
        if isinstance(data, str):
            return data
        if isinstance(data, bytes):
            try:
                return data.decode('utf-8', errors='ignore')
            except:
                return None
        return str(data)
