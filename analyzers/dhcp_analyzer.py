"""
Enhanced DHCP Analyzer
======================
Extracts device information from DHCP traffic.
Now parses vendor class for device type hints and extracts requested IP.
"""

import scapy.all as scapy
from .base import BaseAnalyzer


class DHCPAnalyzer(BaseAnalyzer):
    # Known vendor class patterns for device identification
    VENDOR_CLASS_PATTERNS = {
        'MSFT': 'Windows',
        'android': 'Android',
        'dhcpcd': 'Linux',
        'udhcp': 'Linux/Embedded',
        'iPhone': 'iOS',
        'iPad': 'iOS',
        'Apple': 'Apple',
        'Roku': 'Roku',
        'Samsung': 'Samsung',
        'HUAWEI': 'Huawei',
    }
    
    def process_packet(self, packet):
        """Process DHCP packets to extract device information."""
        if not scapy.DHCP in packet:
            return
            
        src_mac = None
        if scapy.Ether in packet:
            src_mac = packet[scapy.Ether].src.lower()
        
        if not src_mac:
            return

        options = packet[scapy.DHCP].options
        
        hostname = None
        vendor_class_id = None
        requested_ip = None
        client_id = None
        
        for opt in options:
            if not isinstance(opt, tuple):
                continue
                
            opt_name = opt[0]
            opt_value = opt[1] if len(opt) > 1 else None
            
            if opt_name == 'hostname':
                hostname = self._decode(opt_value)
                
            elif opt_name == 'vendor_class_id':
                vendor_class_id = self._decode(opt_value)
                
            elif opt_name == 'requested_addr':
                # This is the IP the client is requesting
                requested_ip = str(opt_value) if opt_value else None
                
            elif opt_name == 'client_id':
                # Sometimes contains device type info
                client_id = self._decode(opt_value)
        
        # Update device with extracted info
        if hostname:
            self.device_manager.update_device(src_mac, hostname=hostname)
        
        if requested_ip:
            self.device_manager.update_device(src_mac, ip=requested_ip)
        
        # Parse vendor class for OS hints
        if vendor_class_id:
            os_hint = self._parse_vendor_class(vendor_class_id)
            if os_hint:
                self.device_manager.update_device(src_mac, os=os_hint)
            else:
                # Still store raw vendor class as service hint
                self.device_manager.update_device(src_mac, service=f"dhcp:{vendor_class_id[:30]}")

    def _parse_vendor_class(self, vendor_class):
        """Parse vendor class ID to identify device type."""
        if not vendor_class:
            return None
            
        vendor_lower = vendor_class.lower()
        
        for pattern, os_name in self.VENDOR_CLASS_PATTERNS.items():
            if pattern.lower() in vendor_lower:
                return os_name
        
        return None

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
