import scapy.all as scapy
from .base import BaseAnalyzer

class SSDPAnalyzer(BaseAnalyzer):
    """
    Analyzes SSDP (Simple Service Discovery Protocol) packets.
    SSDP is used by UPnP devices: smart TVs, Chromecast, Roku, printers, routers.
    Runs on UDP port 1900.
    """
    
    def process_packet(self, packet):
        # SSDP is UDP on port 1900
        if not packet.haslayer(scapy.UDP):
            return
        
        udp = packet[scapy.UDP]
        if udp.dport != 1900 and udp.sport != 1900:
            return
        
        # Get source MAC
        src_mac = None
        if packet.haslayer(scapy.Ether):
            src_mac = packet[scapy.Ether].src
        
        if not src_mac:
            return
        
        # SSDP payload is in Raw layer
        if not packet.haslayer(scapy.Raw):
            return
        
        try:
            payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
        except:
            return
        
        # Parse SSDP headers
        lines = payload.split('\r\n')
        
        # Check if it's NOTIFY or M-SEARCH response
        if not (lines[0].startswith('NOTIFY') or lines[0].startswith('HTTP/1.1 200')):
            return
        
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.upper().strip()] = value.strip()
        
        # Extract useful info
        # SERVER header often contains OS/device info
        server = headers.get('SERVER', '')
        
        # ST or NT contains device type
        device_type = headers.get('ST', headers.get('NT', ''))
        
        # USN is unique service name
        usn = headers.get('USN', '')
        
        # LOCATION has device description URL
        location = headers.get('LOCATION', '')
        
        # Update device
        service_info = []
        if 'upnp:rootdevice' in device_type.lower():
            service_info.append('UPnP')
        if 'mediarenderer' in device_type.lower():
            service_info.append('MediaRenderer')
        if 'mediaserver' in device_type.lower():
            service_info.append('MediaServer')
        if 'dial' in device_type.lower():
            service_info.append('DIAL')
        if 'roku' in server.lower() or 'roku' in usn.lower():
            service_info.append('Roku')
        if 'chromecast' in server.lower() or 'cast' in usn.lower():
            service_info.append('Chromecast')
        
        for svc in service_info:
            self.device_manager.update_device(src_mac, service=f"SSDP:{svc}")
        
        # Use SERVER as OS hint
        if server:
            self.device_manager.update_device(src_mac, os=server[:50])
