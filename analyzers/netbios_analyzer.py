import scapy.all as scapy
from .base import BaseAnalyzer

class NetBIOSAnalyzer(BaseAnalyzer):
    """
    Analyzes NetBIOS Name Service (NBNS) packets.
    Used by Windows PCs to announce their hostname and workgroup.
    Runs on UDP port 137.
    """
    
    def process_packet(self, packet):
        # NetBIOS Name Service is UDP on port 137
        if not packet.haslayer(scapy.UDP):
            return
        
        udp = packet[scapy.UDP]
        if udp.dport != 137 and udp.sport != 137:
            return
        
        # Get source MAC and IP
        src_mac = None
        src_ip = None
        if packet.haslayer(scapy.Ether):
            src_mac = packet[scapy.Ether].src
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
        
        if not src_mac:
            return
        
        # NetBIOS payload is in Raw layer
        if not packet.haslayer(scapy.Raw):
            return
        
        try:
            payload = packet[scapy.Raw].load
            # NetBIOS name is encoded in first-level encoding
            # Skip first 12 bytes (header), then read name
            if len(payload) < 50:
                return
            
            # The name starts at offset 13 and is 32 bytes (encoded)
            encoded_name = payload[13:45]
            name = self._decode_netbios_name(encoded_name)
            
            if name and not name.startswith('\x00'):
                # Clean up the name (remove padding spaces and suffix type byte)
                name = name.rstrip()
                if name:
                    self.device_manager.update_device(src_mac, hostname=name, ip=src_ip)
                    
        except Exception:
            pass
    
    def _decode_netbios_name(self, encoded):
        """Decode NetBIOS first-level encoded name."""
        try:
            decoded = ''
            for i in range(0, 30, 2):
                if i + 1 >= len(encoded):
                    break
                high = encoded[i] - ord('A')
                low = encoded[i + 1] - ord('A')
                char = (high << 4) | low
                if char == 0:
                    break
                decoded += chr(char)
            return decoded.strip()
        except:
            return None
