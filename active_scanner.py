"""
Advanced Active Network Scanner
===============================
Comprehensive device discovery using multiple techniques:
- Full /24 ARP sweep with retries
- ICMP ping sweep
- TCP port scanning
- HTTP/RTSP banner grabbing
- Service fingerprinting
"""

import scapy.all as scapy
import socket
import threading
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import warnings

# Suppress SSL warnings
warnings.filterwarnings('ignore')


def get_local_ip():
    """Get the local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "192.168.1.100"


def get_gateway():
    """Get default gateway IP."""
    try:
        local_ip = get_local_ip()
        parts = local_ip.split('.')
        return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
    except:
        return "192.168.1.1"


def get_subnet(ip):
    """Get subnet from IP (assumes /24)."""
    parts = ip.split('.')
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def get_all_ips_in_subnet(ip):
    """Generate all IPs in /24 subnet."""
    parts = ip.split('.')
    base = f"{parts[0]}.{parts[1]}.{parts[2]}"
    return [f"{base}.{i}" for i in range(1, 255)]


# =============================================================================
# ARP SCANNING
# =============================================================================
def arp_scan(subnet, timeout=2, retry=2, verbose=False):
    """
    Perform comprehensive ARP scan with retries.
    Returns list of (ip, mac) tuples.
    """
    all_devices = {}
    
    for attempt in range(retry):
        try:
            arp_request = scapy.ARP(pdst=subnet)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request
            
            answered, _ = scapy.srp(packet, timeout=timeout, verbose=verbose)
            
            for sent, received in answered:
                ip = received.psrc
                mac = received.hwsrc.lower()
                if ip not in all_devices:
                    all_devices[ip] = mac
        except Exception as e:
            pass
    
    return list(all_devices.items())


def arp_scan_single(ip, timeout=1):
    """Scan a single IP via ARP."""
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        answered, _ = scapy.srp(packet, timeout=timeout, verbose=False)
        
        for sent, received in answered:
            return (received.psrc, received.hwsrc.lower())
    except:
        pass
    return None


# =============================================================================
# HOSTNAME RESOLUTION
# =============================================================================
def resolve_netbios_name(ip, timeout=1):
    """
    Resolve Windows NetBIOS hostname for an IP.
    Uses NetBIOS Name Service (port 137).
    """
    try:
        # NetBIOS Name Query packet
        # Transaction ID + Flags + Questions + Answer RRs + Authority RRs + Additional RRs
        query = (
            b'\x80\x94'  # Transaction ID
            b'\x00\x00'  # Flags (query)
            b'\x00\x01'  # Questions: 1
            b'\x00\x00'  # Answer RRs
            b'\x00\x00'  # Authority RRs
            b'\x00\x00'  # Additional RRs
            b'\x20'      # Name length (32 encoded)
            + b'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'  # Wildcard query *
            b'\x00'      # Null terminator
            b'\x00\x21'  # Type: NBSTAT
            b'\x00\x01'  # Class: IN
        )
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (ip, 137))
        
        response, _ = sock.recvfrom(1024)
        sock.close()
        
        # Parse response - names start at offset 57
        if len(response) > 57:
            num_names = response[56]
            names = []
            offset = 57
            
            for i in range(num_names):
                if offset + 18 > len(response):
                    break
                
                name = response[offset:offset+15].decode('ascii', errors='ignore').strip()
                suffix = response[offset+15]
                flags = response[offset+16:offset+18]
                
                # Suffix 0x00 with bit 7 of flags = 0 is the workstation name
                if suffix == 0x00 and (flags[0] & 0x80) == 0:
                    if name and not name.startswith(' '):
                        return name
                
                offset += 18
            
            # Return first non-empty name found
            for i in range(num_names):
                offset_i = 57 + (i * 18)
                if offset_i + 15 <= len(response):
                    name = response[offset_i:offset_i+15].decode('ascii', errors='ignore').strip()
                    if name and not name.startswith(' ') and not name.startswith('\x00'):
                        return name
    except:
        pass
    
    return None


def resolve_hostname_dns(ip, timeout=1):
    """Resolve hostname via reverse DNS lookup."""
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname.split('.')[0]  # Return short name
    except:
        return None


def resolve_hostname(ip, timeout=1):
    """
    Resolve hostname using multiple methods.
    Returns hostname or None.
    """
    # Try NetBIOS first (better for Windows machines)
    name = resolve_netbios_name(ip, timeout)
    if name:
        return name
    
    # Fall back to DNS
    name = resolve_hostname_dns(ip, timeout)
    if name:
        return name
    
    return None


def parallel_hostname_resolve(ips, max_workers=20):
    """Resolve hostnames for multiple IPs in parallel."""
    results = {}
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(resolve_hostname, ip, 1): ip for ip in ips}
        
        for future in as_completed(futures):
            ip = futures[future]
            try:
                hostname = future.result()
                if hostname:
                    results[ip] = hostname
            except:
                pass
    
    return results


# =============================================================================
# ICMP PING SCANNING
# =============================================================================
def icmp_ping(ip, timeout=1):
    """Ping a single IP using ICMP."""
    try:
        packet = scapy.IP(dst=ip)/scapy.ICMP()
        reply = scapy.sr1(packet, timeout=timeout, verbose=False)
        if reply:
            return ip
    except:
        pass
    return None


def ping_sweep(ips, max_workers=50):
    """Ping sweep multiple IPs in parallel."""
    alive = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(icmp_ping, ip, 0.5): ip for ip in ips}
        for future in as_completed(futures):
            result = future.result()
            if result:
                alive.append(result)
    return alive


# =============================================================================
# TCP PORT SCANNING
# =============================================================================

# Comprehensive port list for device identification
SCAN_PORTS = {
    # Camera ports
    554: "RTSP",
    8554: "RTSP-Alt",
    37777: "Dahua",
    34567: "DVR",
    8000: "ONVIF",
    
    # Web interfaces
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt2",
    
    # IoT/Smart devices
    1883: "MQTT",
    8883: "MQTT-SSL",
    5353: "mDNS",
    1900: "SSDP",
    
    # Network devices
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    161: "SNMP",
    
    # Media devices
    8008: "Chromecast",
    9080: "Roku",
    7000: "AirPlay",
    
    # Printers
    9100: "JetDirect",
    515: "LPR",
    631: "IPP",
    
    # File sharing
    445: "SMB",
    139: "NetBIOS",
    21: "FTP",
    
    # Other
    3389: "RDP",
    5900: "VNC",
}


def check_port(ip, port, timeout=0.5):
    """Check if a port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False


def scan_ports(ip, ports=None, timeout=0.5):
    """Scan multiple ports on an IP."""
    if ports is None:
        ports = SCAN_PORTS.keys()
    
    open_ports = []
    for port in ports:
        if check_port(ip, port, timeout):
            name = SCAN_PORTS.get(port, "Unknown")
            open_ports.append((port, name))
    
    return open_ports


def parallel_port_scan(ips, ports=None, max_workers=30, progress_callback=None):
    """Scan ports on multiple IPs in parallel."""
    if ports is None:
        ports = list(SCAN_PORTS.keys())
    
    results = {}
    total = len(ips)
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_ports, ip, ports, 0.3): ip for ip in ips}
        
        for i, future in enumerate(as_completed(futures)):
            ip = futures[future]
            try:
                open_ports = future.result()
                if open_ports:
                    results[ip] = open_ports
            except:
                pass
            
            if progress_callback:
                progress_callback(i + 1, total)
    
    return results


# =============================================================================
# HTTP BANNER GRABBING
# =============================================================================
def grab_http_banner(ip, port=80, timeout=2):
    """Grab HTTP server banner/title."""
    try:
        protocol = "https" if port in [443, 8443] else "http"
        url = f"{protocol}://{ip}:{port}/"
        
        response = requests.get(
            url, 
            timeout=timeout, 
            verify=False,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        
        # Extract title
        if "<title>" in response.text.lower():
            start = response.text.lower().find("<title>") + 7
            end = response.text.lower().find("</title>")
            if end > start:
                title = response.text[start:end].strip()[:50]
                return title
        
        # Extract server header
        server = response.headers.get("Server", "")
        if server:
            return server[:50]
        
        return None
    except:
        return None


def grab_rtsp_banner(ip, port=554, timeout=2):
    """Check RTSP and get info."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # Send RTSP OPTIONS request
        request = f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
        sock.send(request.encode())
        
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        
        if "RTSP" in response:
            return "RTSP_CONFIRMED"
        return None
    except:
        return None


def fingerprint_device(ip, open_ports):
    """
    Fingerprint device based on open ports and banners.
    Returns additional info for classification.
    """
    info = {
        "banners": [],
        "services": [],
        "hints": []
    }
    
    for port, name in open_ports:
        info["services"].append(f"Port:{port}({name})")
        
        # HTTP banner grabbing
        if port in [80, 8080, 443, 8443, 8888]:
            banner = grab_http_banner(ip, port, timeout=1)
            if banner:
                info["banners"].append(banner)
                
                # Camera indicators in banner
                cam_keywords = ["camera", "ipcam", "dvr", "nvr", "hikvision", "dahua", 
                               "surveillance", "cctv", "reolink", "amcrest", "axis"]
                for kw in cam_keywords:
                    if kw in banner.lower():
                        info["hints"].append("camera_banner")
                        break
        
        # RTSP confirmation
        if port in [554, 8554]:
            rtsp = grab_rtsp_banner(ip, port, timeout=1)
            if rtsp:
                info["hints"].append("rtsp_confirmed")
    
    return info


# =============================================================================
# MAIN ACTIVE SCANNER CLASS
# =============================================================================
class ActiveScanner:
    """Comprehensive active network scanner."""
    
    def __init__(self, device_manager, interface=None):
        self.device_manager = device_manager
        self.interface = interface
        self.local_ip = get_local_ip()
        self.subnet = get_subnet(self.local_ip)
    
    def full_discovery(self, progress_callback=None):
        """
        Comprehensive device discovery:
        1. ARP sweep (with retries)
        2. ICMP ping sweep for missed devices
        3. Port scanning
        4. Service fingerprinting
        """
        discovered = {}
        
        # Phase 1: ARP Sweep
        if progress_callback:
            progress_callback("phase", "ARP Sweep", 0, 100)
        
        arp_results = arp_scan(self.subnet, timeout=2, retry=2)
        for ip, mac in arp_results:
            discovered[ip] = mac
            self.device_manager.update_device(mac, ip=ip)
        
        if progress_callback:
            progress_callback("phase", "ARP Sweep", 100, 100)
            progress_callback("found", len(discovered), "ARP")
        
        # Phase 2: ICMP Ping Sweep (for devices that didn't respond to ARP)
        if progress_callback:
            progress_callback("phase", "Ping Sweep", 0, 100)
        
        all_ips = get_all_ips_in_subnet(self.local_ip)
        missing_ips = [ip for ip in all_ips if ip not in discovered]
        
        # Ping in batches
        alive_ips = ping_sweep(missing_ips, max_workers=50)
        
        # Try ARP on alive IPs
        for ip in alive_ips:
            result = arp_scan_single(ip, timeout=1)
            if result:
                discovered[result[0]] = result[1]
                self.device_manager.update_device(result[1], ip=result[0])
        
        if progress_callback:
            progress_callback("phase", "Ping Sweep", 100, 100)
            progress_callback("found", len(discovered), "Total")
        
        return len(discovered)
    
    def deep_scan(self, progress_callback=None):
        """
        Deep scan all discovered devices:
        1. Port scanning
        2. Service fingerprinting
        3. Banner grabbing
        """
        devices = self.device_manager.get_all_devices()
        ips = [d.ip for d in devices if d.ip and d.ip != "Unknown"]
        
        if not ips:
            return {}
        
        # Port scan
        if progress_callback:
            progress_callback("phase", "Port Scanning", 0, len(ips))
        
        def update_port_progress(current, total):
            if progress_callback:
                progress_callback("phase", "Port Scanning", current, total)
        
        port_results = parallel_port_scan(ips, progress_callback=update_port_progress)
        
        # Fingerprint devices with open ports
        if progress_callback:
            progress_callback("phase", "Fingerprinting", 0, len(port_results))
        
        camera_count = 0
        
        for i, (ip, open_ports) in enumerate(port_results.items()):
            # Update device with port info
            device = next((d for d in devices if d.ip == ip), None)
            if device:
                for port, name in open_ports:
                    device.add_service(f"Port:{port}({name})")
                
                # Check for camera indicators
                camera_ports = [554, 8554, 37777, 34567, 8000]
                if any(p[0] in camera_ports for p in open_ports):
                    device.add_service("⚠️ CAMERA_SUSPECTED")
                    camera_count += 1
                
                # Fingerprint for more info
                fp_info = fingerprint_device(ip, open_ports)
                for hint in fp_info["hints"]:
                    if hint == "camera_banner":
                        device.add_service("⚠️ CAMERA_CONFIRMED")
                    elif hint == "rtsp_confirmed":
                        device.add_service("⚠️ RTSP_STREAMING")
            
            if progress_callback:
                progress_callback("phase", "Fingerprinting", i + 1, len(port_results))
        
        return {
            "port_results": port_results,
            "camera_count": camera_count
        }
    
    def discover_devices(self, progress_callback=None):
        """Basic ARP discovery (legacy interface)."""
        return self.full_discovery(progress_callback)
    
    def scan_for_cameras(self, progress_callback=None):
        """Scan for cameras specifically."""
        devices = self.device_manager.get_all_devices()
        ips = [d.ip for d in devices if d.ip and d.ip != "Unknown"]
        
        if not ips:
            return {}
        
        # Only scan camera-related ports
        camera_ports = [554, 8554, 37777, 34567, 8000, 80, 8080, 443]
        
        results = parallel_port_scan(ips, ports=camera_ports, progress_callback=progress_callback)
        
        # Update devices
        for device in devices:
            if device.ip in results:
                for port, name in results[device.ip]:
                    device.add_service(f"Port:{port}({name})")
                    
                    if port in [554, 8554, 37777, 34567]:
                        device.add_service("⚠️ CAMERA_DETECTED")
        
        return results
