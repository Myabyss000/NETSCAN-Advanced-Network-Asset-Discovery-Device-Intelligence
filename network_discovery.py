"""
Network Discovery Module
========================
Automatically detects all network interfaces, subnets, and VPN connections.
No technical knowledge required - fully automatic detection.
"""

import socket
import subprocess
import re
import ipaddress


def get_all_interfaces():
    """
    Get all network interfaces with their IPs and subnets.
    Returns list of dicts with interface info.
    """
    interfaces = []
    
    try:
        # Windows: Use ipconfig
        result = subprocess.run(
            ["ipconfig", "/all"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        interfaces = _parse_ipconfig(result.stdout)
    except:
        pass
    
    # Fallback: Try socket method
    if not interfaces:
        interfaces = _get_interfaces_socket()
    
    return interfaces


def _parse_ipconfig(output):
    """Parse Windows ipconfig output."""
    interfaces = []
    current_iface = None
    
    lines = output.split('\n')
    
    for line in lines:
        # New interface section - look for adapter headers
        # They look like: "Ethernet adapter Ethernet:", "Wireless LAN adapter Wi-Fi:"
        if 'adapter' in line.lower() and line.strip().endswith(':'):
            if current_iface and current_iface.get('ip'):
                interfaces.append(current_iface)
            
            # Extract just the adapter name after "adapter "
            name = line.strip().rstrip(':')
            # Try to get just the interface name
            if ' adapter ' in name.lower():
                parts = name.split(' adapter ', 1)
                if len(parts) > 1:
                    name = parts[1]  # Get part after "adapter "
            
            current_iface = {
                'name': name.strip(),
                'ip': None,
                'subnet': None,
                'gateway': None,
                'type': _detect_interface_type(name)
            }
            continue
        
        # Skip if no current interface
        if not current_iface:
            continue
        
        # Clean line for parsing
        line = line.strip()
        if not line or ':' not in line:
            continue
        
        # Split on colon and get value
        parts = line.split(':', 1)
        if len(parts) != 2:
            continue
        
        key = parts[0].strip().lower()
        value = parts[1].strip()
        
        # Remove (Preferred) suffix from IP
        value = value.replace('(Preferred)', '').strip()
        
        # IPv4 Address
        if 'ipv4 address' in key or (key == 'ip address' and '.' in value):
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)', value)
            if match:
                current_iface['ip'] = match.group(1)
        
        # Subnet Mask
        elif 'subnet mask' in key:
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)', value)
            if match:
                current_iface['subnet_mask'] = match.group(1)
                # Calculate CIDR subnet
                if current_iface.get('ip'):
                    current_iface['subnet'] = _calculate_subnet(
                        current_iface['ip'],
                        match.group(1)
                    )
        
        # Default Gateway
        elif 'default gateway' in key:
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)', value)
            if match:
                current_iface['gateway'] = match.group(1)
    
    # Don't forget last interface
    if current_iface and current_iface.get('ip'):
        interfaces.append(current_iface)
    
    return interfaces


def _detect_interface_type(name):
    """Detect interface type from name."""
    name_lower = name.lower()
    
    # VPN patterns
    vpn_patterns = [
        'vpn', 'tun', 'tap', 'ppp', 'wg', 'wireguard', 'openvpn',
        'tailscale', 'zerotier', 'nordvpn', 'expressvpn', 'protonvpn',
        'mullvad', 'surfshark', 'pia', 'cyberghost', 'fortinet',
        'cisco anyconnect', 'globalprotect', 'pulse secure', 'juniper'
    ]
    
    for pattern in vpn_patterns:
        if pattern in name_lower:
            return 'vpn'
    
    # WiFi patterns
    if 'wi-fi' in name_lower or 'wifi' in name_lower or 'wireless' in name_lower or 'wlan' in name_lower:
        return 'wifi'
    
    # Ethernet patterns
    if 'ethernet' in name_lower or 'eth' in name_lower or 'local area' in name_lower:
        return 'ethernet'
    
    # Virtual/VM patterns
    if 'vmware' in name_lower or 'virtualbox' in name_lower or 'hyper-v' in name_lower or 'vethernet' in name_lower:
        return 'virtual'
    
    # Loopback
    if 'loopback' in name_lower or name_lower == 'lo':
        return 'loopback'
    
    return 'unknown'


def _calculate_subnet(ip, mask):
    """Calculate network subnet from IP and mask."""
    try:
        network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        return str(network)
    except:
        # Fallback: assume /24
        parts = ip.split('.')
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def _get_interfaces_socket():
    """Fallback method using socket."""
    interfaces = []
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        parts = local_ip.split('.')
        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        
        interfaces.append({
            'name': 'Default',
            'ip': local_ip,
            'subnet': subnet,
            'type': 'unknown'
        })
    except:
        pass
    
    return interfaces


def get_scannable_networks():
    """
    Get all networks that can be scanned.
    Filters out loopback and virtual interfaces.
    Returns list of (name, subnet, type) tuples.
    """
    interfaces = get_all_interfaces()
    networks = []
    seen_subnets = set()
    
    for iface in interfaces:
        # Skip loopback and virtual
        if iface['type'] in ['loopback', 'virtual']:
            continue
        
        # Skip if no subnet
        if not iface.get('subnet'):
            continue
        
        # Skip if no valid IP
        if not iface.get('ip') or iface['ip'].startswith('169.254'):  # APIPA
            continue
        
        # Skip duplicates
        if iface['subnet'] in seen_subnets:
            continue
        
        seen_subnets.add(iface['subnet'])
        
        # Determine icon
        if iface['type'] == 'vpn':
            icon = '🔒'
        elif iface['type'] == 'wifi':
            icon = '📶'
        elif iface['type'] == 'ethernet':
            icon = '🔌'
        else:
            icon = '🌐'
        
        networks.append({
            'name': iface['name'],
            'subnet': iface['subnet'],
            'ip': iface['ip'],
            'type': iface['type'],
            'icon': icon,
            'gateway': iface.get('gateway')
        })
    
    return networks


def detect_vpn_connections():
    """
    Specifically detect active VPN connections.
    Returns list of VPN interface info.
    """
    interfaces = get_all_interfaces()
    vpns = []
    
    for iface in interfaces:
        if iface['type'] == 'vpn' and iface.get('ip'):
            vpns.append(iface)
    
    return vpns


def print_network_summary(networks):
    """Print a summary of detected networks."""
    print("\n🔍 Detected Networks:")
    print("-" * 50)
    
    for i, net in enumerate(networks, 1):
        print(f"  {net['icon']} {net['name'][:30]}")
        print(f"     IP: {net['ip']}")
        print(f"     Subnet: {net['subnet']}")
        if net.get('gateway'):
            print(f"     Gateway: {net['gateway']}")
        print()


if __name__ == "__main__":
    # Test
    networks = get_scannable_networks()
    print_network_summary(networks)
    
    vpns = detect_vpn_connections()
    if vpns:
        print("\n🔒 Active VPN Connections:")
        for vpn in vpns:
            print(f"  - {vpn['name']}: {vpn['ip']}")
