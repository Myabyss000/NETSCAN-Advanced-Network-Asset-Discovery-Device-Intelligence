import time
from datetime import datetime
from collections import defaultdict
from utils import get_vendor_mac_lookup

class Device:
    def __init__(self, mac):
        self.mac = mac
        self.ip = None
        self.vendor = get_vendor_mac_lookup(mac)
        self.hostnames = set()
        self.services = set()
        self.os_guess = None
        self.last_seen = time.time()
        self.first_seen = time.time()

    def update_ip(self, ip):
        if ip and ip != "0.0.0.0":
            self.ip = ip
            self.last_seen = time.time()

    def add_hostname(self, hostname):
        if hostname:
            self.hostnames.add(hostname)
            self.last_seen = time.time()

    def add_service(self, service):
        if service:
            self.services.add(service)
            self.last_seen = time.time()
    
    def set_os(self, os_name):
        if os_name:
            self.os_guess = os_name
            self.last_seen = time.time()

    def touch(self):
        self.last_seen = time.time()
    
    def merge_from(self, other):
        """Merge data from another device (for deduplication)."""
        # Merge hostnames
        self.hostnames.update(other.hostnames)
        # Merge services
        self.services.update(other.services)
        # Keep better OS guess
        if other.os_guess and not self.os_guess:
            self.os_guess = other.os_guess
        # Keep earliest first_seen
        if other.first_seen < self.first_seen:
            self.first_seen = other.first_seen
        # Update last_seen to most recent
        if other.last_seen > self.last_seen:
            self.last_seen = other.last_seen

    def __str__(self):
        return f"[{self.mac}] {self.ip} ({self.vendor}) - {','.join(self.hostnames)}"

class DeviceManager:
    def __init__(self):
        self.devices = {}  # mac -> Device
        self.ip_to_mac = {}  # ip -> mac (for deduplication)

    def get_device(self, mac):
        if mac not in self.devices:
            self.devices[mac] = Device(mac)
        return self.devices[mac]

    def update_device(self, mac, ip=None, hostname=None, service=None, os=None):
        # Check if this IP was already seen with a different MAC
        if ip and ip in self.ip_to_mac:
            existing_mac = self.ip_to_mac[ip]
            if existing_mac != mac and existing_mac in self.devices:
                # Same IP, different MAC - merge into existing device
                existing_device = self.devices[existing_mac]
                
                # If new MAC also has a device, merge its data
                if mac in self.devices:
                    existing_device.merge_from(self.devices[mac])
                    # Remove the duplicate
                    del self.devices[mac]
                
                # Update existing device with new info
                if hostname: existing_device.add_hostname(hostname)
                if service: existing_device.add_service(service)
                if os: existing_device.set_os(os)
                existing_device.touch()
                return existing_device
        
        # Normal case: get or create device by MAC
        device = self.get_device(mac)
        if ip: 
            device.update_ip(ip)
            self.ip_to_mac[ip] = mac  # Track IP -> MAC mapping
        if hostname: device.add_hostname(hostname)
        if service: device.add_service(service)
        if os: device.set_os(os)
        device.touch()
        return device

    def get_all_devices(self):
        """Return all devices, deduplicating by IP."""
        # Additional pass to ensure no duplicate IPs
        seen_ips = {}
        unique_devices = []
        
        for device in self.devices.values():
            if device.ip:
                if device.ip in seen_ips:
                    # Duplicate IP - merge into existing
                    seen_ips[device.ip].merge_from(device)
                else:
                    seen_ips[device.ip] = device
                    unique_devices.append(device)
            else:
                # Device without IP - keep it
                unique_devices.append(device)
        
        return unique_devices

