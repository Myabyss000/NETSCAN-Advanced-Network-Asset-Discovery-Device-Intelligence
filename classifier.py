"""
Advanced Device Classification Engine
=====================================
Multi-signal weighted scoring with confidence levels.
Designed for <1% false positive rate.

Confidence Thresholds:
- HIGH: 80-100% - Very confident
- MEDIUM: 60-79% - Likely correct
- LOW: 40-59% - Possible match
- UNCERTAIN: <40% - Needs more data
"""

# Device type constants
DEVICE_ROUTER = "router"
DEVICE_PC = "pc"
DEVICE_PHONE = "phone"
DEVICE_TABLET = "tablet"
DEVICE_IOT = "iot"
DEVICE_MEDIA = "media"
DEVICE_PRINTER = "printer"
DEVICE_CAMERA = "camera"
DEVICE_UNKNOWN = "unknown"

WEIGHT_VENDOR_EXACT = 25      # Exact vendor match (e.g., "Hikvision")
WEIGHT_VENDOR_PARTIAL = 15    # Partial vendor match
WEIGHT_PORT_PRIMARY = 30      # Primary port for device (e.g., 554 for camera)
WEIGHT_PORT_SECONDARY = 15    # Secondary/common port
WEIGHT_SERVICE_EXACT = 25     # Exact service match (e.g., _rtsp._tcp)
WEIGHT_SERVICE_PARTIAL = 12   # Partial service match
WEIGHT_HOSTNAME = 25          # Hostname pattern match (increased from 20)
WEIGHT_HOSTNAME_DEFINITIVE = 40  # Definitive hostname (LAPTOP-, DESKTOP-, iPhone, etc.)
WEIGHT_OS_HINT = 15           # OS fingerprint hint
WEIGHT_GATEWAY_IP = 15        # .1 or .254 IP (router indicator, reduced from 20)
WEIGHT_DHCP_CLASS = 18        # DHCP vendor class
WEIGHT_RANDOM_MAC = 18        # Random MAC (likely phone/tablet)
WEIGHT_NO_PORTS = 15          # No open ports (likely mobile device)

# Maximum possible score per category (for normalization)
MAX_SCORE = 100


def is_random_mac(mac):
    """
    Check if MAC address is locally administered (random).
    Modern phones use random MACs for privacy.
    Bit 1 of first octet = 1 means locally administered.
    """
    if not mac:
        return False
    try:
        first_byte = int(mac.split(':')[0], 16)
        return bool(first_byte & 0x02)  # Check bit 1
    except:
        return False

# ============================================================================
# VENDOR PATTERNS (Exact and unique to device type)
# ============================================================================
VENDOR_PATTERNS = {
    DEVICE_CAMERA: {
        "exact": [
            "hikvision", "dahua", "reolink", "amcrest", "foscam", "lorex",
            "swann", "axis", "vivotek", "geovision", "hanwha", "uniview",
            "tiandy", "cp plus", "ezviz", "imou"
        ],
        "partial": [
            "camera", "ipcam", "dvr", "nvr", "cctv", "surveillance"
        ]
    },
    DEVICE_PHONE: {
        "exact": [
            "apple", "samsung mobile", "xiaomi", "huawei device", "oneplus",
            "oppo", "vivo", "realme", "motorola mobility", "google"
        ],
        "partial": [
            "mobile", "wireless", "phone"
        ]
    },
    DEVICE_PC: {
        "exact": [
            "dell", "hewlett packard", "lenovo", "asus", "acer", "microsoft",
            "intel corporate", "gigabyte", "msi", "asrock", "razer"
        ],
        "partial": [
            "computer", "desktop", "laptop", "workstation"
        ]
    },
    DEVICE_ROUTER: {
        "exact": [
            "tp-link", "netgear", "d-link", "linksys", "cisco", "ubiquiti",
            "mikrotik", "zyxel", "asus", "arris", "actiontec", "huawei router"
        ],
        "partial": [
            "router", "gateway", "modem", "access point"
        ]
    },
    DEVICE_IOT: {
        "exact": [
            "philips hue", "signify", "ring", "nest", "ecobee", "tuya",
            "espressif", "sonoff", "shelly", "broadlink", "yeelight",
            "smart life", "wemo", "lifx"
        ],
        "partial": [
            "smart", "iot", "sensor", "thermostat", "bulb"
        ]
    },
    DEVICE_MEDIA: {
        "exact": [
            "roku", "amazon fire", "chromecast", "apple tv", "sonos",
            "bose", "nvidia shield", "xbox", "playstation"
        ],
        "partial": [
            "streaming", "media", "entertainment", "tv"
        ]
    },
    DEVICE_PRINTER: {
        "exact": [
            "hp inc", "canon", "epson", "brother", "xerox", "lexmark",
            "ricoh", "konica minolta", "kyocera"
        ],
        "partial": [
            "printer", "print", "mfp", "laserjet", "inkjet"
        ]
    }
}

# ============================================================================
# PORT SIGNATURES (with confidence levels)
# ============================================================================
PORT_SIGNATURES = {
    DEVICE_CAMERA: {
        "primary": [554, 8554, 37777, 34567],   # RTSP, Dahua, DVR
        "secondary": [80, 443, 8080, 8000, 8888, 9000]  # Web interfaces
    },
    DEVICE_PRINTER: {
        "primary": [9100, 515, 631],  # RAW, LPR, IPP
        "secondary": [80, 443]
    },
    DEVICE_ROUTER: {
        "primary": [53],  # DNS
        "secondary": [80, 443, 8080, 23, 22]
    },
    DEVICE_MEDIA: {
        "primary": [8008, 8443, 9080],  # Chromecast, Roku
        "secondary": [7000, 7100, 1900]
    }
}

# ============================================================================
# SERVICE PATTERNS (mDNS, SSDP, etc.)
# ============================================================================
SERVICE_PATTERNS = {
    DEVICE_CAMERA: {
        "exact": ["_rtsp._tcp", "_nvr._tcp", "_ipcamera", "_axis-video"],
        "partial": ["rtsp", "camera", "surveillance", "dvr", "nvr", "onvif"]
    },
    DEVICE_PHONE: {
        "exact": ["_companion-link", "_apple-mobdev2", "_continuity"],
        "partial": ["airpods", "iphone", "android", "mobile"]
    },
    DEVICE_PC: {
        "exact": ["_smb._tcp", "_afp._tcp", "_rfb._tcp", "_ssh._tcp"],
        "partial": ["workstation", "desktop", "laptop", "windows", "macos"]
    },
    DEVICE_MEDIA: {
        "exact": ["_googlecast._tcp", "_airplay._tcp", "_raop._tcp", "_spotify-connect"],
        "partial": ["chromecast", "roku", "plex", "dlna", "upnp:mediarenderer"]
    },
    DEVICE_PRINTER: {
        "exact": ["_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp"],
        "partial": ["printer", "print", "scanner", "fax"]
    },
    DEVICE_IOT: {
        "exact": ["_hap._tcp", "_homekit", "_hue._tcp", "_matter._tcp"],
        "partial": ["homekit", "hue", "smart", "zigbee", "zwave"]
    },
    DEVICE_ROUTER: {
        "exact": ["_dns._udp"],
        "partial": ["gateway", "router", "upnp:internetgateway"]
    }
}

# ============================================================================
# HOSTNAME PATTERNS
# ============================================================================
HOSTNAME_PATTERNS = {
    DEVICE_CAMERA: ["cam", "camera", "ipcam", "dvr", "nvr", "hikvision", "dahua"],
    DEVICE_PHONE: [
        "iphone", "ipad", "galaxy", "pixel", "android", "oneplus", "xiaomi",
        "redmi", "poco", "realme", "oppo", "vivo", "huawei", "samsung",
        "sm-", "gt-", "moto", "nokia", "lg-", "htc", "zte", "lenovo-",
        "mi-", "note", "pro-", "max-", "lite-"  # Common phone model patterns
    ],
    DEVICE_PC: [
        "desktop", "laptop", "pc", "macbook", "imac", "workstation", "windows",
        "thinkpad", "latitude", "pavilion", "inspiron", "xps", "surface",
        "mac-", "macmini", "laptop-", "desktop-", "pc-", "computer",
        "dell", "hp", "lenovo", "asus", "acer", "msi"
    ],
    DEVICE_ROUTER: ["router", "gateway", "modem", "ap-", "access-point", "wifi"],
    DEVICE_MEDIA: ["tv", "roku", "firestick", "chromecast", "appletv", "sonos", "xbox", "playstation"],
    DEVICE_IOT: ["hue", "nest", "ring", "echo", "alexa", "smartthings", "sensor"],
    DEVICE_PRINTER: ["printer", "epson", "canon", "hp-", "brother", "xerox"]
}

# ============================================================================
# OS FINGERPRINT PATTERNS
# ============================================================================
OS_PATTERNS = {
    DEVICE_PC: ["windows", "win10", "win11", "macos", "darwin", "linux", "ubuntu"],
    DEVICE_PHONE: ["ios", "iphone os", "android", "cfnetwork"],
    DEVICE_ROUTER: ["routeros", "openwrt", "ddwrt", "tomato", "asuswrt"],
    DEVICE_IOT: ["freertos", "lwip", "esp8266", "esp32", "tuya"]
}

# Icons for display
DEVICE_ICONS = {
    DEVICE_ROUTER: "🌐",
    DEVICE_PC: "💻",
    DEVICE_PHONE: "📱",
    DEVICE_TABLET: "📱",
    DEVICE_IOT: "🏠",
    DEVICE_MEDIA: "📺",
    DEVICE_PRINTER: "🖨️",
    DEVICE_CAMERA: "📷",
    DEVICE_UNKNOWN: "❓"
}

DEVICE_LABELS = {
    DEVICE_ROUTER: "Router",
    DEVICE_PC: "PC",
    DEVICE_PHONE: "Phone",
    DEVICE_TABLET: "Tablet",
    DEVICE_IOT: "IoT",
    DEVICE_MEDIA: "Media",
    DEVICE_PRINTER: "Printer",
    DEVICE_CAMERA: "Camera",
    DEVICE_UNKNOWN: "Unknown"
}


class ClassificationResult:
    """Holds classification result with confidence."""
    def __init__(self, device_type, confidence, signals):
        self.device_type = device_type
        self.confidence = confidence  # 0-100
        self.signals = signals  # List of matched signals
    
    def __repr__(self):
        return f"{self.device_type} ({self.confidence}%)"


def classify_device(device):
    """
    Advanced multi-signal classification with confidence scoring.
    
    Returns: ClassificationResult with device_type, confidence (0-100), and signals
    """
    scores = {
        DEVICE_ROUTER: 0,
        DEVICE_PC: 0,
        DEVICE_PHONE: 0,
        DEVICE_IOT: 0,
        DEVICE_MEDIA: 0,
        DEVICE_PRINTER: 0,
        DEVICE_CAMERA: 0,
    }
    
    signals_matched = {dtype: [] for dtype in scores}
    
    # Normalize inputs
    vendor = (device.vendor or "").lower()
    services = " ".join(device.services).lower()
    hostnames = " ".join(device.hostnames).lower()
    os_guess = (device.os_guess or "").lower()
    ip = device.ip or ""
    
    # Extract open ports from services (if port scanning was done)
    open_ports = []
    for svc in device.services:
        if svc.startswith("Port:"):
            try:
                port = int(svc.split(":")[1].split("(")[0])
                open_ports.append(port)
            except:
                pass
    
    # ========================================================================
    # SIGNAL 0: Random MAC Detection (Strong phone/tablet indicator)
    # ========================================================================
    mac = device.mac or ""
    if is_random_mac(mac):
        # Random MAC = Almost certainly a phone or tablet
        scores[DEVICE_PHONE] += WEIGHT_RANDOM_MAC
        signals_matched[DEVICE_PHONE].append("random_mac")
        
        # If also no open ports, even more likely mobile device
        if len(open_ports) == 0:
            scores[DEVICE_PHONE] += WEIGHT_NO_PORTS
            signals_matched[DEVICE_PHONE].append("no_open_ports")
    
    # ========================================================================
    # SIGNAL 1: Vendor matching
    # ========================================================================
    for device_type, patterns in VENDOR_PATTERNS.items():
        # Exact matches (high confidence)
        for pattern in patterns.get("exact", []):
            if pattern in vendor:
                scores[device_type] += WEIGHT_VENDOR_EXACT
                signals_matched[device_type].append(f"vendor:{pattern}")
                break
        
        # Partial matches (medium confidence)
        for pattern in patterns.get("partial", []):
            if pattern in vendor:
                scores[device_type] += WEIGHT_VENDOR_PARTIAL
                signals_matched[device_type].append(f"vendor_partial:{pattern}")
                break
    
    # ========================================================================
    # SIGNAL 2: Port signatures
    # ========================================================================
    for device_type, ports in PORT_SIGNATURES.items():
        # Primary ports (strong indicator)
        for port in ports.get("primary", []):
            if port in open_ports:
                scores[device_type] += WEIGHT_PORT_PRIMARY
                signals_matched[device_type].append(f"port_primary:{port}")
        
        # Secondary ports (supporting indicator)
        for port in ports.get("secondary", []):
            if port in open_ports:
                scores[device_type] += WEIGHT_PORT_SECONDARY
                signals_matched[device_type].append(f"port_secondary:{port}")
    
    # ========================================================================
    # SIGNAL 3: Service patterns
    # ========================================================================
    for device_type, patterns in SERVICE_PATTERNS.items():
        # Exact service matches
        for pattern in patterns.get("exact", []):
            if pattern in services:
                scores[device_type] += WEIGHT_SERVICE_EXACT
                signals_matched[device_type].append(f"service:{pattern}")
        
        # Partial service matches
        for pattern in patterns.get("partial", []):
            if pattern in services:
                scores[device_type] += WEIGHT_SERVICE_PARTIAL
                signals_matched[device_type].append(f"service_partial:{pattern}")
    
    # ========================================================================
    # SIGNAL 4: Hostname patterns (also check in services for Windows names)
    # ========================================================================
    # Combine hostnames and services for pattern matching
    # Exclude "Net:" tags from affecting classification
    filtered_services = " ".join([s for s in device.services if not s.lower().startswith("net:")])
    all_names = hostnames + " " + filtered_services.lower()
    
    # Definitive hostname patterns that strongly indicate device type
    DEFINITIVE_PATTERNS = {
        DEVICE_PC: ["laptop-", "desktop-", "pc-", "macbook", "thinkpad", "surface"],
        DEVICE_PHONE: ["iphone", "galaxy", "pixel", "redmi", "xiaomi", "oneplus", "poco"],
    }
    
    # Check definitive patterns first (high weight)
    for device_type, patterns in DEFINITIVE_PATTERNS.items():
        for pattern in patterns:
            if pattern in all_names:
                scores[device_type] += WEIGHT_HOSTNAME_DEFINITIVE
                signals_matched[device_type].append(f"hostname_definitive:{pattern}")
                break
    
    # Then check regular patterns
    for device_type, patterns in HOSTNAME_PATTERNS.items():
        for pattern in patterns:
            if pattern in all_names:
                scores[device_type] += WEIGHT_HOSTNAME
                signals_matched[device_type].append(f"hostname:{pattern}")
                break
    
    # ========================================================================
    # SIGNAL 5: OS fingerprint
    # ========================================================================
    for device_type, patterns in OS_PATTERNS.items():
        for pattern in patterns:
            if pattern in os_guess:
                scores[device_type] += WEIGHT_OS_HINT
                signals_matched[device_type].append(f"os:{pattern}")
                break
    
    # ========================================================================
    # SIGNAL 6: IP-based heuristics
    # ========================================================================
    if ip and (ip.endswith('.1') or ip.endswith('.254')):
        scores[DEVICE_ROUTER] += WEIGHT_GATEWAY_IP
        signals_matched[DEVICE_ROUTER].append("ip:gateway")
    
    # ========================================================================
    # CAMERA-SPECIFIC: Enhanced detection
    # ========================================================================
    # If RTSP port is open, strong camera indicator
    if 554 in open_ports or 8554 in open_ports:
        scores[DEVICE_CAMERA] += 20  # Bonus for RTSP
        signals_matched[DEVICE_CAMERA].append("rtsp_port_open")
    
    # Camera-specific service markers
    if "camera_detected" in services:
        scores[DEVICE_CAMERA] += 25
        signals_matched[DEVICE_CAMERA].append("camera_marker")
    
    # ========================================================================
    # CALCULATE CONFIDENCE
    # ========================================================================
    # Find the highest scoring type
    max_score = max(scores.values())
    
    if max_score == 0:
        return ClassificationResult(DEVICE_UNKNOWN, 0, [])
    
    # Get the winning device type
    winning_type = max(scores.items(), key=lambda x: x[1])[0]
    
    # Calculate confidence (normalized to 0-100)
    # We use a calibrated formula: more signals = higher confidence
    num_signals = len(signals_matched[winning_type])
    
    # Base confidence from score (max ~60%)
    base_confidence = min(max_score / 1.5, 60)
    
    # Signal count bonus (up to 30%)
    signal_bonus = min(num_signals * 8, 30)
    
    # Uniqueness bonus: if winner is clearly ahead (up to 10%)
    second_best = sorted(scores.values(), reverse=True)[1] if len(scores) > 1 else 0
    uniqueness = (max_score - second_best) / max(max_score, 1) * 10
    
    confidence = int(min(base_confidence + signal_bonus + uniqueness, 99))
    
    return ClassificationResult(
        winning_type,
        confidence,
        signals_matched[winning_type]
    )


def get_device_icon(device_type):
    """Get emoji icon for device type."""
    return DEVICE_ICONS.get(device_type, DEVICE_ICONS[DEVICE_UNKNOWN])


def get_device_label(device_type):
    """Get text label for device type."""
    return DEVICE_LABELS.get(device_type, DEVICE_LABELS[DEVICE_UNKNOWN])


def get_confidence_label(confidence):
    """Get human-readable confidence label."""
    if confidence >= 80:
        return "HIGH"
    elif confidence >= 60:
        return "MEDIUM"
    elif confidence >= 40:
        return "LOW"
    else:
        return "UNCERTAIN"


def is_camera_confident(device, threshold=70):
    """
    Check if device is classified as camera with high confidence.
    Used for privacy alerts - only alert if confidence >= threshold.
    """
    result = classify_device(device)
    return result.device_type == DEVICE_CAMERA and result.confidence >= threshold
