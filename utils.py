
from scapy.config import conf

def get_vendor_mac_lookup(mac):
    """
    Tries to find vendor using Scapy's internal manuf db.
    """
    try:
        # scapy's conf.manufdb is a dict-like object
        # It expects the first 3 bytes usually, but scapy handles it usually.
        # Let's try scapy's internal lookup first
        prefix = mac[:8].upper()
        if prefix in conf.manufdb:
            result = conf.manufdb[prefix]
            # Some versions return a tuple (short_name, full_name)
            if isinstance(result, tuple):
                return result[0] if result[0] else result[1]
            return result
        
        # Fallback or additional lookup could go here, but for now stick to scapy
    except Exception:
        pass
    return "Unknown"
