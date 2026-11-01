"""
Centralized Configuration for NIDS Engine.
Decouples detection rules, thresholds, and file paths from packet capture loops.
"""

# Sliding-window inspection settings
TIME_WINDOW = 5.0             # Rolling evaluation window (seconds)
SCAN_THRESHOLD = 15           # Unique destination ports probed within TIME_WINDOW
ALERT_COOLDOWN = 10.0         # Suppression interval for duplicate IP alerts (seconds)
IP_INACTIVITY_TIMEOUT = 30.0  # Time before an idle IP is purged from memory (seconds)

# Serialization & Storage
STATE_FILE = "metrics.json"
SCHEMA_VERSION = "1.0.0"

# Network Capture Rules
# Setting to None allows Scapy to automatically bind to your active gateway interface
CAPTURE_INTERFACE = None
BPF_FILTER = "ip and (tcp or udp or icmp)"