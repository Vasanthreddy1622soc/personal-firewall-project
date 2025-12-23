# rules.py

# Blocked IP addresses
BLOCKED_IPS = [
    "192.168.1.100",
    "10.10.10.10"
]

# Blocked destination ports
BLOCKED_PORTS = [
    23,     # Telnet
    445     # SMB
]

# Allowed protocols
ALLOWED_PROTOCOLS = ["TCP", "UDP"]
