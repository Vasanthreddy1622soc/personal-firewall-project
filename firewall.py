# firewall.py

from scapy.all import sniff, IP, TCP, UDP
from rules import BLOCKED_IPS, BLOCKED_PORTS
from logger import log_event
from datetime import datetime

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet.proto

        # Block IP rule
        if src_ip in BLOCKED_IPS:
            message = f"BLOCKED IP: {src_ip} -> {dst_ip}"
            print(message)
            log_event(message)
            return

        # Block Port rule
        if TCP in packet:
            if packet[TCP].dport in BLOCKED_PORTS:
                message = f"BLOCKED PORT: {packet[TCP].dport} from {src_ip}"
                print(message)
                log_event(message)
                return

        # Allowed traffic
        print(f"[ALLOWED] {src_ip} -> {dst_ip} | Time: {datetime.now()}")

print("Starting Personal Firewall...")
print("Monitoring network traffic...\n")

sniff(prn=packet_handler, store=False)
