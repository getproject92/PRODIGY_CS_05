from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
log_file = f"packet_log_{timestamp}.txt"

with open(log_file, "w") as f:
    f.write("=== Packet Capture Log ===\n")
    f.write(f"Session Start: {datetime.now()}\n\n")

def analyze_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = ""
        payload = ""

        if TCP in packet:
            protocol = "TCP"
            payload = str(bytes(packet[TCP].payload))
        elif UDP in packet:
            protocol = "UDP"
            payload = str(bytes(packet[UDP].payload))
        else:
            protocol = "Other"

        time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{time_now}] Source: {ip_src} | Destination: {ip_dst} | Protocol: {protocol}\n"
        log_entry += f"    Payload: {payload[:100]}...\n\n"
        
        print(log_entry)

        with open(log_file, "a") as f:
            f.write(log_entry)

print("Starting packet capture. Press Ctrl+C to stop.")
sniff(filter="ip", prn=analyze_packet, store=False)
