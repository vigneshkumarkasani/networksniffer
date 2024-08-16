from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import logging
logging.basicConfig(filename="captured_packets.log", level=logging.INFO, format="%(message)s")
def packet_callback(packet):
    protocol = None

    
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            protocol = "ICMP"
            src_port = None
            dst_port = None

        log_msg = f"{datetime.now()} - Protocol: {protocol} | Source: {ip_src}:{src_port} -> Destination: {ip_dst}:{dst_port}"
        
        print(log_msg)
        logging.info(log_msg)
packet_filter = "ip or tcp or udp or icmp"

sniff(filter=packet_filter, prn=packet_callback, store=0)
