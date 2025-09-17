from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime, timedelta
import logging
from collections import defaultdict

# Logging setup
logging.basicConfig(filename="captured_packets.log", level=logging.INFO, format="%(message)s")
alert_logger = logging.getLogger("alerts")
alert_handler = logging.FileHandler("alerts.log")
alert_logger.addHandler(alert_handler)

# Stats tracking
packet_count = 0
protocol_counts = defaultdict(int)
ip_activity = defaultdict(list)  # stores timestamps of packets per IP

# Alert thresholds
MAX_PACKETS_PER_IP = 500   # e.g., if >500 packets from same IP in a minute → alert
PORT_SCAN_THRESHOLD = 50   # if >50 distinct ports accessed by one IP → alert

def trigger_alert(message):
    """Print and log alerts"""
    alert_msg = f"[ALERT] {datetime.now()} - {message}"
    print(f"\033[91m{alert_msg}\033[0m")  # red text for visibility
    alert_logger.warning(alert_msg)

def packet_callback(packet):
    global packet_count
    protocol = None
    src_port, dst_port = None, None

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

        # Update stats
        packet_count += 1
        protocol_counts[protocol] += 1
        ip_activity[ip_src].append(datetime.now())

        # Log every packet
        log_msg = f"{datetime.now()} - Protocol: {protocol} | Source: {ip_src}:{src_port} -> Destination: {ip_dst}:{dst_port}"
        print(log_msg)
        logging.info(log_msg)

        # ---- Real-time ALERT conditions ----
        # 1. Flood detection (too many packets in 60s)
        one_minute_ago = datetime.now() - timedelta(seconds=60)
        ip_activity[ip_src] = [t for t in ip_activity[ip_src] if t > one_minute_ago]
        if len(ip_activity[ip_src]) > MAX_PACKETS_PER_IP:
            trigger_alert(f"Potential Flood from {ip_src} - {len(ip_activity[ip_src])} packets in last 60s")

        # 2. Port scan detection (many unique ports targeted by one IP)
        if protocol in ["TCP", "UDP"]:
            unique_ports = set([p.dport for p in packet.sniffed_sessions()])
            if len(unique_ports) > PORT_SCAN_THRESHOLD:
                trigger_alert(f"Potential Port Scan by {ip_src} - {len(unique_ports)} ports scanned")

        # 3. Milestone alert (every 50K packets)
        if packet_count % 50000 == 0:
            trigger_alert(f"Milestone Reached: {packet_count} packets processed")

# Apply BPF filter for performance
packet_filter = "ip or tcp or udp or icmp"

print("[*] Starting packet capture with real-time alerts...")
sniff(filter=packet_filter, prn=packet_callback, store=0)
