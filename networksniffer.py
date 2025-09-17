from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime, timedelta
import logging
from collections import defaultdict, deque
import threading
import time
import plotly.graph_objs as go
from plotly.subplots import make_subplots
import dash
from dash import dcc, html
from dash.dependencies import Input, Output

# ================= Logging Setup =================
logging.basicConfig(filename="captured_packets.log", level=logging.INFO, format="%(message)s")
alert_logger = logging.getLogger("alerts")
alert_handler = logging.FileHandler("alerts.log")
alert_logger.addHandler(alert_handler)

# ================= Stats Tracking =================
packet_count = 0
protocol_counts = defaultdict(int)
ip_activity = defaultdict(list)
ip_counter = defaultdict(int)

# For charting (last 60 seconds of packets/sec)
time_window = 60
pps_tcp = deque([0] * time_window, maxlen=time_window)
pps_udp = deque([0] * time_window, maxlen=time_window)
pps_icmp = deque([0] * time_window, maxlen=time_window)
pps_total = deque([0] * time_window, maxlen=time_window)
timestamps = deque([i for i in range(-time_window + 1, 1)], maxlen=time_window)

last_second = int(time.time())
temp_counts = defaultdict(int)

# Alert thresholds
MAX_PACKETS_PER_IP = 500
lock = threading.Lock()

# ================= Alert System =================
def trigger_alert(message):
    alert_msg = f"[ALERT] {datetime.now()} - {message}"
    print(f"\033[91m{alert_msg}\033[0m")  # red text in console
    alert_logger.warning(alert_msg)

# ================= Packet Handler =================
def packet_callback(packet):
    global packet_count, last_second, temp_counts
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

        now = int(time.time())
        with lock:
            packet_count += 1
            protocol_counts[protocol] += 1
            ip_counter[ip_src] += 1
            ip_activity[ip_src].append(datetime.now())
            temp_counts[protocol] += 1
            temp_counts["TOTAL"] += 1

        # Logging
        log_msg = f"{datetime.now()} - Protocol: {protocol} | Source: {ip_src}:{src_port} -> Destination: {ip_dst}:{dst_port}"
        logging.info(log_msg)

        # Flood detection
        one_minute_ago = datetime.now() - timedelta(seconds=60)
        ip_activity[ip_src] = [t for t in ip_activity[ip_src] if t > one_minute_ago]
        if len(ip_activity[ip_src]) > MAX_PACKETS_PER_IP:
            trigger_alert(f"Potential Flood from {ip_src} - {len(ip_activity[ip_src])} packets in last 60s")

        # Milestone alerts
        if packet_count % 50000 == 0:
            trigger_alert(f"Milestone Reached: {packet_count} packets processed")

        # Update counters per second
        if now != last_second:
            with lock:
                pps_tcp.append(temp_counts.get("TCP", 0))
                pps_udp.append(temp_counts.get("UDP", 0))
                pps_icmp.append(temp_counts.get("ICMP", 0))
                pps_total.append(temp_counts.get("TOTAL", 0))
                timestamps.append(timestamps[-1] + 1)

                temp_counts.clear()
                last_second = now

# ================= Dash Web Dashboard =================
app = dash.Dash(__name__)
app.layout = html.Div([
    html.H1("Real-Time Network Traffic Monitor"),
    dcc.Interval(id="interval", interval=1000, n_intervals=0),
    dcc.Graph(id="line-chart"),

    dcc.Graph(id="pie-chart")
])

@app.callback(
    [Output("line-chart", "figure"),
     Output("pie-chart", "figure")],
    [Input("interval", "n_intervals")]
)
def update_charts(n):
    with lock:
        x = list(timestamps)
        tcp = list(pps_tcp)
        udp = list(pps_udp)
        icmp = list(pps_icmp)
        total = list(pps_total)
        proto_dist = dict(protocol_counts)

    
    fig_line = go.Figure()
    fig_line.add_trace(go.Scatter(x=x, y=tcp, mode="lines+markers", name="TCP"))
    fig_line.add_trace(go.Scatter(x=x, y=udp, mode="lines+markers", name="UDP"))
    fig_line.add_trace(go.Scatter(x=x, y=icmp, mode="lines+markers", name="ICMP"))
    fig_line.add_trace(go.Scatter(x=x, y=total, mode="lines+markers", name="TOTAL", line=dict(width=3)))

    fig_line.update_layout(
        title="Packets per Second (Last 60s)",
        xaxis_title="Time (s)",
        yaxis_title="Packets/sec",
        hovermode="x unified"
    )
    labels = list(proto_dist.keys())
    values = list(proto_dist.values())
    fig_pie = go.Figure(data=[go.Pie(labels=labels, values=values, hole=0.3)])
    fig_pie.update_layout(title="Protocol Distribution")

    return fig_line, fig_pie

def run_dashboard():
    app.run(debug=False, port=8050, use_reloader=False)

threading.Thread(target=run_dashboard, daemon=True).start()

packet_filter = "ip or tcp or udp or icmp"
print("[*] Starting packet capture with interactive dashboard at http://127.0.0.1:8050 ...")
sniff(filter=packet_filter, prn=packet_callback, store=0)
