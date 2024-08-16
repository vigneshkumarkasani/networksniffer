

Basic Network Sniffer
This project is an advanced network sniffer built using Python and the scapy library. It captures, analyzes, and logs network traffic, providing insights into the flow of data within a network.

Features
Protocol Filtering: Captures only IP, TCP, UDP, and ICMP packets.
Packet Parsing: Extracts and displays source and destination IP addresses, ports, and protocol type.
Live Summary: Prints a real-time summary of captured packets.
File Logging: Logs captured packet details to a file (captured_packets.log) with timestamps for later analysis.
Requirements
Python 3.x
scapy library
Installation
Clone the Repository:

bash
Copy code
git clone https://github.com/yourusername/advanced-network-sniffer.git
cd advanced-network-sniffer
Install Dependencies:

bash
Copy code
pip install scapy
Usage
Run the Sniffer:

Ensure you have administrator privileges, as packet sniffing requires elevated permissions.

bash
Copy code
sudo python3 advanced_network_sniffer.py
Captured Packets:

The details of each captured packet are printed to the console and logged to the captured_packets.log file.
