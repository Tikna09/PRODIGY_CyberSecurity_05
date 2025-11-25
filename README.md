# Network Packet Analyzer 
The Packet Sniffer project is a Python-based tool designed to capture and analyze network traffic in real time. The sniffer listens to packets traveling through the computer’s network interface (Wi-Fi) and extracts important details such as protocol type, IP addresses, port numbers, and payload data. This helps visualize how devices communicate over a network and how data moves between a source and destination.

# How the Tool Works
* Packet Capturing
The tool uses the Scapy library to listen to all incoming and outgoing IP packets.
Each time a packet is detected, Scapy sends it to the packet_callback() function for analysis.

Protocol Identification
The sniffer identifies whether the captured packet is TCP, UDP, ICMP, or another IP-based protocol by checking the protocol number inside the IP header.

Header Extraction
For every packet, the tool extracts:

Source IP address

Destination IP address

Source port (for TCP/UDP)

Destination port (for TCP/UDP)

Payload Capture
If the packet contains raw data, the sniffer extracts a preview of the payload and prints it in the terminal.

Saving Data
When the program is stopped (Ctrl + C), all captured packets are automatically saved into a captured_data.pcap file.
This file can be opened in Wireshark for professional packet analysis.
