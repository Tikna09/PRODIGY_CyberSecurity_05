l# Network Packet Analyzer 
The Packet Sniffer project is a Python-based tool designed to capture and analyze network traffic in real time. The sniffer listens to packets traveling through the computer’s network interface (Wi-Fi) and extracts important details such as protocol type, IP addresses, port numbers, and payload data. This helps visualize how devices communicate over a network and how data moves between a source and destination.

# How the Tool Works

**Packet Capturing**
* The tool uses the Scapy library to listen to all incoming and outgoing IP packets.
Each time a packet is detected, Scapy sends it to the packet_callback() function for analysis.

**Protocol Identification**
* The sniffer identifies whether the captured packet is TCP, UDP, ICMP, or another IP-based protocol by checking the protocol number inside the IP header.

**Header Extraction**
* For every packet, the tool extracts:
* Source IP address
* Destination IP address
* Source port (for TCP/UDP)
* Destination port (for TCP/UDP)

**Payload Capture**
* If the packet contains raw data, the sniffer extracts a preview of the payload and prints it in the terminal.

**Saving Data**
* When the program is stopped (Ctrl + C), all captured packets are automatically saved into a captured_data.pcap file.
This file can be opened in Wireshark for professional packet analysis.

# What the Screenshots Show
* **Screenshot 1 — Sniffer Code (VS Code)**
<img width="959" height="562" alt="Screenshot 2025-11-26 045652" src="https://github.com/user-attachments/assets/2b5fa230-54cb-49b3-b487-862d5e16da93" />
* This screenshot displays the Python code used to build the sniffer. It shows the logic for identifying protocols, extracting header information, and printing packet details.



* **Screenshot 2 — Live Packet Capture Output**
<img width="959" height="564" alt="Screenshot 2025-11-26 045800" src="https://github.com/user-attachments/assets/49a9988a-98f5-4830-a8c4-f2b8dcc39bb3" />
* This screenshot shows the sniffer running in the VS Code terminal.
* You can see real packets being captured, including:
* TCP packets going to port 443 (HTTPS)
* UDP packets with payload data
* Source and destination IP addresses
* Port numbers for each packet
* This demonstrates the sniffer working correctly in real time.

# Conclusion
* This project demonstrates how network monitoring tools work at a basic level.
By capturing live traffic, identifying protocol types, and analyzing packet content, the sniffer shows how data moves across a network. It also highlights why security measures like encryption (HTTPS) are important for protecting sensitive information from being exposed.
