from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap  # pyright: ignore[reportMissingImports]
# Notice: 'wrpcap' has been added

def packet_callback(packet):
    """Processes each captured packet and displays details."""
    if IP in packet:
        ip_layer = packet[IP]
        
        protocol_name = ""
        protocol_number = ip_layer.proto
        
        if protocol_number == 6:
            protocol_name = "TCP"
        elif protocol_number == 17:
            protocol_name = "UDP"
        elif protocol_number == 1:
            protocol_name = "ICMP"
        else:
            protocol_name = f"Protocol {protocol_number}"

        print("-" * 50)
        print(f"** Protocol: {protocol_name} **")
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")

        # Extract port information for TCP/UDP
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")

        # Extract payload (Raw Data)
        if Raw in packet:
            payload_data = packet[Raw].load
            print(f"Payload (Partial): {str(payload_data)[:50]}...")

def main():
    """Starts the packet sniffing process."""
    print("[*] Starting packet sniffer. Press Ctrl+C to stop.")
    
    # Filter for common web/DNS traffic
    traffic_filter = "ip"
    
    # 🎯 Set interface to "Wi-Fi" (based on your ipconfig output)
    interface_name = "Wi-Fi" 

    # Start sniffing with the interface and filter applied
    captured_packets = sniff(iface=interface_name, filter=traffic_filter, prn=packet_callback, store=1)
    
    # Action B: Write stored packets to a file when sniffing stops
    filename = "captured_data.pcap"
    wrpcap(filename, captured_packets)
    print(f"\n[*] Sniffing stopped. Saved {len(captured_packets)} packets to {filename}") 

if __name__ == "__main__":
    main()
