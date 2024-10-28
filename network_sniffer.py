from scapy.all import sniff, IP, TCP, UDP, wrpcap

packets = []

def packet_callback(packet):
    packets.append(packet)
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"Source: {ip_src}, Destination: {ip_dst}")

        if packet.haslayer(TCP):
            print(f"TCP Packet: {packet[TCP].sport} -> {packet[TCP].dport}")

# Capture de paquets et enregistrement
sniff(prn=packet_callback, count=10)

# Sauvegarder les paquets capturés
wrpcap('captured_packets.pcap', packets)
