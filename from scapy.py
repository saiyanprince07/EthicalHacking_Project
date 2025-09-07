from scapy.all import sniff, TCP, IP, ARP

# Function to analyze each packet
def analyze_packet(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"[IP] {ip_src} -> {ip_dst}")

    if packet.haslayer(TCP) and packet.haslayer("Raw"):
        payload = packet["Raw"].load.decode(errors="ignore")
        if "password" in payload.lower():
            print(f"[ALERT] Possible credential leak: {payload}")

    if packet.haslayer(ARP):
        print(f"[ARP] {packet[ARP].psrc} is asking about {packet[ARP].pdst}")

# Start sniffing
print("[*] Starting packet capture...")
sniff(prn=analyze_packet, count=20)  # capture 20 packets
