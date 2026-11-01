from scapy.all import sniff, IP, TCP, UDP, ICMP

PACKET_LIMIT = 15


def packet_callback(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        proto = "OTHER"

        if packet.haslayer(TCP):
            proto = f"TCP (Port {packet[TCP].sport} -> {packet[TCP].dport})"
        elif packet.haslayer(UDP):
            proto = f"UDP (Port {packet[UDP].sport} -> {packet[UDP].dport})"
        elif packet.haslayer(ICMP):
            proto = "ICMP (Ping)"

        print(f"[+] Captured: {src} -> {dst} | Protocol: {proto}")


def main():
    print("=" * 60)
    print(" [*] Listening for raw network frames...")
    print(f" [*] Capturing first {PACKET_LIMIT} packets...")
    print("=" * 60)

    # Sniffs packets on your default active network interface
    sniff(prn=packet_callback, count=PACKET_LIMIT, store=0)
    print("\n[✓] Packet capture functional!")


if __name__ == "__main__":
    main()