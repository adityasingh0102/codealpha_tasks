
from datetime import datetime
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Raw

PACKET_LIMIT = 25


def analyze_packet(packet):
    # Source aur destination IP
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif IPv6 in packet:
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
    else:
        src_ip = dst_ip = "N/A"

    # Protocol aur ports
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
        src_port = dst_port = "N/A"
    else:
        protocol = "Other"
        src_port = dst_port = "N/A"

    print("\n" + "-" * 45)
    print("Time      :", datetime.now().strftime("%H:%M:%S"))
    print("Protocol  :", protocol)
    print("Source IP :", src_ip)
    print("Dest IP   :", dst_ip)
    print("Source port:", src_port)
    print("Dest port :", dst_port)
    print("Size      :", len(packet), "bytes")

    # Limited payload preview
    if Raw in packet:
        data = bytes(packet[Raw].load)[:40]
        preview = "".join(
            chr(b) if 32 <= b <= 126 else "."
            for b in data
        )
        print("Payload preview:", repr(preview))


def main():
    print("Basic Network Sniffer started")
    print("Capturing up to", PACKET_LIMIT, "packets.")
    print("Use only on networks you are authorized to inspect.")

    try:
        sniff(
            prn=analyze_packet,
            count=PACKET_LIMIT,
            store=False
        )
        print("\nCapture complete.")

    except KeyboardInterrupt:
        print("\nCapture stopped.")

    except Exception as error:
        print("\nCapture error:", error)
        print("Check permissions, Npcap and Scapy installation.")


if __name__ == "__main__":
    main()
