#!/usr/bin/env python3
"""
CodeAlpha_NetworkSniffer
--------------------------------
Basic Network Sniffer using Scapy

Yeh program network traffic ke packets capture karta hai aur unki
details (source IP, destination IP, protocol, ports, payload) screen
par dikhata hai.

Requirements:
    pip install scapy

IMPORTANT:
    - Isse Administrator / root privileges ke saath chalana padta hai,
      kyunki raw packets capture karne ke liye special permission chahiye.
    - Windows: Command Prompt ko "Run as Administrator" karke chalayein.
    - Linux/Mac: sudo python3 network_sniffer.py
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

# Kitne packets capture karne hain (0 = jab tak manually stop na karein - Ctrl+C)
PACKET_COUNT = 0

# Har protocol number ka naam
PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}


def process_packet(packet):
    """
    Har capture hue packet ko analyze karke uski details print karta hai.
    """
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto_num = ip_layer.proto
        proto_name = PROTOCOL_MAP.get(proto_num, f"Other({proto_num})")

        timestamp = datetime.now().strftime("%H:%M:%S")

        print("=" * 60)
        print(f"[{timestamp}] Packet Captured")
        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")
        print(f"Protocol       : {proto_name}")

        # TCP details
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Source Port    : {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
            print(f"TCP Flags      : {tcp_layer.flags}")

        # UDP details
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Source Port    : {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")

        # ICMP details
        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            print(f"ICMP Type      : {icmp_layer.type}")
            print(f"ICMP Code      : {icmp_layer.code}")

        # Payload (raw data) dikhana, agar available ho
        if Raw in packet:
            payload = packet[Raw].load
            try:
                decoded = payload.decode(errors="replace")
                # Sirf pehle 100 characters dikhayenge taaki screen clutter na ho
                print(f"Payload (partial): {decoded[:100]}")
            except Exception:
                print(f"Payload (raw bytes, {len(payload)} bytes)")

        print("=" * 60 + "\n")


def start_sniffer():
    print("Network Sniffer shuru ho raha hai...")
    print("Ruknay ke liye Ctrl+C dabayein.\n")

    try:
        # filter="ip" sirf IP packets capture karega
        # count=0 ka matlab hai jab tak manually stop na ho
        sniff(
    iface="Intel(R) Wi-Fi 6 AX201 160MHz #2",
    filter="ip",
    prn=process_packet,
    store=False,
    count=PACKET_COUNT
)
    except PermissionError:
        print("Error: Is program ko Administrator/root permissions ke saath chalayein.")
    except KeyboardInterrupt:
        print("\nSniffer band kar diya gaya.")


if __name__ == "__main__":
    start_sniffer()