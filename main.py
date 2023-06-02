from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.inet import TCP
from scapy.sendrecv import sniff
from scapy.layers.http import HTTP
import socket
import time

failed_logins = {}

#Intrusion Detection Functions
def ddos_detection(packet):
    if packet.haslayer(TCP):
        # Check if packet is part of a DDOS attack
        if packet[TCP].flags & 0x003f == 0x003f:
            # Alert on potential DDOS attack and flag packet in red
            print(f"\033[91mDDOS attack detected:\033[0m {packet.summary()}")

            # Save packet to file
            with open("ddos_packets.txt", "a") as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {packet.summary()}\n")
                f.write("\n")

    elif packet.haslayer(UDP):
        # Check if packet is part of a DDOS attack
        if packet.getlayer(UDP).len > 120:
            print("\033[93mUDP packet length is long.\033[0m")
            # Frequency Analysis for DDOS Reporting --
            # Count the number of UDP packets received in the last second
            current_time = time.time()
            packet_handler.last_time = current_time
            packet_handler.udp_packet_count = 0
            if current_time - packet_handler.last_time > 1:
                packet_handler.udp_packet_count = 1
            else:
                packet_handler.udp_packet_count += 1
            # Trigger an alert if the UDP packet rate exceeds a certain threshold
            if packet_handler.udp_packet_count > 100:
                print("\033[91mUDP packet rate is too high!\033[0m")
                # Alert on potential DDOS attack and flag packet in red
                print(f"\033[91mDDOS attack detected:\033[0m {packet.summary()}")
                with open("ddos_packets.txt", "a") as f:
                    f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {packet.summary()}\n")
                    f.write("\n")

    elif ICMP in packet:
        # Check if packet is part of a DDOS attack
        if packet[ICMP].type == 8 and packet[ICMP].code == 0:
            # Alert on potential DDOS attack and flag packet in red
            print(f"\033[91mDDOS attack detected:\033[0m {packet.summary()}")
            with open("ddos_packets.txt", "a") as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {packet.summary()}\n")
                f.write("\n")

def bruteforce_detection(packet):
    global failed_logins
    source_ip = None
    if TCP in packet:
        if packet[TCP].dport == 22 and packet[TCP].flags & 0x002 == 0x002:
        # Increment the count of failed login attempts for this source IP address
            source_ip = packet[IP].src
            if source_ip in packet_handler.failed_logins:
                failed_logins[source_ip] += 1
        else:
            failed_logins[source_ip] = 1

        # Trigger an alert if the number of failed login attempts exceeds a certain threshold
        if failed_logins[source_ip] > 10:
            print(f"\033[91mBrute force attack detected from {source_ip}!\033[0m")
            with open("bruteforce_detections.txt", "a") as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {packet.summary()}\n")
                f.write("\n")

# Function to handle packets captured
def packet_handler(packet):
    bruteforce_detection(packet)
    ddos_detection(packet)
    print(packet.summary())

# Prompt for filter
protocol = input("Enter protocol (TCP, UDP, ICMP, HTTP, or all): ")
if protocol == "TCP":
    protocol = "tcp"
elif protocol == "UDP":
    protocol = "udp"
elif protocol == "all":
    protocol = ""
elif protocol == "ICMP":
    protocol = "icmp"
elif protocol == "HTTP":
    protocol = "http"
else:
    print("Invalid protocol specified.")
    exit()

#Sniffing loop/function
sniff(filter=protocol, prn=packet_handler)
