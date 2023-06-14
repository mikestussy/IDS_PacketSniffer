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

#Function for IP filtering
filterIPS = False #bool for ip filtering option
filterPORTS = False #bool for port filtering from src

def read_filter_ips():
    with open('ipfilter.txt', 'r') as f:
        return [line.strip() for line in f.readlines()]
filter_ips = read_filter_ips()
if "#FILTER SRC IP: ON" in filter_ips:
    filterIPS = True
if "#FILTER PORTS: ON" in filter_ips:
    filterPORTS = True

if filterIPS == False:
    if filterPORTS == False:
        print(f"\033[37mPort Filtering:\033[0m", f"\033[31m OFF\033[0m")
        print(f"\033[37mIP Filtering:\033[0m", f"\033[31m OFF\033[0m")

if filterIPS == False:
    if filterPORTS == True:
        print(f"\033[37mPort Filtering:\033[0m", f"\033[34m ON\033[0m")
        print(f"\033[37mIP Filtering:\033[0m", f"\033[31m OFF\033[0m")

if filterIPS == True:
    if filterPORTS == False:
        print(f"\033[37mPort Filtering:\033[0m", f"\033[31m OFF\033[0m")
        print(f"\033[37mIP Filtering:\033[0m", f"\033[34m ON\033[0m")

if filterIPS == True:
    if filterPORTS == True:
        print(f"\033[37mPort Filtering:\033[0m", f"\033[34m ON\033[0m")
        print(f"\033[37mIP Filtering:\033[0m", f"\033[34m ON\033[0m")

# Function to handle packets captured
def packet_handler(packet):
    source_ip = None
    source_port = None

##CONDITIONS FOR IP CHECKING/FILTERING##
    ##IF PORT AND IP FILTERING IS ON
    if filterIPS:
        if filterPORTS:
            if packet.haslayer(IP):
                source_ip = packet[IP].src
                if packet.haslayer(TCP):
                    source_port = packet[TCP].sport
                    if source_ip in filter_ips:
                        if str(source_port) in filter_ips:
                            bruteforce_detection(packet)
                            ddos_detection(packet)
                            print(time.strftime('%H:%M:%S'), packet.summary(),source_ip, ":", source_port, " >> ", packet[IP].dst,":",packet[UDP].dport)
                if packet.haslayer(UDP):
                    source_port = packet[UDP].sport
                    if source_ip in filter_ips:
                        if str(source_port) in filter_ips:
                            bruteforce_detection(packet)
                            ddos_detection(packet)
                            print(time.strftime('%H:%M:%S'), packet.summary(),source_ip, ":", source_port, " >> ", packet[IP].dst,":",packet[UDP].dport)

    ##IF PORT FILTERING ON AND IP FILTERING IS OFF
    if filterIPS == False:
        if filterPORTS:
            if packet.haslayer(IP):
                source_ip = packet[IP].src
                if packet.haslayer(TCP):
                    source_port = packet[TCP].sport
                if packet.haslayer(UDP):
                    source_port = packet[UDP].sport
                if str(source_port) in filter_ips:
                    bruteforce_detection(packet)
                    ddos_detection(packet)
                    print(time.strftime('%H:%M:%S'), packet.summary())

    ##IF PORT FILTER OFF AND IP FILTERING IS ON
    if filterIPS and filterPORTS == False:
        if packet.haslayer(IP):
            source_ip = packet[IP].src
            if source_ip in filter_ips:
                bruteforce_detection(packet)
                ddos_detection(packet)
                print(time.strftime('%H:%M:%S'), packet.summary())

    ## IF NEITHER ARE ON, FILTER IS OFF
    if filterIPS == False:
        if filterPORTS == False:
            bruteforce_detection(packet)
            ddos_detection(packet)
            print(time.strftime('%H:%M:%S'), packet.summary())


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
