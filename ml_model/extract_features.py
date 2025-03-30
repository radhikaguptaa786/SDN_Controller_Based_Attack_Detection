import pandas as pd
import numpy as np
from scapy.all import *
import socket
import struct
from collections import defaultdict
import time
# ===========================
# 🚀 FUNCTION TO CONVERT IP TO NUMERIC
# ===========================
def ip_to_int(ip):
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except socket.error:
        return 0  # Return 0 for invalid/missing IPs

# ===========================
# 🚀 FUNCTION TO IDENTIFY PROTOCOL TYPE
# ===========================
def get_protocol(pkt):
    if TCP in pkt:
        if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
            return "HTTP"
        elif pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
            return "HTTPS"
        return "TCP"
    elif UDP in pkt:
        return "UDP"
    return "OTHER"


# Dictionary to track flow statistics
flows = defaultdict(lambda: {"timestamps": [], "packet_sizes": []})

# ===========================
# 🚀 FUNCTION TO EXTRACT FEATURES FROM PACKETS
# ===========================
def extract_features(pkt):
           
        features= {
            "proto":'',
            "sport": 0, "dport": 0,
            "state_number": 0,
            "mean": 0, "stddev": 0, "min": len(pkt), "max": len(pkt),
            "saddr": "", "daddr": "",
            "srate": 0, "drate": 0,
            "N_IN_Conn_P_SrcIP": 0, "N_IN_Conn_P_DstIP": 0,
            "attack": 0, "category": "normal","subcategory": "tcp"
        }

        if IP in pkt:
            features["saddr"] = pkt[IP].src
            features["daddr"] = pkt[IP].dst

        if TCP in pkt or UDP in pkt:
            proto = "tcp" if TCP in pkt else "udp"
            features["sport"] = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport
            features["dport"] = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport

        # Determine port category
        if features["dport"] in [80, 443, 8080]:
            port_type = "http"
        elif TCP in pkt:
            port_type = "tcp"
        elif UDP in pkt:
            port_type = "udp"
        else:
            port_type = "unknown"

        features['proto']=port_type
        features["state_number"] = {"tcp": 1, "udp": 2, "http": 3}.get(port_type, 0)

        # Update flow statistics
        key = (features["saddr"], features["daddr"], features["sport"], features["dport"])
        flows[key]["timestamps"].append(time.time())
        flows[key]["packet_sizes"].append(len(pkt))
        flows[key]["unique_dests"].add(features["daddr"])

        # Keep only last 100 packets (rolling window)
        if len(flows[key]["timestamps"]) > 100:
            flows[key]["timestamps"].pop(0)
            flows[key]["packet_sizes"].pop(0)

        # Compute statistics
        features["mean"] = np.mean(flows[key]["packet_sizes"])
        features["stddev"] = np.std(flows[key]["packet_sizes"])
        features["min"] = np.min(flows[key]["packet_sizes"])
        features["max"] = np.max(flows[key]["packet_sizes"])

        # Compute srate & drate (packets per second)
        time_diff = flows[key]["timestamps"][-1] - flows[key]["timestamps"][0]
        features["srate"] = len(flows[key]["timestamps"]) / time_diff if time_diff > 0 else 0
        features["drate"] = features["srate"]  # Assuming bidirectional flow rate (adjust if needed)

        # Connection tracking
        features["N_IN_Conn_P_SrcIP"] = len(flows[key]["unique_dests"])
        features["N_IN_Conn_P_DstIP"] = len(flows[key]["unique_dests"])

         # Define thresholds
        DOS_THRESHOLD = 100  # More than 100 packets per second → Possible DoS
        DDOS_THRESHOLD = 500  # More than 500 packets per second → Possible DDoS

        # Check for potential DDoS or DoS attack
        if features["srate"] > DDOS_THRESHOLD:
            features["category"] = "DDoS"
        elif features["srate"] > DOS_THRESHOLD:
            features["category"] = "DoS"

        # Assign subcategory based on protocol
        if features["category"] in ["DDoS", "DoS"]:
            if port_type == "http":
                features["subcategory"] = "HTTP"
            elif port_type == "tcp":
                features["subcategory"] = "TCP"
            elif port_type == "udp":
                features["subcategory"] = "UDP"
        # Mark attack flag (1 = attack, 0 = normal)
        features["attack"] = 1 if features["category"] in ["DDoS", "DoS"] else 0

        return features



