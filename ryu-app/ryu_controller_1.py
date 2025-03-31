from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
import requests
from ryu.app.simple_switch_13 import SimpleSwitch13
from scapy.all import *
import pandas as pd
import sys
import os


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../ml_model")))
from extract_features import extract_features
from ml_model_training_testing import test_model
class SDNFirewall(SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNFirewall, self).__init__(*args, **kwargs)
        # self.dnn_api_url = "http://127.0.0.1:5000/predict"  # Flask API for attack detection
        
    
    
    # ===========================
    # 🚀 PROCESS PCAP FILE & SAVE DATASET
    # ===========================
    def process_pcap(file_path):
        print(f"📡 Processing {file_path}...")

        # Read packets
        packets = rdpcap(file_path)
        return packets
        

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """ Install a default rule to send packets to the controller """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Default rule: Send all packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, buffer_id=ofproto.OFP_NO_BUFFER)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """ Adds a flow rule to the switch, ensuring correct data types. """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Ensure actions is a list
        if not isinstance(actions, list):
            actions = [actions]

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)

        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """ Handle incoming packets and check for attacks """
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)

        if not ip:
            return  # Ignore non-IP packets

         # Extracting features from real-time network packet
        pcap_file = "../ml_model/pcap_file_1.pcap"  # Replace with your PCAP file path
        packets = self.process_pcap(pcap_file)
        # Send data to ML model for attack detection
        try:
            features_list = [extract_features(pkt) for pkt in packets if extract_features(pkt) is not None]
            
            print("Features are extracted")
            # Convert to DataFrame
            df = pd.DataFrame(features_list)

            output_csv = "packet_features.csv"
            df.to_csv(output_csv, index=False)
            print(f"✅ Feature extraction complete! Saved to {output_csv}")

            # Test with ML Model
            prediction = test_model(output_csv)
            print("Prediction saved.")
            
            # If attack detected, install blocking rule
            if prediction in [1, 2]:  # 1 = Neptune, 2 = Smurf
                self.logger.info(f"🚨 Blocking Attack from {ip.src} to {ip.dst} (Prediction: {prediction})")

                match = parser.OFPMatch(
                    eth_type=0x0800,
                    ipv4_src=ip.src,
                    ipv4_dst=ip.dst,
                    ip_proto=ip.proto
                )

                actions = []  # No actions = Drop packet
                self.add_flow(datapath, 10, match, actions, buffer_id=msg.buffer_id)


                return  # Drop packet immediately

        except Exception as e:
            self.logger.error(f"❌ Error querying ONNX API: {e}")

        # Forward normal traffic
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst)
        self.add_flow(datapath, 1, match, actions)
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)

      

        
