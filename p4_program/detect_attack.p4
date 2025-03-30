// Standard P4 header
#include <core.p4>

// Define Ethernet Header
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> ethType;
}

// Define IPv4 Header
header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

// Packet Headers Structure
struct headers_t {
    ethernet_t eth;
    ipv4_t ip;
}

// Metadata (empty for now)
struct metadata_t { }

// Standard Parser
parser MyParser(packet_in pkt, out headers_t hdr, inout metadata_t meta, inout standard_metadata_t stdmeta) {
    state start {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.ethType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ip);
        transition accept;
    }
}

// Match-Action Table for Attack Detection
table detect_attack {
    key = {
        hdr.ip.srcAddr: exact;  // Match based on Source IP
    }
    actions = {
        drop_attack;
        NoAction;
    }
    size = 1024;
    default_action = NoAction;
}

// Define Actions
action drop_attack() {
    mark_to_drop();
}

// Control Block
control MyIngress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t stdmeta) {
    apply {
        detect_attack.apply();
    }
}

// Deparser to Send Out Packets
control MyDeparser(packet_out pkt, in headers_t hdr) {
    apply {
        pkt.emit(hdr.eth);
        pkt.emit(hdr.ip);
    }
}

// Pipeline Definition
pipeline MyPipeline(MyParser(), MyIngress(), MyDeparser());

// Switch Configuration
package MySwitch(MyPipeline pipeline);
