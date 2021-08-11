parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
        // transition parse_ipv4;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_VLAN : parse_vlan;
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
        }
    }

    state parse_vlan {
        pkt.extract(hdr.vlan_tag);
        transition select(hdr.vlan_tag.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        // transition select(hdr.ipv4.protocol) {
        //     IP_PROTOCOLS_UDP : parse_udp;
        //     IP_PROTOCOLS_TCP : parse_tcp;
        //     default : reject;
        // }
    }

    // state parse_tcp {
    //     pkt.extract(hdr.tcp);
    //     transition accept;
    // }

    // state parse_udp {
    //     pkt.extract(hdr.udp);
    //     transition accept;
    // }
}

control SwitchIngressDeparser(packet_out pkt,
                              inout header_t hdr,
                              in metadata_t ig_md,
                              in ingress_intrinsic_metadata_for_deparser_t 
                                ig_intr_dprsr_md
                              ) {

    apply {
        pkt.emit(hdr);
    }
}