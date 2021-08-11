#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "headers.p4"
#include "util.p4"

struct metadata_t {
    bit<32> sampling_hash;
    bit<32> level;
    bit<16> index;
}

#include "parser.p4"

#include "API_common.p4"
#include "API_O3_tcam.p4"

control LL_UPDATE(
  in bit<16> index,
  in bit<32> level)
{

    Register<bit<32>, bit<16>>(32w2048) cs_table;

    RegisterAction<bit<32>, bit<16>, bit<32>>(cs_table) cs_action = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            if (level > register_data) {
                register_data = level;
            }
        }
    };

    apply {
        cs_action.execute(index);
    }
}

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    lpm_optimization_32() tcam;
    LL_UPDATE() update;

    action split() {
        ig_md.sampling_hash = (bit<32>)hdr.ipv4.src_addr[19:0];
        ig_md.index = (bit<16>)hdr.ipv4.src_addr[31:20];
    }
    apply {

        if(hdr.ethernet.ether_type == ETHERTYPE_IPV4) {
            split();
            tcam.apply(ig_md.sampling_hash, ig_md.level);
            update.apply(ig_md.index, ig_md.level);
        }
    }
}

struct my_egress_headers_t {
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


Pipeline(
    SwitchIngressParser(),
    SwitchIngress(),
    SwitchIngressDeparser(),
    EgressParser(),
    EmptyEgress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
