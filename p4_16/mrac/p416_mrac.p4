#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "headers.p4"
#include "util.p4"

struct metadata_t {
    bit<15> sampling_hash_value;
    bit<16> level;
    bit<16> index;
    bit<16> base;
    bit<16> mem_index;
}

#include "parser.p4"

#include "API_common.p4"
#include "API_O1_hash.p4"
#include "API_O2_hash.p4"
#include "API_O3_tcam.p4"
#include "API_O5_salu.p4"

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    lpm_optimization_mrb() tcam;
    HASH_COMPUTE_SRCIP_15_15(32w0x790900f3) sampling_hash;
    HASH_COMPUTE_SRCIP_16_11(32w0x30243f0b) index_hash;
    consolidate_update_mrac() update;

    apply {
        if(hdr.ethernet.ether_type == ETHERTYPE_IPV4) {
            sampling_hash.apply(hdr.ipv4.src_addr, ig_md.sampling_hash_value);
            tcam.apply(ig_md.sampling_hash_value, ig_md.level);
            index_hash.apply(hdr.ipv4.src_addr, ig_md.index);
            update.apply(ig_md.index, ig_md.level, ig_md.base, ig_md.mem_index);
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
