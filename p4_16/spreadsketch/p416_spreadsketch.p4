// This code is written based on the original paper's implementation
// https://github.com/Grace-TL/SpreadSketch/blob/master/p4/ss.p4

#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "headers.p4"
#include "util.p4"

struct metadata_t {
    bit<32> srcip_dstip_hash;
    bit<32> level;
    bit<32> short_level;

    bit<32> index_1;
    bit<32> index_2;
    bit<32> index_3;

    bit<32> base_1_1;
    bit<32> base_2_1;
    bit<32> base_3_1;

    bit<32> base_1_2;
    bit<32> base_2_2;
    bit<32> base_3_2;

    bit<32> mem_index_1;
    bit<32> mem_index_2;
    bit<32> mem_index_3;
}

#include "parser.p4"

#include "API_common.p4"
#include "API_O1_hash.p4"
#include "API_O2_hash.p4"
#include "API_O3_tcam.p4"
#include "API_O5_salu.p4"

control max_level(
    in bit<32> srcIP,
    in bit<32> index,
    in bit<32> level)
{
    Register<bit<32>, bit<32>>(2048) store_max_level;
    Register<bit<32>, bit<32>>(2048) store_candidate_ss_srcIP;

    RegisterAction<bit<32>, bit<32>, bit<1>>(store_max_level) max_level_action = {
        void apply(inout bit<32> register_data, out bit<1> result) {
            if (level > register_data) {
                register_data = level;
                result = 1;
            }
            else {
                result = 0;
            }
        }
    };

    RegisterAction<bit<32>, bit<32>, bit<32>>(store_candidate_ss_srcIP) candidate_ss_srcIP_action = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            register_data = srcIP;
        }
    };

    apply{
        bit<1> result;
        result = max_level_action.execute(index);
        if (result == 1) {
            candidate_ss_srcIP_action.execute(index);
        }
    }
}

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    HASH_COMPUTE_SRCIP_DSTIP_32_32(32w0x790900f3) sampling_hash;
    lpm_optimization_32() tcam;

    HASH_COMPUTE_SRCIP_32_11(32w0x30243f0b) index_hash_1;
    HASH_COMPUTE_SRCIP_32_11(32w0x0f79f523) index_hash_2;
    HASH_COMPUTE_SRCIP_32_11(32w0x6b8cb0c5) index_hash_3;

    consolidate_update_ss() update_sketch_1;
    consolidate_update_ss() update_sketch_2;
    consolidate_update_ss() update_sketch_3;

    max_level() update_info_1;
    max_level() update_info_2;
    max_level() update_info_3;

    apply {
        if(hdr.ethernet.ether_type == ETHERTYPE_IPV4) {
            sampling_hash.apply(hdr.ipv4.src_addr, hdr.ipv4.dst_addr, ig_md.srcip_dstip_hash);
            tcam.apply(ig_md.srcip_dstip_hash, ig_md.level);

            ig_md.short_level = ig_md.level;
            if(ig_md.level > 3) {
                ig_md.short_level = 4;
            }

            index_hash_1.apply(hdr.ipv4.src_addr, ig_md.index_1);
            index_hash_2.apply(hdr.ipv4.src_addr, ig_md.index_2);
            index_hash_3.apply(hdr.ipv4.src_addr, ig_md.index_3);

            update_sketch_1.apply(ig_md.index_1, ig_md.srcip_dstip_hash, ig_md.short_level, ig_md.base_1_1, ig_md.base_1_2, ig_md.mem_index_1);
            update_sketch_2.apply(ig_md.index_2, ig_md.srcip_dstip_hash, ig_md.short_level, ig_md.base_2_1, ig_md.base_2_2, ig_md.mem_index_2);
            update_sketch_3.apply(ig_md.index_3, ig_md.srcip_dstip_hash, ig_md.short_level, ig_md.base_3_1, ig_md.base_3_2, ig_md.mem_index_3);

            update_info_1.apply(hdr.ipv4.src_addr, ig_md.index_1, ig_md.level);
            update_info_2.apply(hdr.ipv4.src_addr, ig_md.index_2, ig_md.level);
            update_info_3.apply(hdr.ipv4.src_addr, ig_md.index_3, ig_md.level);
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
