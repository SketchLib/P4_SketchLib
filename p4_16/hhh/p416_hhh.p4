#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "headers.p4"
#include "util.p4"

#define METADATA_LEVEL_SETUP(L) \
    bit<32> level_##L##_threshold; \
    bit<16> level_##L##_res_all; \
    bit<1> level_##L##_res_1; \
    bit<1> level_##L##_res_2; \
    bit<1> level_##L##_res_3; \
    bit<1> level_##L##_res_4; \
    bit<1> level_##L##_res_5; \
    bit<32> level_##L##_est_1; \
    bit<32> level_##L##_est_2; \
    bit<32> level_##L##_est_3; \
    bit<1> level_##L##_c_1; \
    bit<1> level_##L##_c_2; \
    bit<1> level_##L##_c_3; \
    bit<1> level_##L##_above_threshold;

#define CONTROL_FUNC_SETUP(L) \
    hash_consolidate_and_split_srcip(32w0x5b445b31) level_##L##_res_split; \
    CS_UPDATE(32w0x30243f0b) level_##L##_update_1; \
    CS_UPDATE(32w0x0f79f523) level_##L##_update_2; \
    CS_UPDATE(32w0x6b8cb0c5) level_##L##_update_3;

#define APPLY_SETUP(L) \
    level_##L##_res_split.apply(key##L##, ig_md.level_##L##_res_all, \
                    ig_md.level_##L##_res_1, \
                    ig_md.level_##L##_res_2, \
                    ig_md.level_##L##_res_3, \
                    ig_md.level_##L##_res_4, \
                    ig_md.level_##L##_res_5); \
    level_##L##_update_1.apply(key##L##, ig_md.level_##L##_res_1, ig_md.level_##L##_est_1); \
    level_##L##_update_2.apply(key##L##, ig_md.level_##L##_res_2, ig_md.level_##L##_est_2); \
    level_##L##_update_3.apply(key##L##, ig_md.level_##L##_res_3, ig_md.level_##L##_est_3);

    // level_##L##_update_4.apply(key##L##, ig_md.level_##L##_res_4, ig_md.level_##L##_est_4); \
    // level_##L##_update_5.apply(key##L##, ig_md.level_##L##_res_5, ig_md.level_##L##_est_5);

struct metadata_t {
    METADATA_LEVEL_SETUP(1)
    METADATA_LEVEL_SETUP(2)
    METADATA_LEVEL_SETUP(3)
    METADATA_LEVEL_SETUP(4)
}

#include "parser.p4"

#include "API_common.p4"
#include "API_O1_hash.p4"
#include "API_O2_hash.p4"
#include "API_O3_tcam.p4"
#include "API_O5_salu.p4"
#include "API_O6_flowkey_hhh.p4"

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {


    heavy_flowkey_storage() store_flowkey;

    CONTROL_FUNC_SETUP(1)
    CONTROL_FUNC_SETUP(2)
    CONTROL_FUNC_SETUP(3)
    CONTROL_FUNC_SETUP(4)

    apply {
        if(hdr.ethernet.ether_type == ETHERTYPE_IPV4) {
            bit<32> key1 = hdr.ipv4.src_addr & 0xFFFFFFFF;
            bit<32> key2 = hdr.ipv4.src_addr & 0xFFFFFF00;
            bit<32> key3 = hdr.ipv4.src_addr & 0xFFFF0000;
            bit<32> key4 = hdr.ipv4.src_addr & 0xFF000000;
            APPLY_SETUP(1)
            APPLY_SETUP(2)
            APPLY_SETUP(3)
            APPLY_SETUP(4)

            store_flowkey.apply(hdr, ig_md, ig_tm_md);
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
