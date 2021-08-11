#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "headers.p4"
#include "util.p4"

struct metadata_t {
    bit<16> sampling_hash_value;
    bit<10> level;
    bit<16> base;
    bit<32> threshold;

    bit<16> index_1;
    bit<16> index_2;
    bit<16> index_3;
    bit<16> index_4;
    bit<16> index_5;

    // bit<5> res_all;
    bit<16> res_all;
    bit<1> res_1;
    bit<1> res_2;
    bit<1> res_3;
    bit<1> res_4;
    bit<1> res_5;

    bit<32> est_1;
    bit<32> est_2;
    bit<32> est_3;
    bit<32> est_4;
    bit<32> est_5;

    bit<1> c_1;
    bit<1> c_2;
    bit<1> c_3;
    bit<1> c_4;
    bit<1> c_5;

    bit<1> above_threshold;
}

#include "parser.p4"

#include "API_common.p4"
#include "API_O1_hash.p4"
#include "API_O2_hash.p4"
#include "API_O3_tcam.p4"
#include "API_O5_salu.p4"
#include "API_O6_flowkey.p4"
#include "API_threshold.p4"

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    hash_consolidate_and_split_srcip(32w0x5b445b31) res_split;
    CS_UPDATE(32w0x30243f0b) update_1;
    CS_UPDATE(32w0x0f79f523) update_2;
    CS_UPDATE(32w0x6b8cb0c5) update_3;
    CS_UPDATE(32w0x00390fc3) update_4;
    CS_UPDATE(32w0x298ac673) update_5;

    heavy_flowkey_storage() store_flowkey;

    GET_THRESHOLD() get_threshold;

    apply {

        if(hdr.ethernet.ether_type == ETHERTYPE_IPV4) {

            get_threshold.apply(hdr, ig_md);

            res_split.apply(hdr.ipv4.src_addr, ig_md.res_all,
                            ig_md.res_1,
                            ig_md.res_2,
                            ig_md.res_3,
                            ig_md.res_4,
                            ig_md.res_5);

            update_1.apply(hdr.ipv4.src_addr, ig_md.res_1, ig_md.est_1);
            update_2.apply(hdr.ipv4.src_addr, ig_md.res_2, ig_md.est_2);
            update_3.apply(hdr.ipv4.src_addr, ig_md.res_3, ig_md.est_3);
            update_4.apply(hdr.ipv4.src_addr, ig_md.res_4, ig_md.est_4);
            update_5.apply(hdr.ipv4.src_addr, ig_md.res_5, ig_md.est_5);

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

