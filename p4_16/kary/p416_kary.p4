#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "headers.p4"
#include "util.p4"

struct metadata_t {
    bit<16> epoch_index;
    bit<32> threshold;

    bit<16> res_all;
    bit<1> res_1;
    bit<1> res_2;
    bit<1> res_3;
    bit<1> res_4;
    bit<1> res_5;

    bit<32> est_1;
    bit<32> est_2;
    bit<32> est_3;
    // bit<32> est_4;
    // bit<32> est_5;

    bit<32> est_6;
    bit<32> est_7;
    bit<32> est_8;
    // bit<32> est_9;
    // bit<32> est_10;

    bit<32> diff_1;
    bit<32> diff_2;
    bit<32> diff_3;
    // bit<32> diff_4;
    // bit<32> diff_5;

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
#include "API_O6_flowkey_kary.p4"
#include "API_threshold.p4"

control EPOCH_INDEX(inout bit<16> epoch_index)
{
    Register<bit<32>, bit<16>>(32w1024) epoch_index_table;
    RegisterAction<bit<32>, bit<16>, bit<32>>(epoch_index_table) epoch_index_action = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            result = register_data;
        }
    };

    apply {
        epoch_index = (bit<16>)epoch_index_action.execute(0);
    }
}

#define DEFINE_REGISTER(R, S, POLY) \
    CRCPolynomial<bit<32>>(##POLY##,\
                         true,                                  \
                         false,                                 \
                         false,                                 \
                         32w0xFFFFFFFF,                         \
                         32w0xFFFFFFFF                          \
                         ) poly_##R##;                           \
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_##R##) hash_##R##;\
    Register<bit<32>, bit<16>>(32w4096) cs_table_##R##;\
    RegisterAction<bit<32>, bit<16>, bit<32>>(cs_table_##R##) cs_update_##R## = {\
        void apply(inout bit<32> register_data, out bit<32> result) {\
            if (ig_md.res_##S## == 0) {\
                register_data = register_data - 1;\
            }\
            else {\
                register_data = register_data + 1;\
            }\
            result = register_data;\
        }\
    };\
    RegisterAction<bit<32>, bit<16>, bit<32>>(cs_table_##R##) cs_read_##R## = {\
        void apply(inout bit<32> register_data, out bit<32> result) {\
            result = register_data;\
        }\
    };

#define UPDATE(R, S) \
    ig_md.est_##R## = cs_update_##R##.execute(hash_##R##.get({hdr.ipv4.src_addr})); \
    if (ig_md.res_##S## == 0) { \
        ig_md.est_##R## = -ig_md.est_##R##; \
    }

#define READ(R, S) \
    ig_md.est_##R## = cs_read_##R##.execute(hash_##R##.get({hdr.ipv4.src_addr})); \
    if (ig_md.res_##S## == 0) { \
        ig_md.est_##R## = -ig_md.est_##R##; \
    }

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    hash_consolidate_and_split_srcip(32w0x5b445b31) res_split;


    EPOCH_INDEX() get_epoch_index;

    GET_THRESHOLD() get_threshold;

    DEFINE_REGISTER(1, 1, 32w0x30243f0b)
    DEFINE_REGISTER(2, 2, 32w0x0f79f523)
    DEFINE_REGISTER(3, 3, 32w0x6b8cb0c5)
    // DEFINE_REGISTER(4, 4, 32w0x00390fc3)
    // DEFINE_REGISTER(5, 5, 32w0x298ac673)

    DEFINE_REGISTER(6, 1, 32w0x30243f0b)
    DEFINE_REGISTER(7, 2, 32w0x0f79f523)
    DEFINE_REGISTER(8, 3, 32w0x6b8cb0c5)
    // DEFINE_REGISTER(9, 4, 32w0x00390fc3)
    // DEFINE_REGISTER(10, 5, 32w0x298ac673)

    heavy_flowkey_storage() store_flowkey;

    apply {

        if(hdr.ethernet.ether_type == ETHERTYPE_IPV4) {
            get_epoch_index.apply(ig_md.epoch_index);
            get_threshold.apply(hdr, ig_md);

            res_split.apply(hdr.ipv4.src_addr, ig_md.res_all,
                            ig_md.res_1,
                            ig_md.res_2,
                            ig_md.res_3,
                            ig_md.res_4,
                            ig_md.res_5);


            if (ig_md.epoch_index % 2 == 0) {
                READ(1, 1)
                READ(2, 2)
                READ(3, 3)
                // READ(4, 4)
                // READ(5, 5)

                UPDATE(6, 1)
                UPDATE(7, 2)
                UPDATE(8, 3)
                // UPDATE(9, 4)
                // UPDATE(10, 5)

                ig_md.est_1 = ig_md.est_6 - ig_md.est_1;
                ig_md.est_2 = ig_md.est_7 - ig_md.est_2;
                ig_md.est_3 = ig_md.est_8 - ig_md.est_3;
                // ig_md.est_4 = ig_md.est_4 - ig_md.est_9;
                // ig_md.est_5 = ig_md.est_5 - ig_md.est_10;
            }
            else {
                UPDATE(1, 1)
                UPDATE(2, 2)
                UPDATE(3, 3)
                // UPDATE(4, 4)
                // UPDATE(5, 5)

                READ(6, 1)
                READ(7, 2)
                READ(8, 3)
                // READ(9, 4)
                // READ(10, 5)

                ig_md.est_1 = ig_md.est_1 - ig_md.est_6;
                ig_md.est_2 = ig_md.est_2 - ig_md.est_7;
                ig_md.est_3 = ig_md.est_3 - ig_md.est_8;
                // ig_md.diff_4 = ig_md.est_9 - ig_md.est_4;
                // ig_md.diff_5 = ig_md.est_10 - ig_md.est_5;
            }

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
