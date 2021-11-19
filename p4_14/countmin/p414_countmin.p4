#include <tofino/constants.p4>
#include <tofino/intrinsic_metadata.p4>
#include <tofino/primitives.p4>
#include <tofino/stateful_alu_blackbox.p4>

#include "headers.p4"
#include "parsers.p4"

#include "API_common.p4"
#include "API_O1_hash.p4"
#include "API_O3_tcam.p4"
#include "API_O6_flowkey.p4"
#include "API_threshold.p4"

field_list key_fields {
    ipv4.srcAddr;
}

header_type md_t {
    fields {
        res_1: 1;
        res_2: 1;
        res_3: 1;
        res_4: 1;
        res_5: 1;
        index_1: 16;
        index_2: 16;
        index_3: 16;
        index_4: 16;
        index_5: 16;
        est_1: 32;
        est_2: 32;
        est_3: 32;
        est_4: 32;
        est_5: 32;
        threshold: 16;
        above_threshold: 1;
        hash_entry: 32;
        hash_hit: 1;
        match_hit: 1;
    }
}
metadata md_t md;

#define WIDTH_BITLEN 11
#define WIDTH 2048

#define ROW_SKETCH(R) \
    register  register_##R { \
        width: 32; \
        instance_count: WIDTH; \
    } \
    blackbox stateful_alu blackbox_##R { \
        reg: register_##R; \
        update_lo_1_value    : register_lo + 1;  \
        update_hi_1_value    : 1+register_lo; \
        output_value: alu_hi; \
        output_dst: md.est_##R; \
    } \
    table sketching_##R##_table { \
        actions { \
            sketching_##R##_act; \
        } \
        default_action: sketching_##R##_act; \
    } \
    action sketching_##R##_act () { \
        blackbox_##R.execute_stateful_alu_from_hash(cs_index_hash_func_##R); \
    }

field_list_calculation cs_index_hash_func_1 {
    input {
        key_fields;
    }
    algorithm : poly_0x30243f0b_init_0x00000000_xout_0ffffffff;
    output_width : WIDTH_BITLEN;
}

field_list_calculation cs_index_hash_func_2 {
    input {
        key_fields;
    }
    algorithm : poly_0x0f79f523_init_0x00000000_xout_0ffffffff;
    output_width : WIDTH_BITLEN;
}

field_list_calculation cs_index_hash_func_3 {
    input {
        key_fields;
    }
    algorithm : poly_0x6b8cb0c5_init_0x00000000_xout_0ffffffff;
    output_width : WIDTH_BITLEN;
}

field_list_calculation cs_index_hash_func_4 {
    input {
        key_fields;
    }
    algorithm : poly_0x00390fc3_init_0x00000000_xout_0ffffffff;
    output_width : WIDTH_BITLEN;
}

field_list_calculation cs_index_hash_func_5 {
    input {
        key_fields;
    }
    algorithm : poly_0x298ac671_init_0x00000000_xout_0ffffffff;
    output_width : WIDTH_BITLEN;
}

TH_TABLE(md.threshold)

ROW_SKETCH(1)
ROW_SKETCH(2)
ROW_SKETCH(3)
ROW_SKETCH(4)
ROW_SKETCH(5)

heavy_flowkey_storage_step1_5_init(cm_f1, md.est_1, md.est_2, md.est_3, md.est_4, md.est_5, md.res_1, md.res_2, md.res_3, md.res_4, md.res_5, md.threshold)
heavy_flowkey_storage_step2_5_init(cm_f2, md.res_1, md.res_2, md.res_3, md.res_4, md.res_5, md.above_threshold, key_fields, ipv4.srcAddr, 0x11e12a719, 16384, md.hash_entry, md.match_hit)

control ingress {
    apply(th_table);

    apply(sketching_1_table);
    apply(sketching_2_table);
    apply(sketching_3_table);
    apply(sketching_4_table);
    apply(sketching_5_table);

    heavy_flowkey_storage_step1_5_call(cm_f1)
    heavy_flowkey_storage_step2_5_call(cm_f2, md.above_threshold, md.hash_entry, ipv4.srcAddr)
}

control egress {

}