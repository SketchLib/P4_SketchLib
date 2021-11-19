#include <tofino/constants.p4>
#include <tofino/intrinsic_metadata.p4>
#include <tofino/primitives.p4>
#include <tofino/stateful_alu_blackbox.p4>

#include "headers.p4"
#include "parsers.p4"

#include "API_common.p4"
#include "API_O1_hash.p4"
#include "API_O3_tcam.p4"
#include "API_O5_salu.p4"
#include "API_O6_flowkey.p4"
#include "API_threshold.p4"

field_list key_fields {
    ipv4.srcAddr;
}

header_type md_t {
    fields {
        temp:5;
        sampling_hash_value: 16;
        level:32;
        base:16;
        threshold: 32;
        temp1:5;
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
        comp_1: 1;
        comp_2: 1;
        comp_3: 1;
        comp_4: 1;
        comp_5: 1;
        above_threshold: 1;
        hash_entry: 32;
        hash_hit: 1;
        match_hit: 1;
    }
}

metadata md_t md;

TH_BASE_TABLE(md.threshold, md.base)
hash_init(um_sampling, key_fields, 0x1198f10d1, md.sampling_hash_value, 65536)
lpm_optimization_init(um_tcam, md.sampling_hash_value, md.level)
hash_consolidate_and_split_5_init(um_group, key_fields, 0x11e12a717, md.temp, 32, md.res_1, md.res_2, md.res_3, md.res_4, md.res_5, 1, 1, 1, 1, 1, 2, 3, 4)

hash_init(cs_index_1, key_fields, 0x119cf8783, md.index_1, 2048)
hash_init(cs_index_2, key_fields, 0x119cf8785, md.index_2, 2048)
hash_init(cs_index_3, key_fields, 0x119cf8787, md.index_3, 2048)
hash_init(cs_index_4, key_fields, 0x119cf8789, md.index_4, 2048)
hash_init(cs_index_5, key_fields, 0x119cf878b, md.index_5, 2048)

consolidate_update_cs_5_init(cs_row_1, md.base, md.index_1, md.res_1, md.est_1, 32768)
consolidate_update_cs_5_init(cs_row_2, md.base, md.index_2, md.res_2, md.est_2, 32768)
consolidate_update_cs_5_init(cs_row_3, md.base, md.index_3, md.res_3, md.est_3, 32768)
consolidate_update_cs_5_init(cs_row_4, md.base, md.index_4, md.res_4, md.est_4, 32768)
consolidate_update_cs_5_init(cs_row_5, md.base, md.index_5, md.res_5, md.est_5, 32768)

heavy_flowkey_storage_step1_5_init(um_f1, md.est_1, md.est_2, md.est_3, md.est_4, md.est_5, md.comp_1, md.comp_2, md.comp_3, md.comp_4, md.comp_5, md.threshold)
heavy_flowkey_storage_step2_5_init(um_f2, md.comp_1, md.comp_2, md.comp_3, md.comp_4, md.comp_5, md.above_threshold, key_fields, ipv4.srcAddr, 0x11ba201b1, 10000, md.hash_entry, md.match_hit)


control ingress {
    apply(th_table);

    hash_call(um_sampling)
    lpm_optimization_call(um_tcam)

    hash_consolidate_and_split_5_call(um_group)

    hash_call(cs_index_1)
    hash_call(cs_index_2)
    hash_call(cs_index_3)
    hash_call(cs_index_4)
    hash_call(cs_index_5)

    consolidate_update_cs_5_call(cs_row_1)
    consolidate_update_cs_5_call(cs_row_2)
    consolidate_update_cs_5_call(cs_row_3)
    consolidate_update_cs_5_call(cs_row_4)
    consolidate_update_cs_5_call(cs_row_5)

    heavy_flowkey_storage_step1_5_call(um_f1)
    heavy_flowkey_storage_step2_5_call(um_f2, md.above_threshold, md.hash_entry, ipv4.srcAddr)
}

control egress {
}
