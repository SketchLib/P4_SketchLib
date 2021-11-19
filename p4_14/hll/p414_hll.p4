#include <tofino/constants.p4>
#include <tofino/intrinsic_metadata.p4>
#include <tofino/primitives.p4>
#include <tofino/stateful_alu_blackbox.p4>

#include "headers.p4"
#include "parsers.p4"

#include "API_common.p4"
#include "API_O3_tcam.p4"

field_list key_fields {
    ipv4.srcAddr;
}

header_type md_t {
    fields {
        sampling_hash_value:32;
        level:32;
        index:16;
    }
}
metadata md_t md;

hash_init(hll_hash, key_fields, 0x1798f10d1, md.sampling_hash_value, 4294967296) // 2^32 = 4294967296
lpm_optimization_init(hll_tcam, md.sampling_hash_value, md.level)

register hll_reg {
    width: 32;
    instance_count: 2048;
}
blackbox stateful_alu hll_blackbox {
    reg: hll_reg;
    condition_lo: md.level > register_lo;
    update_lo_1_predicate: condition_lo;
    update_lo_1_value    : md.level;
}
table sketching_table {
    actions {
        sketching_act;
    }
    default_action: sketching_act;
}
field_list_calculation hll_hash_func {
    input {
        key_fields;
    }
    algorithm : poly_0x11e12a717_init_0x00000000_xout_0ffffffff;
    output_width : 11;
}
action sketching_act () {
    hll_blackbox.execute_stateful_alu_from_hash(hll_hash_func);
}

control ingress {
    hash_call(hll_hash)
    lpm_optimization_call(hll_tcam)
    apply(sketching_table);
}

control egress {

}
