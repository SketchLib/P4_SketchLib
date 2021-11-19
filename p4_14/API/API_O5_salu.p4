#define consolidate_update_cs_5_init(NAME, BASE, INDEX, RES, EST, SIZE) \
	table NAME##_add_base_table { \
	    actions { \
	        NAME##_add_base_table_act; \
	    } \
	    default_action: NAME##_add_base_table_act; \
	} \
	action NAME##_add_base_table_act () { \
        add_to_field(INDEX, BASE); \
	} \
    register  NAME##_register { \
        width: 32; \
        instance_count: SIZE; \
    } \
    blackbox stateful_alu NAME##_salu { \
        reg: NAME##_register; \
        condition_lo: RES > 0; \
        update_lo_1_predicate: condition_lo;     /* if (res == 0)  */ \
        update_lo_1_value    : register_lo + 1; \
        update_lo_2_predicate: not condition_lo; /* else */ \
        update_lo_2_value    : register_lo - 1; \
        condition_hi: RES > 0; \
        update_hi_1_predicate: condition_hi;     /* if   */ \
        update_hi_1_value    : register_lo + 1; \
        update_hi_2_predicate: not condition_hi; /* else */ \
        update_hi_2_value    : ~register_lo; \
        output_value: alu_hi; \
        output_dst: EST; \
    } \
    table NAME##_update_table { \
        actions { \
            NAME##_update_table_act; \
        } \
        default_action: NAME##_update_table_act; \
    } \
    action NAME##_update_table_act () { \
        NAME##_salu.execute_stateful_alu(INDEX); \
    }

#define consolidate_update_cs_5_call(NAME) \
    apply(NAME##_add_base_table); \
    apply(NAME##_update_table);

