
#define heavy_flowkey_storage_step1_5_init(NAME, E1, E2, E3, E4, E5, COMP1, COMP2, COMP3, COMP4, COMP5, THRESHOLD) \
    table NAME##_subtract_table { \
        actions { \
            NAME##_subtract_table_act; \
        } \
        default_action: NAME##_subtract_table_act; \
    } \
    action NAME##_subtract_table_act () { \
        subtract_from_field(E1, THRESHOLD); \
        subtract_from_field(E2, THRESHOLD); \
        subtract_from_field(E3, THRESHOLD); \
        subtract_from_field(E4, THRESHOLD); \
        subtract_from_field(E5, THRESHOLD); \
    } \
    table NAME##_shift_table { \
        actions { \
            NAME##_shift_table_act; \
        } \
        default_action: NAME##_shift_table_act; \
    } \
    action NAME##_shift_table_act () { \
        shift_right(COMP1, E1, 31); \
        shift_right(COMP2, E2, 31); \
        shift_right(COMP3, E3, 31); \
        shift_right(COMP4, E4, 31); \
        shift_right(COMP5, E5, 31); \
    }

#define heavy_flowkey_storage_step1_5_call(NAME) \
    apply(NAME##_subtract_table); \
    apply(NAME##_shift_table);

#define heavy_flowkey_storage_step2_5_init(NAME, C1, C2, C3, C4, C5, ABOVE_THRESHOLD, KEY_FIELDS, KEY, POLY_PARAM, HASH_TABLE_SIZE, HASH_ENTRY, MATCH_HIT) \
    field_list_calculation NAME##_hash_func { \
        input { \
            KEY_FIELDS; \
        } \
        algorithm : poly_##POLY_PARAM##_init_0x00000000_xout_0xffffffff; \
        output_width : 14; \
    } \
    register NAME##_hash_table_register { \
        width: 32; \
        instance_count: HASH_TABLE_SIZE; \
    } \
    blackbox stateful_alu NAME##_blackbox { \
        reg: NAME##_hash_table_register; \
        condition_lo: register_lo == 0; \
        update_lo_1_predicate: condition_lo; \
        update_lo_1_value    : KEY; \
        update_lo_2_predicate: not condition_lo; /* else */ \
        update_lo_2_value    : register_lo; \
        update_hi_1_predicate: condition_lo;     /* if   */ \
        update_hi_1_value    : 0; \
        update_hi_2_predicate: not condition_lo; /* else */ \
        update_hi_2_value    : register_lo; \
        output_value: alu_hi; \
        output_dst: HASH_ENTRY; \
    } \
    table NAME##_sum_table { \
        reads { \
            C1: exact; \
            C2: exact; \
            C3: exact; \
            C4: exact; \
            C5: exact; \
        } \
        actions { \
            NAME##_sum_miss; \
            NAME##_sum_hit; \
        } \
        default_action: NAME##_sum_miss; \
        size: 32; \
    } \
    action NAME##_sum_miss() { \
        modify_field(ABOVE_THRESHOLD, 0); \
    } \
    action NAME##_sum_hit() { \
        modify_field(ABOVE_THRESHOLD, 1); \
        NAME##_blackbox.execute_stateful_alu_from_hash(NAME##_hash_func); \
    } \
    table NAME##_match_table { \
        reads { \
            KEY: exact; \
        } \
        actions { \
            NAME##_match_miss; \
            NAME##_match_hit; \
        } \
        default_action: NAME##_match_miss; \
        size : 10000; \
    } \
    action NAME##_match_miss() { \
        modify_field(MATCH_HIT, 0); \
    } \
    action NAME##_match_hit() { \
        modify_field(MATCH_HIT, 1); \
    }

// if MATCH_HIT == 0 -> send to CPU


#define heavy_flowkey_storage_step2_5_call(NAME, ABOVE_THRESHOLD, HASH_ENTRY, KEY) \
    apply(NAME##_sum_table); \
    if (HASH_ENTRY != 0) { \
        if(HASH_ENTRY != KEY) { \
            apply(NAME##_match_table); \
        } \
    }

