#define hash_init(NAME, KEY_FIELDS, POLY_PARAM, DST, MASK) \
    field_list_calculation NAME##_hash_func { \
        input { \
            KEY_FIELDS; \
        } \
        algorithm : poly_##POLY_PARAM##_init_0x00000000_xout_0xffffffff; \
        output_width : 32; \
    } \
    table NAME##_compute_hash { \
        actions { \
            NAME##_compute_hash_act; \
        } \
        default_action: NAME##_compute_hash_act; \
    } \
    action NAME##_compute_hash_act () { \
        modify_field_with_hash_based_offset(DST, 0x0, NAME##_hash_func, MASK); \
    }
#define hash_call(NAME) \
    apply(NAME##_compute_hash);
