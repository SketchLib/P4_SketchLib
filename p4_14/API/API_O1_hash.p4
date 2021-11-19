#define hash_consolidate_and_split_5_init(NAME, KEY_FIELDS, POLY_PARAM, PHV0, LEN0, PHV1, PHV2, PHV3, PHV4, PHV5, MASK1, MASK2, MASK3, MASK4, LEN1, LEN2, LEN3, LEN4) \
    field_list_calculation NAME##_hash_func { \
        input { \
            KEY_FIELDS; \
        } \
        algorithm : poly_##POLY_PARAM##_init_0x00000000_xout_0xffffffff; \
        output_width : 16; \
    } \
    table NAME##_compute_all_hash { \
        actions { \
            NAME##_compute_all_hash_act; \
        } \
        default_action: NAME##_compute_all_hash_act; \
    } \
    action NAME##_compute_all_hash_act () { \
        modify_field_with_hash_based_offset(PHV0, 0x0, NAME##_hash_func, LEN0); \
    } \
    table NAME##_split_table { \
        actions { \
            NAME##_split_table_act; \
        } \
        default_action: NAME##_split_table_act; \
    } \
    action NAME##_split_table_act () { \
        modify_field_with_shift(PHV1, PHV0, 0, MASK1); \
        modify_field_with_shift(PHV2, PHV0, LEN1, MASK2); \
        modify_field_with_shift(PHV3, PHV0, LEN2, MASK3); \
        modify_field_with_shift(PHV4, PHV0, LEN3, MASK4); \
        shift_right(PHV5, PHV0, LEN4); \
    }

#define hash_consolidate_and_split_5_call(NAME) \
    apply(NAME##_compute_all_hash); \
    apply(NAME##_split_table);