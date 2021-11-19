#define lpm_optimization_init(NAME, SAMPLING_HASH, LEVEL) \
    action NAME##_table_act (level) { \
        modify_field(LEVEL, level); \
    } \
    table NAME##_table { \
        reads { \
            SAMPLING_HASH : lpm; \
        } \
        actions { \
            NAME##_table_act; \
        } \
    }

#define lpm_optimization_call(NAME) \
	apply(NAME##_table);
