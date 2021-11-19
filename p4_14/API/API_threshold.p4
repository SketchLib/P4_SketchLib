#define TH_TABLE(THRESHOLD) \
    action th_table_act (threshold) { \
        modify_field(THRESHOLD, threshold); \
    } \
    table th_table { \
        actions { \
            th_table_act; \
        } \
    }

#define TH_BASE_TABLE(THRESHOLD, BASE) \
    action th_table_act (threshold, base) { \
        modify_field(THRESHOLD, threshold); \
        modify_field(BASE, base); \
    } \
    table th_table { \
        actions { \
            th_table_act; \
        } \
    }
