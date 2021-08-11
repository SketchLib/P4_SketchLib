#define ETHERTYPE_TO_CPU 0xBF01

const PortId_t CPU_PORT = 192; // tofino with pipeline 2
// const PortId_t CPU_PORT = 320; // tofino with pipeline 4

#define O6_TABLE_SETUP(L) \
    action level_##L##_tbl_threshold_above_action() { \
        ig_md.level_##L##_above_threshold = 1; \
    } \
    table level_##L##_tbl_threshold { \
        key = { \
            ig_md.level_##L##_c_1 : exact; \
            ig_md.level_##L##_c_2 : exact; \
            ig_md.level_##L##_c_3 : exact; \
        } \
        actions = { \
            level_##L##_tbl_threshold_above_action; \
        } \
    }

#define O6_APPLY_SETUP(L) \
    ig_md.level_##L##_est_1 = ig_md.level_##L##_est_1 - ig_md.level_##L##_threshold; \
    ig_md.level_##L##_est_2 = ig_md.level_##L##_est_2 - ig_md.level_##L##_threshold; \
    ig_md.level_##L##_est_3 = ig_md.level_##L##_est_3 - ig_md.level_##L##_threshold; \
    ig_md.level_##L##_c_1 = (bit<1>) ig_md.level_##L##_est_1 >> 31; \
    ig_md.level_##L##_c_2 = (bit<1>) ig_md.level_##L##_est_2 >> 31; \
    ig_md.level_##L##_c_3 = (bit<1>) ig_md.level_##L##_est_3 >> 31; \
    level_##L##_tbl_threshold.apply();

control heavy_flowkey_storage (
    inout header_t hdr,
    inout metadata_t ig_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md)
{
    O6_TABLE_SETUP(1)
    O6_TABLE_SETUP(2)
    O6_TABLE_SETUP(3)
    O6_TABLE_SETUP(4)

    Register<bit<32>, bit<16>>(32w65536) flowkey_hash_table;

    RegisterAction<bit<32>, bit<16>, bit<32>>(flowkey_hash_table) flowkey_action = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data == 0) {
                register_data = hdr.ipv4.src_addr;
                result = 0;
            }
            else {
                result = register_data;
            }
        }
    };


    // exact table
    action tbl_exact_match_miss() {

        hdr.cpu_ethernet.setValid();
        hdr.cpu_ethernet.dst_addr   = 0xFFFFFFFFFFFF;
        hdr.cpu_ethernet.src_addr   = 0xAAAAAAAAAAAA;
        hdr.cpu_ethernet.ether_type = ETHERTYPE_TO_CPU;
        ig_tm_md.ucast_egress_port = CPU_PORT;
    }

    action tbl_exact_match_hit() {
    }

    table tbl_exact_match {
        key = {
            hdr.ipv4.src_addr : exact;
        }
        actions = {
            tbl_exact_match_miss;
            tbl_exact_match_hit;
        }
        const default_action = tbl_exact_match_miss;
        size = 65536;
    }

    apply {

        O6_APPLY_SETUP(1)
        O6_APPLY_SETUP(2)
        O6_APPLY_SETUP(3)
        O6_APPLY_SETUP(4)

        if(ig_md.level_1_above_threshold == 1 || ig_md.level_2_above_threshold == 1 || ig_md.level_3_above_threshold == 1 || ig_md.level_4_above_threshold == 1) {
            bit<32> hash_entry = flowkey_action.execute(ig_md.level_1_res_all[15:0]);

            if (hash_entry != 0) {
                if (hash_entry != hdr.ipv4.src_addr) {
                    tbl_exact_match.apply();
                }
            }
            // alternatively, we can read flowkey from flowkey_hash_table in the control plane
            // else {
            //     tbl_exact_match_miss();
            // }
        }
    }
}
