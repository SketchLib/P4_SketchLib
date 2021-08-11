#define ETHERTYPE_TO_CPU 0xBF01

const PortId_t CPU_PORT = 192; // tofino with pipeline 2
// const PortId_t CPU_PORT = 320; // tofino with pipeline 4

control heavy_flowkey_storage_rhhh (
    inout header_t hdr,
    inout metadata_t ig_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md)
{
    // threshold table
    action tbl_threshold_above_action() {
        ig_md.above_threshold = 1;
    }

    table tbl_threshold {
        key = {
            ig_md.c_1 : exact;
            ig_md.c_2 : exact;
            ig_md.c_3 : exact;
            // ig_md.c_4 : exact;
            // ig_md.c_5 : exact;
        }
        actions = {
            tbl_threshold_above_action;
        }
    }

    // Register<bit<32>, bit<2>>(32w4) flowkey_hash_table;
    // RegisterAction<bit<32>, bit<2>, bit<32>>(flowkey_hash_table) flowkey_action = {

    // hash table
    // bit<32> : entry size
    // bit<16> : index size
    // 65536   : SRAM size

    Register<bit<32>, bit<16>>(32w65536) srcip_hash_table;
    RegisterAction<bit<32>, bit<16>, bit<32>>(srcip_hash_table) srcip_action = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data == 0) {
                register_data = ig_md.masked_srcip;
                result = 0;
            }
            else {
                result = register_data;
            }
        }
    };

    Register<bit<32>, bit<16>>(32w65536) dstip_hash_table;
    RegisterAction<bit<32>, bit<16>, bit<32>>(dstip_hash_table) dstip_action = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            if (register_data == 0) {
                register_data = ig_md.masked_dstip;
                result = 0;
            }
            else {
                result = register_data;
            }
        }
    };

    Register<bit<8>, bit<16>>(32w65536) level_hash_table;
    RegisterAction<bit<8>, bit<16>, bit<8>>(level_hash_table) level_action = {
        void apply(inout bit<8> register_data, out bit<8> result) {
            if (register_data == 0) {
                register_data = (bit<8>)ig_md.level;
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

        hdr.ipv4.src_addr = ig_md.masked_srcip;
        hdr.ipv4.dst_addr = ig_md.masked_dstip;
        hdr.ipv4.protocol = (bit<8>)ig_md.level;

        ig_tm_md.ucast_egress_port = CPU_PORT;
    }

    action tbl_exact_match_hit() {
    }

    table tbl_exact_match {
        key = {
            ig_md.masked_srcip : exact;
            ig_md.masked_dstip : exact;
            ig_md.level : exact;
        }
        actions = {
            tbl_exact_match_miss;
            tbl_exact_match_hit;
        }
        const default_action = tbl_exact_match_miss;
        size = 1024;
    }

    action subtract_threshold_values() {
        ig_md.est_1 = ig_md.est_1 - ig_md.threshold;
        ig_md.est_2 = ig_md.est_2 - ig_md.threshold;
        ig_md.est_3 = ig_md.est_3 - ig_md.threshold;
        // ig_md.est_4 = ig_md.est_4 - ig_md.threshold;
        // ig_md.est_5 = ig_md.est_5 - ig_md.threshold;
    }

    action shift_est_values() {
        ig_md.c_1 = (bit<1>) ig_md.est_1 >> 31;
        ig_md.c_2 = (bit<1>) ig_md.est_2 >> 31;
        ig_md.c_3 = (bit<1>) ig_md.est_3 >> 31;
        // ig_md.c_4 = (bit<1>) ig_md.est_4 >> 31;
        // ig_md.c_5 = (bit<1>) ig_md.est_5 >> 31;
    }

    action subtract_values() {
        ig_md.diff_srcip = ig_md.hash_entry_srcip - ig_md.masked_srcip;
        ig_md.diff_dstip = ig_md.hash_entry_dstip - ig_md.masked_dstip;
        ig_md.diff_level = ig_md.hash_entry_level - (bit<8>)ig_md.level;
    }

    apply {
        subtract_threshold_values();
        shift_est_values();
        tbl_threshold.apply();

        if(ig_md.above_threshold == 1) {
            ig_md.hash_entry_srcip = srcip_action.execute(ig_md.res_all[15:0]);
            ig_md.hash_entry_dstip = dstip_action.execute(ig_md.res_all[15:0]);
            ig_md.hash_entry_level = level_action.execute(ig_md.res_all[15:0]);

            if (ig_md.hash_entry_level != 0) { // result 0 means there was no entry.
                subtract_values();
                if (ig_md.diff_srcip != 0) {
                    tbl_exact_match.apply();
                } else {
                    if (ig_md.diff_dstip != 0) {
                        tbl_exact_match.apply();
                    }
                    else {
                        if (ig_md.diff_level != 0) {
                            tbl_exact_match.apply();
                        }
                    }
                }
            }
            else {
                tbl_exact_match_miss();
            }
        }
    }
}
