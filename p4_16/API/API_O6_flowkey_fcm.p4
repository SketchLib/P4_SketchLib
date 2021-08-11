#define ETHERTYPE_TO_CPU 0xBF01

const PortId_t CPU_PORT = 192; // tofino with pipeline 2
// const PortId_t CPU_PORT = 320; // tofino with pipeline 4

control heavy_flowkey_storage (
    inout header_t hdr,
    inout fcm_metadata_t ig_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md)
{
    // threshold table
    action tbl_threshold_above_action() {
        ig_md.above_threshold = 1;
    }

    table tbl_threshold {
        key = {
            ig_md.c_1 : exact;
        }
        actions = {
            tbl_threshold_above_action;
        }
    }

    // hash table
    // bit<32> : entry size
    // bit<16> : index size
    // 65536   : SRAM size

    Register<bit<32>, bit<16>>(32w65536) flowkey_hash_table;

    RegisterAction<bit<32>, bit<16>, bit<32>>(flowkey_hash_table) flowkey_action = {
    
    // Register<bit<32>, bit<2>>(32w4) flowkey_hash_table;

    // RegisterAction<bit<32>, bit<2>, bit<32>>(flowkey_hash_table) flowkey_action = {
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

    action subtract(){  
        ig_md.est_1 = ig_md.est_1 - ig_md.threshold;
    }

    apply {
        subtract();
        ig_md.c_1 = (bit<1>) ig_md.est_1 >> 31;
        tbl_threshold.apply();

        if(ig_md.above_threshold == 1) {
            // bit<32> hash_entry = flowkey_action.execute(ig_md.res_all[1:0]);
            bit<32> hash_entry = flowkey_action.execute(ig_md.result_d1[15:0]);

            if (hash_entry != 0) {
                if (hash_entry != hdr.ipv4.src_addr) {
                    tbl_exact_match.apply();
                }
            }
            else {
                tbl_exact_match_miss();
            }
        }
    }
}

