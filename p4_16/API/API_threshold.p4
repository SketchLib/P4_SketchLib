
control GET_THRESHOLD(
    inout header_t hdr,
    inout metadata_t ig_md)
{
    action tbl_get_threshold_act (bit<32> threshold) {
        ig_md.threshold = threshold;
    }
    table tbl_get_threshold {
        key = {
            hdr.ethernet.ether_type : exact;
        }
        actions = {
            tbl_get_threshold_act;
        }
    }
    apply {
        tbl_get_threshold.apply();
    }
}
