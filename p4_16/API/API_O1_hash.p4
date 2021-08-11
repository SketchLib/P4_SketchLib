control hash_consolidate_and_split_srcip(
  in ipv4_addr_t srcIP,
  out bit<16> res_all,
  out bit<1> res_1,
  out bit<1> res_2,
  out bit<1> res_3,
  out bit<1> res_4,
  out bit<1> res_5)(
  bit<32> polynomial)
{
    CRCPolynomial<bit<32>>(polynomial,
                           true,
                           false,
                           false,
                           32w0xFFFFFFFF,
                           32w0xFFFFFFFF
                           ) poly1;

    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly1) hash;

    action action_hash() {
        res_all = hash.get({srcIP[31:0]});
    }

    table tbl_hash {
        actions = {
            action_hash;
        }
        const default_action = action_hash();
    }

    apply {
        tbl_hash.apply();
        res_1 = res_all[0:0];
        res_2 = res_all[1:1];
        res_3 = res_all[2:2];
        res_4 = res_all[3:3];
        res_5 = res_all[4:4];
    }
}

control hash_consolidate_and_split_srcip_dstip(
  in ipv4_addr_t srcIP,
  in ipv4_addr_t dstIP,
  out bit<16> res_all,
  out bit<1> res_1,
  out bit<1> res_2,
  out bit<1> res_3,
  out bit<1> res_4,
  out bit<1> res_5)(
  bit<32> polynomial)
{
    CRCPolynomial<bit<32>>(polynomial,
                           true,
                           false,
                           false,
                           32w0xFFFFFFFF,
                           32w0xFFFFFFFF
                           ) poly1;

    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly1) hash;

    action action_hash() {
        res_all = hash.get({srcIP[31:0], dstIP[31:0]});
    }

    table tbl_hash {
        actions = {
            action_hash;
        }
        const default_action = action_hash();
    }

   apply {
        tbl_hash.apply();
        res_1 = res_all[0:0];
        res_2 = res_all[1:1];
        res_3 = res_all[2:2];
        res_4 = res_all[3:3];
        res_5 = res_all[4:4];
    }
}
