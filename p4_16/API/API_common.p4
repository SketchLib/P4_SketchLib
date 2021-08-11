#define PLAIN_HASH_SRCIP(TOTAL_LENGTH, HASH_LENGTH)                 \
  control HASH_COMPUTE_SRCIP_##TOTAL_LENGTH##_##HASH_LENGTH## (     \
    in ipv4_addr_t srcIP,                                           \
    out bit<##TOTAL_LENGTH##> result)(                              \
    bit<32> polynomial)                                             \
  {                                                                 \
      CRCPolynomial<bit<32>>(polynomial,                            \
                             true,                                  \
                             false,                                 \
                             false,                                 \
                             32w0xFFFFFFFF,                         \
                             32w0xFFFFFFFF                          \
                             ) poly1;                               \
                                                                    \
      Hash<bit<##HASH_LENGTH##>>(HashAlgorithm_t.CUSTOM, poly1) hash;\
                                                                    \
      action action_hash() {                                        \
          result = (bit<##TOTAL_LENGTH##>) hash.get({srcIP});       \
      }                                                             \
                                                                    \
      table tbl_hash {                                              \
          actions = {                                               \
              action_hash;                                          \
          }                                                         \
          const default_action = action_hash();                     \
      }                                                             \
                                                                    \
     apply {                                                        \
          tbl_hash.apply();                                         \
      }                                                             \
  }

PLAIN_HASH_SRCIP(12, 12)
PLAIN_HASH_SRCIP(15, 15)

PLAIN_HASH_SRCIP(16, 5)
PLAIN_HASH_SRCIP(16, 11)
PLAIN_HASH_SRCIP(16, 12)
PLAIN_HASH_SRCIP(16, 16)

PLAIN_HASH_SRCIP(20, 20)

PLAIN_HASH_SRCIP(32, 11)
PLAIN_HASH_SRCIP(32, 20)

#define PLAIN_HASH_SRCIP_DSTIP(TOTAL_LENGTH, HASH_LENGTH)           \
  control HASH_COMPUTE_SRCIP_DSTIP_##TOTAL_LENGTH##_##HASH_LENGTH## (\
    in ipv4_addr_t srcIP,                                           \
    in ipv4_addr_t dstIP,                                           \
    out bit<##TOTAL_LENGTH##> result)(                              \
    bit<32> polynomial)                                             \
  {                                                                 \
      CRCPolynomial<bit<32>>(polynomial,                            \
                             true,                                  \
                             false,                                 \
                             false,                                 \
                             32w0xFFFFFFFF,                         \
                             32w0xFFFFFFFF                          \
                             ) poly1;                               \
                                                                    \
      Hash<bit<##HASH_LENGTH##>>(HashAlgorithm_t.CUSTOM, poly1) hash;\
                                                                    \
      action action_hash() {                                        \
          result = (bit<##TOTAL_LENGTH##>) hash.get({srcIP[31:0], dstIP[31:0]}); \
      }                                                             \
                                                                    \
      table tbl_hash {                                              \
          actions = {                                               \
              action_hash;                                          \
          }                                                         \
          const default_action = action_hash();                     \
      }                                                             \
                                                                    \
     apply {                                                        \
          tbl_hash.apply();                                         \
      }                                                             \
  }

PLAIN_HASH_SRCIP_DSTIP(16, 16)
PLAIN_HASH_SRCIP_DSTIP(16, 11)
PLAIN_HASH_SRCIP_DSTIP(32, 32)

control CS_UPDATE(
  in bit<32> key,
  in bit<1> res,
  out bit<32> est)(
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

    Register<bit<32>, bit<16>>(32w4096) cs_table;

    RegisterAction<bit<32>, bit<16>, bit<32>>(cs_table) cs_action = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            if (res == 0) {
                register_data = register_data - 1;
            }
            else {
                register_data = register_data + 1;
            }
            result = register_data;
        }
    };

    apply {
        est = cs_action.execute(hash.get({key}));
        if (res == 0) {
            est = -est;
        }
    }
}

control CM_UPDATE(
  in bit<32> key,
  out bit<32> est)(
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

    Register<bit<32>, bit<16>>(32w4096) cs_table;

    RegisterAction<bit<32>, bit<16>, bit<32>>(cs_table) cs_action = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            register_data = register_data + 1;
            result = register_data;
        }
    };

    apply {
        est = cs_action.execute(hash.get({key}));
    }
}

control CALC_RNG(out bit<5> random_number)
{
    Random<bit<5>>() rng;
    action get_random() {
        random_number = rng.get();
    }
    table random {
        actions = { get_random; }
        default_action = get_random();
        size = 1;
    }
    apply {
        random.apply();
    }
}
