#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "headers.p4"
#include "util.p4"

struct metadata_t {
    bit<16> index;

    bit<1> f1;
    bit<1> f2;
    bit<1> f3;
    bit<1> f4;
    bit<1> f5;
    bit<1> f6;
    bit<1> f7;
    bit<1> f8;
    bit<1> f9;
    bit<1> f10;

    bit<1> f11;
    bit<1> f12;
    bit<1> f13;
    bit<1> f14;
    bit<1> f15;
    bit<1> f16;
    bit<1> f17;
    bit<1> f18;
    bit<1> f19;
    bit<1> f20;

    bit<1> f21;
    bit<1> f22;
    bit<1> f23;
    bit<1> f24;
    bit<1> f25;
    bit<1> f26;
    bit<1> f27;
    bit<1> f28;
    bit<1> f29;
    bit<1> f30;

    bit<1> f31;
    bit<1> f32;
}

#include "parser.p4"

#include "API_common.p4"
#include "API_O1_hash.p4"
#include "API_O2_hash.p4"
#include "API_O3_tcam.p4"
#include "API_O5_salu.p4"

#define DEFINE_REGISTER(R) \
    Register<bit<32>, bit<16>>(32w4096) reg_table_##R##;\
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_table_##R##) reg_update_##R## = {\
        void apply(inout bit<32> register_data, out bit<32> result) {\
            register_data = register_data + 1;\
        }\
    };

#define UPDATE(R) \
    reg_update_##R##.execute(ig_md.index);

#define APPLY(R) \
    if (ig_md.f##R## == 1) { \
        UPDATE(##R##) \
    }

#define SPLIT(R) \
    ig_md.f##R## = hdr.ipv4.src_addr[##R##:##R##];

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    DEFINE_REGISTER(1)
    DEFINE_REGISTER(2)
    DEFINE_REGISTER(3)
    DEFINE_REGISTER(4)
    DEFINE_REGISTER(5)
    DEFINE_REGISTER(6)
    DEFINE_REGISTER(7)
    DEFINE_REGISTER(8)
    DEFINE_REGISTER(9)
    DEFINE_REGISTER(10)

    DEFINE_REGISTER(11)
    DEFINE_REGISTER(12)
    DEFINE_REGISTER(13)
    DEFINE_REGISTER(14)
    DEFINE_REGISTER(15)
    DEFINE_REGISTER(16)
    DEFINE_REGISTER(17)
    DEFINE_REGISTER(18)
    DEFINE_REGISTER(19)
    DEFINE_REGISTER(20)

    DEFINE_REGISTER(21)
    DEFINE_REGISTER(22)
    DEFINE_REGISTER(23)
    DEFINE_REGISTER(24)
    DEFINE_REGISTER(25)
    DEFINE_REGISTER(26)
    DEFINE_REGISTER(27)
    DEFINE_REGISTER(28)
    DEFINE_REGISTER(29)
    DEFINE_REGISTER(30)

    DEFINE_REGISTER(31)
    DEFINE_REGISTER(32)

    HASH_COMPUTE_SRCIP_16_11(32w0x30243f0b) index_hash;

    action split() {
        SPLIT(1)
        SPLIT(2)
        SPLIT(3)
        SPLIT(4)
        SPLIT(5)
        SPLIT(6)
        SPLIT(7)
        SPLIT(8)
        SPLIT(9)
        SPLIT(10)

        SPLIT(11)
        SPLIT(12)
        SPLIT(13)
        SPLIT(14)
        SPLIT(15)
        SPLIT(16)
        SPLIT(17)
        SPLIT(18)
        SPLIT(19)
        SPLIT(20)

        SPLIT(21)
        SPLIT(22)
        SPLIT(23)
        SPLIT(24)
        SPLIT(25)
        SPLIT(26)
        SPLIT(27)
        SPLIT(28)
        SPLIT(29)
        SPLIT(30)

        SPLIT(31)
        ig_md.f32 = hdr.ipv4.src_addr[0:0];
    }
    apply {
        if(hdr.ethernet.ether_type == ETHERTYPE_IPV4) {
            split();
            index_hash.apply(hdr.ipv4.src_addr, ig_md.index);
            APPLY(1)
            APPLY(2)
            APPLY(3)
            APPLY(4)
            APPLY(5)
            APPLY(6)
            APPLY(7)
            APPLY(8)
            APPLY(9)
            APPLY(10)

            APPLY(11)
            APPLY(12)
            APPLY(13)
            APPLY(14)
            APPLY(15)
            APPLY(16)
            APPLY(17)
            APPLY(18)
            APPLY(19)
            APPLY(20)

            APPLY(21)
            APPLY(22)
            APPLY(23)
            APPLY(24)
            APPLY(25)
            APPLY(26)
            APPLY(27)
            APPLY(28)
            APPLY(29)
            APPLY(30)

            APPLY(31)
            APPLY(32)
        }
    }
}

struct my_egress_headers_t {
}

/********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}

Pipeline(
    SwitchIngressParser(),
    SwitchIngress(),
    SwitchIngressDeparser(),
    EgressParser(),
    EmptyEgress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;

