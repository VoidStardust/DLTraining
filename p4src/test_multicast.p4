#include <core.p4>
#include <tna.p4>

// #define LONG_SUP

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
 *************************************************************************/
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_ARP  = 0x0806;

const bit<8> IPV4_PROTOCOL_TCP = 6;
const bit<8> IPV4_PROTOCOL_UDP = 17;

const int IPV4_HOST_SIZE = 65536;
const int IPV4_LPM_SIZE  = 12288;

//
#define INDEX_WIDTH   32
#define INDEX_SIZE    128

#define VALUE_WIDTH   32

#define COUNTER_WIDTH 32

#define NODE_SIZE     1
#define NODE_MAP      0x00000001

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
header ethernet_h 
{
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header arp_h
{
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8>  hw_addr_len;
    bit<8>  proto_addr_len;
    bit<16> opcode;

    bit<48> src_hw_addr;
    bit<32> src_proto_addr;
    bit<48> dst_hw_addr;
    bit<32> dst_proto_addr;
}

header ipv4_h
{
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header tcp_h
{
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_t
{
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
    bit<16> checksum;
}

/* Customized struct */

header payload_t
{
    bit<32> bitmap;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<1>  resend;
    bit<1>  is_ack;
    bit<1>  is_agg;
    bit<1>  is_clr;

    bit<156> __pad;

    bit<32> value1;
    bit<32> value2;
    bit<32> value3;
    bit<32> value4;
    bit<32> value5;
    bit<32> value6;
    bit<32> value7;
    bit<32> value8;
}

#define VALUE_REG(i)                                                                  \
    Register<bit<VALUE_WIDTH>, bit<INDEX_WIDTH>>(INDEX_SIZE) value_##i##_reg;         \
    RegisterAction<bit<VALUE_WIDTH>,                                                  \
                   bit<INDEX_WIDTH>,                                                  \
                   bit<VALUE_WIDTH>>(value_##i##_reg)                                 \
    value_##i##_add = {                                                               \
        void apply(inout bit<VALUE_WIDTH> register_data, out bit<VALUE_WIDTH> result) \
        {                                                                             \
            register_data = register_data + hdr.load.value##i##;                      \
            result = register_data;                                                   \
        }                                                                             \
    };                                                                                \
    RegisterAction<bit<VALUE_WIDTH>,                                                  \
                   bit<INDEX_WIDTH>,                                                  \
                   bit<VALUE_WIDTH>>(value_##i##_reg)                                 \
    value_##i##_get = {                                                               \
        void apply(inout bit<VALUE_WIDTH> register_data, out bit<VALUE_WIDTH> result) \
        {                                                                             \
            result = register_data;                                                   \
        }                                                                             \
    };                                                                                \
    RegisterAction<bit<VALUE_WIDTH>,                                                  \
                   bit<INDEX_WIDTH>,                                                  \
                   bit<VALUE_WIDTH>>(value_##i##_reg)                                 \
    value_##i##_rst = {                                                               \
        void apply(inout bit<VALUE_WIDTH> register_data, out bit<VALUE_WIDTH> result) \
        {                                                                             \
            result = register_data;                                                   \
            register_data = 0;                                                        \
        }                                                                             \
    }


/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
 
/***********************  H E A D E R S  ************************/

struct my_ingress_headers_t
{
    ethernet_h ethernet;
    arp_h      arp;
    ipv4_h     ipv4;
    tcp_h      tcp;
    udp_t      udp;
    payload_t  load;
}

/******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t
{
    bit<32> dst_ipv4;
}

/***********************  P A R S E R  **************************/

// see includes/parsers.p4
parser IngressParser(packet_in       pkt,
    /* User */    
    out my_ingress_headers_t         hdr,
    out my_ingress_metadata_t        meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start
    {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition meta_init;
    }

    state meta_init
    {
        meta.dst_ipv4 = 0;
        transition parse_load;
    }

    state parse_ethernet
    {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type)
        {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_ARP : parse_arp;
            default       : accept;
        }
    }

    state parse_arp
    {
        pkt.extract(hdr.arp);
        meta.dst_ipv4 = hdr.arp.dst_proto_addr;
        
        transition accept;
    }

    state parse_ipv4
    {
        pkt.extract(hdr.ipv4);
        meta.dst_ipv4 = hdr.ipv4.dst_addr;

        transition select(hdr.ipv4.protocol)
        {
            IPV4_PROTOCOL_TCP: parse_tcp;
            IPV4_PROTOCOL_UDP: parse_udp;
            default          : accept;
        }
    }

    state parse_tcp
    {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp
    {
        pkt.extract(hdr.udp);
        transition parse_load;
    }

    state parse_load
    {
        pkt.extract(hdr.load);
        transition accept;
    }
}

/***************** M A T C H - A C T I O N  *********************/

control Ingress(
    /* User */
    inout my_ingress_headers_t                      hdr,
    inout my_ingress_metadata_t                     meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t              ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md)
{
    // forward
    action send(PortId_t port)
    {
        ig_tm_md.ucast_egress_port = port;
    }

    action multicast(MulticastGroupId_t mcast_grp)
    {
        ig_tm_md.mcast_grp_a = mcast_grp;
    }

    VALUE_REG(1);
    VALUE_REG(2);
    VALUE_REG(3);
    VALUE_REG(4);
    VALUE_REG(5);
    VALUE_REG(6);
    VALUE_REG(7);
    VALUE_REG(8);

    bit<32> count_value = 1;
    Register<bit<COUNTER_WIDTH>, bit<INDEX_WIDTH>>(INDEX_SIZE) counter_reg;
    RegisterAction<bit<COUNTER_WIDTH>,
                   bit<INDEX_WIDTH>,
                   bit<COUNTER_WIDTH>>(counter_reg)
    counter_add = {
        void apply(inout bit<COUNTER_WIDTH> register_data, out bit<COUNTER_WIDTH> result)
        {
            // if(register_data >= NODE_SIZE)
            //     register_data = 0;

            register_data = register_data + count_value;
            result = register_data;
        }
    };
    RegisterAction<bit<COUNTER_WIDTH>,
                   bit<INDEX_WIDTH>,
                   bit<COUNTER_WIDTH>>(counter_reg)
    counter_get = {
        void apply(inout bit<COUNTER_WIDTH> register_data, out bit<COUNTER_WIDTH> result)
        {
            result = register_data;
        }
    };
    RegisterAction<bit<COUNTER_WIDTH>,
                   bit<INDEX_WIDTH>,
                   bit<COUNTER_WIDTH>>(counter_reg)
    counter_rst = {
        void apply(inout bit<COUNTER_WIDTH> register_data, out bit<COUNTER_WIDTH> result)
        {
            result = register_data;
            register_data = 0;
        }
    };

    Register<bit<32>, bit<INDEX_WIDTH>>(INDEX_SIZE) node_map_reg;
    RegisterAction<bit<32>,
                   bit<INDEX_WIDTH>,
                   bit<32>>(node_map_reg)
    node_map_merge = {
        void apply(inout bit<32> register_data, out bit<32> result)
        {
            bit<32> temp = register_data & hdr.load.bitmap;
            register_data = register_data | hdr.load.bitmap;
            result = temp;
            // if(register_data == NODE_MAP)
            //     register_data = 0;
        }
    };
    RegisterAction<bit<32>,
                   bit<INDEX_WIDTH>,
                   bit<32>>(node_map_reg)
    node_map_check = {
        void apply(inout bit<32> register_data, out bit<32> result)
        {
            bit<32> temp = register_data & hdr.load.bitmap;
            result = temp;
        }
    };
    RegisterAction<bit<32>,
                   bit<INDEX_WIDTH>,
                   bit<32>>(node_map_reg)
    node_map_clean = {
        void apply(inout bit<32> register_data, out bit<32> result)
        {
            result = register_data;
            register_data = 0;
        }
    };

    Register<bit<32>, bit<INDEX_WIDTH>>(INDEX_SIZE) ack_map_reg;
    RegisterAction<bit<32>,
                   bit<INDEX_WIDTH>,
                   bit<32>>(ack_map_reg)
    ack_map_merge = {
        void apply(inout bit<32> register_data, out bit<32> result)
        {
            register_data = register_data | hdr.load.bitmap;
            result = register_data;
            if(register_data == NODE_MAP)
                register_data = 0;
        }
    };
    
    apply
    {
        if(hdr.load.isValid())
        {
            bit<32> status;
            bit<32> i;
            
            if(hdr.load.is_ack == 1)
            {
                status = ack_map_merge.execute(hdr.load.ack_no);
                if(status == NODE_MAP) // full
                {
                    node_map_clean.execute(hdr.load.ack_no);

                    counter_rst.execute(hdr.load.ack_no);

                    value_1_rst.execute(hdr.load.ack_no);
                    value_2_rst.execute(hdr.load.ack_no);
                    value_3_rst.execute(hdr.load.ack_no);
                    value_4_rst.execute(hdr.load.ack_no);
                    value_5_rst.execute(hdr.load.ack_no);
                    value_6_rst.execute(hdr.load.ack_no);
                    value_7_rst.execute(hdr.load.ack_no);
                    value_8_rst.execute(hdr.load.ack_no);

                    hdr.load.is_clr = 1;

                    multicast(1);
                }
                else // not full
                {
                    // reply clc
                    send(192);
                }
            }
            else if(hdr.load.is_agg == 1)
            {
                // if(hdr.load.resend != 1)
                // {
                //     status = node_map_merge.execute(hdr.load.seq_no);
                // }
                // else
                // {
                //     status = node_map_check.execute(hdr.load.seq_no);
                // }

                status = node_map_merge.execute(hdr.load.seq_no);
                if(status != 0) // already aggregated
                {
                    count_value = 0;

                    hdr.load.value1 = 0;
                    hdr.load.value2 = 0;
                    hdr.load.value3 = 0;
                    hdr.load.value4 = 0;
                    hdr.load.value5 = 0;
                    hdr.load.value6 = 0;
                    hdr.load.value7 = 0;
                    hdr.load.value8 = 0;
                }
                else
                {
                    count_value = 1;
                }

                i = counter_add.execute(hdr.load.seq_no);
                if(i >= NODE_SIZE)
                {
                    if(status == 0)
                    {
                        multicast(1);
                    }
                    else
                    {
                        send(ig_intr_md.ingress_port);
                    }
                }
                else
                {
                    send(192);
                }

                hdr.load.value1 = value_1_add.execute(hdr.load.seq_no);
                hdr.load.value2 = value_2_add.execute(hdr.load.seq_no);
                hdr.load.value3 = value_3_add.execute(hdr.load.seq_no);
                hdr.load.value4 = value_4_add.execute(hdr.load.seq_no);
                hdr.load.value5 = value_5_add.execute(hdr.load.seq_no);
                hdr.load.value6 = value_6_add.execute(hdr.load.seq_no);
                hdr.load.value7 = value_7_add.execute(hdr.load.seq_no);
                hdr.load.value8 = value_8_add.execute(hdr.load.seq_no);
            }
        }
    }
}

/*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out                  pkt,
    /* User */
    inout my_ingress_headers_t                      hdr,
    in    my_ingress_metadata_t                     meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    Checksum() ipv4_checksum;
    
    apply
    {
        hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
        });

        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

/***********************  H E A D E R S  ************************/

struct my_egress_headers_t
{
}

/********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t
{
}

/***********************  P A R S E R  **************************/

parser EgressParser(packet_in       pkt,
    /* User */
    out my_egress_headers_t         hdr,
    out my_egress_metadata_t        meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t eg_intr_md)
{
    state start
    {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

/***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                         hdr,
    inout my_egress_metadata_t                        meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                 eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_oport_md)
{
    apply
    {
    }
}

/*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out                  pkt,
    /* User */
    inout my_egress_headers_t                      hdr,
    in    my_egress_metadata_t                     meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t eg_dprsr_md)
{
    apply
    {
        pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/

Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
