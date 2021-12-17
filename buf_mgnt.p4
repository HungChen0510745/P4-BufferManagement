/* -*- P4_16 -*- */
#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/

#define TIMEOUT 10000

const bit<16> ETHERTYPE_TPID = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_MIRR = 0x0FFF;

const int CPU_PORT = 64;

typedef bit<8>  pkt_type_t;
const pkt_type_t PKT_TYPE_NORMAL = 1;
const pkt_type_t PKT_TYPE_MIRROR = 2;

typedef bit<3> mirror_type_t;
const mirror_type_t MIRROR_TYPE_I2E = 1;
const mirror_type_t MIRROR_TYPE_E2E = 2;

typedef bit<32> queue_type_t;
typedef bit<32> threshold_type_t;
typedef bit<16> box_num_t;
const box_num_t box_num = 1024;

const int QUEUE_BUFFER = 20000;

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */


header mirror_h {
    pkt_type_t  pkt_type;
    bit<32> queue_length;
    bit<16> eport;
    threshold_type_t queue_threshold;
}

/* Standard ethernet header */
header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}


header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header queue_h {
    bit<32> queue_length;
    bit<16> eport;
    threshold_type_t queue_threshold;
}



/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct ingress_headers_t {
    mirror_h mirror_md;
    ethernet_h ethernet;
    ipv4_h ipv4;
    queue_h queue;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct ingress_metadata_t {
    bit<1> update;
    threshold_type_t qth;
    queue_type_t qlen;
    bit<32> pkt_block;
    bit<16> eport;
    bit<1> priority;
}

    /***********************  P A R S E R  **************************/
parser IngressParser(packet_in        pkt,
    /* User */
    out ingress_headers_t          hdr,
    out ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
            ETHERTYPE_MIRR : parse_queue;
            default: accept;
        }
    }
    
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }

    state parse_queue {
        pkt.extract(hdr.ipv4);
        pkt.extract(hdr.queue);
        meta.eport = hdr.queue.eport;
        meta.update = 1;
        meta.pkt_block = hdr.queue.queue_length;
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Ingress(
    /* User */
    inout ingress_headers_t                       hdr,
    inout ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{

    Register<threshold_type_t, box_num_t>(32w1024, QUEUE_BUFFER) bound_reg;
    RegisterAction<threshold_type_t, box_num_t, threshold_type_t> (bound_reg) update_bound_reg = {
        void apply(inout threshold_type_t value, out threshold_type_t read_value){
            if(meta.update == 1){
                value = hdr.queue.queue_threshold;
            }
            read_value = value;
        }
    };

    Register<threshold_type_t, box_num_t>(32w1024, 0) drop_reg;
    RegisterAction<threshold_type_t, box_num_t, threshold_type_t> (drop_reg) drop_reg_action = {
        void apply(inout threshold_type_t value){
            value = value+1;
        }
    };

    Register<queue_type_t, box_num_t>(32w1024, 0) queue_reg;    
    RegisterAction<queue_type_t, box_num_t, queue_type_t> (queue_reg) write_queue_reg_action = {
        void apply(inout queue_type_t value, out queue_type_t read_value){
            if(value > meta.qth){
                read_value = 0;
            }
            else{
                read_value = 1;
                value = value + meta.pkt_block;
            }
        }
    };    
    RegisterAction<queue_type_t, box_num_t, queue_type_t> (queue_reg) write_queue_reg_action2 = {
        void apply(inout queue_type_t value, out queue_type_t read_value){
            read_value = 1;
            value = meta.pkt_block;
        }
    };

    action send(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        meta.eport = (bit<16>)port;
        // set normal packet
        hdr.mirror_md.setValid();
        hdr.mirror_md.pkt_type = PKT_TYPE_NORMAL; 
    }

    action set_priority(bit<1> pri) {
        meta.priority = pri;
    }

    action set_pkt_range(bit<32> value){
        meta.pkt_block = value;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    table ipv4_host {
        key = { hdr.ipv4.dst_addr : exact; }
        actions = {
            send; drop;
        }
        size = 15;
    }

    table pkt_range {
        key = {
            hdr.ipv4.total_len : range;
        }
        actions = {
            set_pkt_range;
        }
        const entries = {
            #include "table-range.p4"
        }
        default_action = set_pkt_range(1);
	    size = 400;
    }

    table time_priority {
        key = {
            hdr.ipv4.src_addr : exact;
        }
        actions = {
            set_priority;
        }
        default_action = set_priority(1);
	    size = 10;
    }

    apply {
        if(hdr.ipv4.isValid()){
            if(hdr.queue.isValid()){
                meta.qth = update_bound_reg.execute(meta.eport);
                meta.qlen = write_queue_reg_action2.execute(meta.eport);
                drop();
            }
            else{
                ipv4_host.apply();
                pkt_range.apply();
                time_priority.apply();
                if(meta.priority == 0){
                    ig_tm_md.qid = 0; 
                }
                else{
                    ig_tm_md.qid = 1;
                    meta.eport = meta.eport+512;
                }
                meta.qth = update_bound_reg.execute(meta.eport);
                hdr.mirror_md.eport = meta.eport;
                meta.qlen = write_queue_reg_action.execute(meta.eport);
                if(meta.qlen == 0){
                    drop();
                    drop_reg_action.execute(meta.eport);
                }
            }
        }
    }
}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout ingress_headers_t                       hdr,
    in    ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct egress_headers_t {
    mirror_h mirror_md;
    ethernet_h ethernet;
    ipv4_h ipv4;
    queue_h queue;
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/
struct egress_metadata_t {
    MirrorId_t egr_mir_ses;   // Egress mirror session ID
    pkt_type_t pkt_type;
    bit<32> queue_length;
    threshold_type_t new_queue_threshold;
    threshold_type_t old_queue_threshold;
    bit<16> eport;
    bit<16> count;
    int<32> offset;
    bit<32> state;
    bit<32> eva;
    bit<32> lock;
    bit<32> state2;
}

struct pair{
    bit<32> old;
    bit<32> count;
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out egress_headers_t          hdr,
    out egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition parse_metadata;
    }

    state parse_metadata {
        pkt.extract(hdr.mirror_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
            default: accept;
        }
    }
    
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout egress_headers_t                          hdr,
    inout egress_metadata_t                         meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    Register<threshold_type_t, box_num_t>(32w1024, QUEUE_BUFFER) thrshold_reg;
    RegisterAction<threshold_type_t, box_num_t, threshold_type_t> (thrshold_reg) write_thrshold_reg = {
        void apply(inout threshold_type_t value, out threshold_type_t read_value){
            read_value = value;
            if(meta.new_queue_threshold > QUEUE_BUFFER){
                value = QUEUE_BUFFER;
            }
            else{
                value = meta.new_queue_threshold;
            }
        }
    };
    RegisterAction<threshold_type_t, box_num_t, threshold_type_t> (thrshold_reg) read_thrshold_reg = {
        void apply(inout threshold_type_t value, out threshold_type_t read_value){
            read_value = value;
        }
    };

    Register<bit<16>, box_num_t>(32w512, 0) counter_reg;
    RegisterAction<bit<16>, box_num_t, bit<16>> (counter_reg) update_counter_reg = {
        void apply(inout bit<16> value, out bit<16> read_value){
            if(value == 10){
                value = 0;
            }
            else{
                value = value +1;
            }
            read_value = value;
        }
    };

    Register<int<32>, box_num_t>(32w1, QUEUE_BUFFER) space_reg;
    RegisterAction<int<32>, box_num_t, int<32>> (space_reg) update_space_reg = {
        void apply(inout int<32> value, out int<32> read_value){
            read_value = value - meta.offset;
            value = read_value;
        }
    };

    Register<bit<32>, box_num_t>(32w1024, 0) occupy_reg;
    RegisterAction<bit<32>, box_num_t, int<32>> (occupy_reg) update_occupy_reg = {
        void apply(inout bit<32> value, out int<32> read_value){
            read_value = (int<32>)meta.queue_length - (int<32>)value;
            value = meta.queue_length;
        }
    };

    Register<bit<32>, box_num_t>(32w1024, 0) enq_reg;
    RegisterAction<bit<32>, box_num_t, bit<32>> (enq_reg) update_enq_reg = {
        void apply(inout bit<32> value){
            value = (bit<32>)eg_intr_md.enq_qdepth;
        }
    };

    Register<bit<32>, box_num_t>(32w1024, 0) state_reg;
    RegisterAction<bit<32>, box_num_t, bit<32>> (state_reg) update_normal_state_reg = {
        void apply(inout bit<32> value, out bit<32> read_value){
            if(value > 0){
                value = value - 1;
            }
            read_value = value;
        }
    };
    RegisterAction<bit<32>, box_num_t, bit<32>> (state_reg) update_ev_state_reg = {
        void apply(inout bit<32> value, out bit<32> read_value){
            if(value < 1000000){
                value = value + 1;
            }
            read_value = value;
        }
    };

    Register<bit<32>, box_num_t>(32w1024, 0) lock_reg;
    RegisterAction<bit<32>, box_num_t, bit<32>> (lock_reg) update_lock_reg = {
        void apply(inout bit<32> value, out bit<32> read_value){
            if(meta.state > 700){
                value = 1;
            }
            else{
                if(meta.state < 300){
                    value = 0;

                }
            }
            read_value = value;
        }
    };

    Register<bit<32>, box_num_t>(32w1024, 0) return_reg;
    RegisterAction<bit<32>, box_num_t, bit<32>> (return_reg) update_return_reg = {
        void apply(inout bit<32> value, out bit<32> read_value){
            if(meta.lock == 1){
                value = 5000;
            }
            else{
                if(value > 0){
                    value = value - 1;
                }
            }
            read_value = value;
        }
    };

    Register<bit<32>, box_num_t>(32w1024, 0) eva_reg;
    RegisterAction<bit<32>, box_num_t, bit<32>> (eva_reg) update_eva_reg = {
        void apply(inout bit<32> value, out bit<32> read_value){
            if(meta.state2  > 0){
                value = 1;
            }
            else{
                value = 0;
            }
            read_value = value;
        }
    };

    action set_mirror(MirrorId_t egr_ses) {
        meta.egr_mir_ses = egr_ses;
        meta.pkt_type = PKT_TYPE_MIRROR;
        meta.queue_length = (bit<32>) eg_intr_md.deq_qdepth;
        eg_dprsr_md.mirror_type = MIRROR_TYPE_E2E;
    }

    action set_queue() {
        hdr.queue.setValid();
        hdr.queue.eport = hdr.mirror_md.eport;
        hdr.queue.queue_length = hdr.mirror_md.queue_length;
        hdr.queue.queue_threshold = read_thrshold_reg.execute(hdr.mirror_md.eport);
        hdr.ethernet.ether_type = 0x0FFF;
    }

    table mirror_fwd {
        key = {
            eg_intr_md.egress_port  : exact;
        }

        actions = {
            set_mirror;
        }

        size = 512;
    }

    apply {
        if(hdr.mirror_md.pkt_type == PKT_TYPE_NORMAL){
            meta.eport = hdr.mirror_md.eport;

            update_enq_reg.execute(meta.eport);

            // compute reamined buffer in traffic manager, and compute threshold (= remained buffer)
            meta.queue_length = (bit<32>)eg_intr_md.deq_qdepth;
            meta.offset = update_occupy_reg.execute(meta.eport);
            meta.new_queue_threshold = (bit<32>)update_space_reg.execute(0);

            if(meta.eport[9:9] == 0){//time-sensitive: absorb as much as possible
                meta.new_queue_threshold = meta.new_queue_threshold + meta.queue_length;
            }
            else{//non time-sensitive: evacutaion
                //Judge state
                bool is_dif = (meta.queue_length[31:10] != 0);
                if(is_dif){
                    meta.state = update_ev_state_reg.execute(meta.eport);
                }
                else{
                    meta.state = update_normal_state_reg.execute(meta.eport);
                }
                meta.lock = update_lock_reg.execute(meta.eport);
                meta.state2 = update_return_reg.execute(meta.eport);
                meta.eva = update_eva_reg.execute(meta.eport);

                if(meta.eva  == 1){
                    meta.new_queue_threshold = 3000;
                }
            }

            // update record register of threshold
            meta.old_queue_threshold = (bit<32>)write_thrshold_reg.execute(meta.eport);

            // update count register
            meta.count = update_counter_reg.execute(meta.eport);

            // decide whether to mirror back a pkt to update ingress register
            if(meta.count == 10 || meta.new_queue_threshold != meta.old_queue_threshold){
                mirror_fwd.apply();
            }
        }
        else{
            // set information to update ingress regisers
            set_queue();
        }

    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout egress_headers_t                       hdr,
    in    egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    Mirror() mirror;
    apply {
        if (eg_dprsr_md.mirror_type == MIRROR_TYPE_E2E) {
            mirror.emit<mirror_h>(meta.egr_mir_ses, {meta.pkt_type, meta.queue_length, meta.eport, meta.new_queue_threshold});
        }
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.queue);
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

