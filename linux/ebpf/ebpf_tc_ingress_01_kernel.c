/*
文件目标:
1.内核态程序, 做网络数据包的转发.
2.转发规则由用户态程序下发并作配置持久化, 每一条转发规则包含 规则id, 数据包类型, 源ip和port, 目的ip和port, 目标ip和port.
如针对tcp报文, 源ip和port是 192.168.23.1:8023, 目的ip和port是 192.168.23.62:8023的数据, 如果匹配到转发规则, 则转发到192.168.23.62:18023.
如针对udp报文, 源ip和port是 192.168.23.1:8024, 目的ip和port是 192.168.23.62:8024的数据, 如果匹配到转发规则, 则转发到192.168.23.62:18024.

eBPF TC ingress program for packet forwarding based on user-defined rules.
Rules are stored in a hash map and include protocol, source/dest IP/port, and target IP/port.
Supports TCP and UDP packets within port range 8000-8100.

ubuntu 24.04
Linux xxxxxx 6.11.0-21-generic #21~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Mon Feb 24 16:52:15 UTC 2 x86_64 x86_64 x86_64 GNU/Linux

apt install -y clang llvm libbpf-dev
Ubuntu clang version 18.1.3 (1ubuntu1)

clang -target bpf -O2 -I/usr/include/$(uname -m)-linux-gnu/ -c ebpf_tc_ingress_01_kernel.c -o ebpf_tc_ingress_01_kernel.o

sudo tc qdisc add dev ens33 clsact
sudo tc filter add dev ens33 ingress bpf obj ebpf_tc_ingress_01_kernel.o sec classifier

sudo tc qdisc show dev ens33 clsact
*/


#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h> // for bpf_ntohs

// Port range for destination port check
#define PORT_MIN 8000
#define PORT_MAX 8100

// Key for forwarding rules
struct rule_key {
    __u8 protocol;      // Protocol (IPPROTO_TCP or IPPROTO_UDP)
    __u32 src_ip;       // Source IP
    __u16 src_port;     // Source port
    __u32 dst_ip;       // Destination IP
    __u16 dst_port;     // Destination port
};

// Value for forwarding rules
struct rule_value {
    __u8 rule_id;       // Rule ID (0-255)
    __u32 target_ip;    // Target IP
    __u16 target_port;  // Target port
};

// Hash map to store forwarding rules
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct rule_key);
    __type(value, struct rule_value);
} forward_rules SEC(".maps");

// Global array to store logging configuration
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} log_enable_map SEC(".maps");

// Validate packet headers
static __always_inline int packets_valid_check(struct __sk_buff *skb,
                                              struct ethhdr **eth,
                                              struct iphdr **ip)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Parse Ethernet header
    *eth = data;
    if ((void *)(*eth + 1) > data_end)
        return 0;

    // Check if packet is IP
    if ((*eth)->h_proto != __constant_htons(ETH_P_IP))
        return 0;

    // Parse IP header
    *ip = (struct iphdr *)((void *)*eth + sizeof(**eth));
    if ((void *)(*ip + 1) > data_end)
        return 0;

    // Check if protocol is TCP or UDP
    if ((*ip)->protocol != IPPROTO_TCP && (*ip)->protocol != IPPROTO_UDP)
        return 0;

    return 1;
}

// Update IP checksum
static __always_inline void update_ip_checksum(struct iphdr *ip)
{
    __u32 csum = 0;
    __u16 *ptr = (__u16 *)ip;
    int len = sizeof(*ip) / 2;

    ip->check = 0;
    for (int i = 0; i < len; i++)
        csum += ptr[i];
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = ~csum;
}

// Update TCP/UDP checksum
static __always_inline void update_l4_checksum(struct __sk_buff *skb,
                                              struct iphdr *ip,
                                              void *l4_hdr,
                                              __u8 protocol,
                                              __u32 old_ip,
                                              __u32 new_ip,
                                              __u16 old_port,
                                              __u16 new_port)
{
    void *data_end = (void *)(long)skb->data_end;
    __u32 csum = 0;
    __u16 *ptr;
    int len;

    // Pseudo-header: source IP, destination IP, protocol, length
    csum += ip->saddr & 0xFFFF;
    csum += (ip->saddr >> 16) & 0xFFFF;
    csum += old_ip & 0xFFFF;
    csum += (old_ip >> 16) & 0xFFFF;
    csum += __constant_htons(protocol);

    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_hdr;
        if ((void *)(tcp + 1) > data_end)
            return;
        len = bpf_ntohs(ip->tot_len) - (ip->ihl * 4);
        csum += __constant_htons(len);
        tcp->check = 0;
        ptr = (__u16 *)tcp;
        len = len / 2;
    } else { // UDP
        struct udphdr *udp = l4_hdr;
        if ((void *)(udp + 1) > data_end)
            return;
        len = bpf_ntohs(udp->len);
        csum += __constant_htons(len);
        udp->check = 0;
        ptr = (__u16 *)udp;
        len = len / 2;
    }

    // Subtract old destination IP and port
    csum -= old_ip & 0xFFFF;
    csum -= (old_ip >> 16) & 0xFFFF;
    csum -= old_port;

    // Add new destination IP and port
    csum += new_ip & 0xFFFF;
    csum += (new_ip >> 16) & 0xFFFF;
    csum += new_port;

    // Calculate checksum for L4 header and data
    for (int i = 0; i < len && (void *)(ptr + i + 1) <= data_end; i++)
        csum += ptr[i];

    // Fold checksum
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);

    // Set checksum
    if (protocol == IPPROTO_TCP)
        ((struct tcphdr *)l4_hdr)->check = ~csum;
    else
        ((struct udphdr *)l4_hdr)->check = (csum == 0) ? 0xFFFF : ~csum;
}

// Process TCP packet
static __always_inline int process_tcp_packet(struct __sk_buff *skb,
                                             struct iphdr *ip,
                                             struct rule_key *key,
                                             __u8 log_enable)
{
    void *data_end = (void *)(long)skb->data_end;
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    key->src_port = tcp->source;
    key->dst_port = tcp->dest;

    // Ignore packets with destination port outside PORT_MIN-PORT_MAX
    if (bpf_ntohs(key->dst_port) < PORT_MIN || bpf_ntohs(key->dst_port) > PORT_MAX)
        return TC_ACT_OK;

    // Lookup forwarding rule
    struct rule_value *value = bpf_map_lookup_elem(&forward_rules, key);
    if (value) {
        // Log if enabled
        if (log_enable) {
            // 参数只能有3个.
            //bpf_printk("UDP: rule_id=%u, src=%x:%u\n", value->rule_id, bpf_ntohl(key->src_ip), bpf_ntohs(key->src_port));
            //bpf_printk("UDP: rule_id=%u, dst=%x:%u\n", value->rule_id, bpf_ntohl(key->dst_ip), bpf_ntohs(key->dst_port));
            //bpf_printk("UDP: rule_id=%u, target=%x:%u\n", value->rule_id, bpf_ntohl(value->target_ip), bpf_ntohs(value->target_port));
        }

        // Store old values for checksum update
        __u32 old_ip = ip->daddr;
        __u16 old_port = tcp->dest;

        // Modify destination IP and port
        ip->daddr = value->target_ip;
        tcp->dest = value->target_port;

        // Update checksums
        update_ip_checksum(ip);
        update_l4_checksum(skb, ip, tcp, IPPROTO_TCP, old_ip, value->target_ip,
                          old_port, value->target_port);
    }

    return TC_ACT_OK;
}

// Process UDP packet
static __always_inline int process_udp_packet(struct __sk_buff *skb,
                                             struct iphdr *ip,
                                             struct rule_key *key,
                                             __u8 log_enable)
{
    void *data_end = (void *)(long)skb->data_end;
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;

    key->src_port = udp->source;
    key->dst_port = udp->dest;

    // Ignore packets with destination port outside PORT_MIN-PORT_MAX
    if (bpf_ntohs(key->dst_port) < PORT_MIN || bpf_ntohs(key->dst_port) > PORT_MAX)
        return TC_ACT_OK;

    // Lookup forwarding rule
    struct rule_value *value = bpf_map_lookup_elem(&forward_rules, key);
    if (value) {
        // Log if enabled
        if (log_enable) {
            // 参数只能有3个.
            //bpf_printk("UDP: rule_id=%u, src=%x:%u\n", value->rule_id, bpf_ntohl(key->src_ip), bpf_ntohs(key->src_port));
            //bpf_printk("UDP: rule_id=%u, dst=%x:%u\n", value->rule_id, bpf_ntohl(key->dst_ip), bpf_ntohs(key->dst_port));
            //bpf_printk("UDP: rule_id=%u, target=%x:%u\n", value->rule_id, bpf_ntohl(value->target_ip), bpf_ntohs(value->target_port));
        }
        // Store old values for checksum update
        __u32 old_ip = ip->daddr;
        __u16 old_port = udp->dest;

        // Modify destination IP and port
        ip->daddr = value->target_ip;
        udp->dest = value->target_port;

        // Update checksums
        update_ip_checksum(ip);
        update_l4_checksum(skb, ip, udp, IPPROTO_UDP, old_ip, value->target_ip,
                          old_port, value->target_port);
    }

    return TC_ACT_OK;
}

SEC("classifier")
int tc_ingress_01_kernel(struct __sk_buff *skb)
{
    struct ethhdr *eth;
    struct iphdr *ip;

    // Validate packet
    if (!packets_valid_check(skb, &eth, &ip))
        return TC_ACT_OK;

    // Read log enable flag from global array
    __u8 log_enable = 0;
/*
    __u32 log_key = 0;
    __u8 *log_val = bpf_map_lookup_elem(&log_enable_map, &log_key);
    if (log_val)
        log_enable = *log_val;


    // Initialize rule key
    struct rule_key key = {
        .protocol = ip->protocol,
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
    };

    // Process TCP or UDP packet
    if (ip->protocol == IPPROTO_TCP)
        return process_tcp_packet(skb, ip, &key, log_enable);
    else if (ip->protocol == IPPROTO_UDP)
        return process_udp_packet(skb, ip, &key, log_enable);
*/
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

/*
tc filter add dev ens33 ingress bpf obj ebpf_tc_ingress_01_kernel.o sec classifier报错

libbpf: BTF is required, but is missing or corrupted.
ERROR: opening BPF object file failed
Unable to load program
*/

/*
clang -target bpf -O2 -g -I/usr/include/$(uname -m)-linux-gnu/ -c ebpf_tc_ingress_01_kernel.c -o ebpf_tc_ingress_01_kernel.o
tc filter add dev ens33 ingress bpf obj ebpf_tc_ingress_01_kernel.o sec classifier 加-g调试 疯狂刷屏

libbpf: BTF is required, but is missing or corrupted.
ERROR: opening BPF object file failed
Unable to load program
*/