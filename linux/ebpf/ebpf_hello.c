#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

SEC("classifier")
int ebpf_hello(struct __sk_buff *skb) {
    static __u16 count = 0;
    count++;
    if (count < 10) {
        bpf_printk("ebpf_hello %d", count);
    }
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

/*
clang -target bpf -O2 -I/usr/include/$(uname -m)-linux-gnu -c ebpf_hello.c -o ebpf_hello.o 

tc qdisc add dev ens33 clsact
tc filter add dev ens33 ingress bpf obj ebpf_hello.o sec classifier direct-action

tc qdisc show dev ens33
tc filter show dev ens33 ingress

bpftool prog list  
*/


/*
clang -target bpf -O0 -c ebpf_hello.c -o ebpf_hello.o 
tc filter add dev ens33 ingress bpf obj ebpf_hello.o sec classifier direct-action

-O0导致报错:

libbpf: prog 'ebpf_hello': BPF program load failed: Invalid argument
libbpf: prog 'ebpf_hello': -- BEGIN PROG LOAD LOG --
unknown opcode 8d
processed 0 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --
libbpf: prog 'ebpf_hello': failed to load: -22
libbpf: failed to load object 'ebpf_hello.o'
Unable to load program
*/
