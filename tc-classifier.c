#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include <iproute2/bpf_elf.h>
#include "tc-classifier.h"

#define ETH_LEN 14
#define MIN_MASK 20
#define DEFAULT_CLASS 1

union key_4 {
	u32 b32[2];
	u8 b8[8];
};

struct bpf_elf_map subnets SEC("maps") = {
    .type           = BPF_MAP_TYPE_LPM_TRIE,
    .size_key       = 8,
    .size_value     = sizeof(uint16_t),
    .pinning        = PIN_GLOBAL_NS,
    .max_elem       = 1024,
    .flags          = BPF_F_NO_PREALLOC,
};

SEC("prog")
int tc_main(struct __sk_buff *skb)
{
	unsigned char *head, *tail;
	u16 class = DEFAULT_CLASS;
	struct ethhdr *eth;
	struct iphdr *ip;
	u16 *match;
	union key_4 key;

	__be32 dest_ip;

	head = (void *)(unsigned long)skb->data;
	tail = (void *)(unsigned long)skb->data_end;

	if (head + sizeof(*eth) > tail) {
		class = 2;
		goto out;
	}

	eth = (void *)head;
	head += sizeof(*eth);

	if (__be16_to_cpu(eth->h_proto) != ETH_P_IP) {
		class = 3;
		goto out;
	}

	if (head + sizeof(*ip) > tail) {
		class = 4;
		goto out;
	}

	ip = (void *)head;

	if (head + ip->ihl * 4 > tail) {
		class = 5;
		goto out;
	}

	dest_ip = ip->daddr;

	key.b32[0] = 32;
	key.b8[4] = dest_ip & 0xff;
	key.b8[5] = (dest_ip >> 8) & 0xff;
	key.b8[6] = (dest_ip >> 16) & 0xff;
	key.b8[7] = (dest_ip >> 24) & 0xff;

	match = map_lookup_elem(&subnets, &key);
	if (match)
		class = *match;

out:

	skb->tc_classid = TC_H_MAKE(TC_H_ROOT, class);

	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
