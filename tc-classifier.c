/*
 * Author:   Toke Høiland-Jørgensen (toke@toke.dk)
 * Date:     23 May 2018
 * Copyright (c) 2018, Toke Høiland-Jørgensen
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include <iproute2/bpf_elf.h>
#include <sys/types.h>
#include <stdint.h>

typedef uint8_t  u8;			/* Unsigned types of an exact size */
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#define SEC(NAME) __attribute__((section(NAME), used))

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)              \
   (*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif

static void *BPF_FUNC(map_lookup_elem, void *map, const void *key);

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

	if (head + sizeof(*eth) > tail)
		goto out;

	eth = (void *)head;
	head += sizeof(*eth);

	if (__be16_to_cpu(eth->h_proto) != ETH_P_IP ||
	    head + sizeof(*ip) > tail)
		goto out;

	ip = (void *)head;

	if (head + ip->ihl * 4 > tail)
		goto out;

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
