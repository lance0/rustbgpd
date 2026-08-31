// SPDX-License-Identifier: GPL-2.0
// Bounded TC classifier for the disposable EVPN local-bias netns spike.
//
// This is deliberately not production packet parsing. It recognizes only the
// spike's fixed Ethernet/IPv4/UDP/4789/VXLAN-100 shape, one ES-peer VTEP, and
// one fixed unknown-unicast destination. Everything else passes unchanged.

#define SEC(name) __attribute__((section(name), used))

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;

struct __sk_buff {
    __u32 len;
    __u32 pkt_type;
    __u32 mark;
    __u32 queue_mapping;
    __u32 protocol;
    __u32 vlan_present;
    __u32 vlan_tci;
    __u32 vlan_proto;
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
    __u32 tc_index;
    __u32 cb[5];
    __u32 hash;
    __u32 tc_classid;
    __u32 data;
    __u32 data_end;
};

struct eth_header {
    __u8 destination[6];
    __u8 source[6];
    __u8 protocol[2];
} __attribute__((packed));

struct ipv4_header {
    __u8 version_ihl;
    __u8 tos;
    __u16 total_length;
    __u16 identification;
    __u8 fragment_offset[2];
    __u8 ttl;
    __u8 protocol;
    __u16 checksum;
    __u8 source[4];
    __u8 destination[4];
} __attribute__((packed));

struct udp_header {
    __u8 source[2];
    __u8 destination[2];
    __u8 length[2];
    __u8 checksum[2];
} __attribute__((packed));

#define TC_ACT_UNSPEC (-1)
#define IPPROTO_UDP 17
#define VXLAN_PORT 4789
#define VXLAN_VNI 100
#define LOCAL_BIAS_MARK_BIT 0x40000000
#define PARSER_DIAGNOSTIC_MARK_BIT 0x20000000

static __inline int is_fixed_unknown(const __u8 destination[6])
{
    return destination[0] == 0x02 && destination[1] == 0x00 &&
           destination[2] == 0x00 && destination[3] == 0x00 &&
           destination[4] == 0x00 && destination[5] == 0x50;
}

SEC("classifier")
int classify_local_bias(struct __sk_buff *skb)
{
    void *data = (void *)(unsigned long)skb->data;
    void *data_end = (void *)(unsigned long)skb->data_end;
    struct eth_header *outer_eth = data;

    // A second lab-only bit feeds the next TC filter's action counter and is
    // cleared there immediately. It proves direct-action execution without a
    // map; the local-bias bit remains independent and survives to CE egress.
    skb->mark |= PARSER_DIAGNOSTIC_MARK_BIT;

    if ((void *)(outer_eth + 1) > data_end)
        return TC_ACT_UNSPEC;
    if (outer_eth->protocol[0] != 0x08 || outer_eth->protocol[1] != 0x00)
        return TC_ACT_UNSPEC;

    struct ipv4_header *ipv4 = (void *)(outer_eth + 1);
    if ((void *)(ipv4 + 1) > data_end)
        return TC_ACT_UNSPEC;
    if ((ipv4->version_ihl >> 4) != 4 || ipv4->protocol != IPPROTO_UDP)
        return TC_ACT_UNSPEC;

    __u32 ipv4_length = (ipv4->version_ihl & 0x0f) * 4;
    if (ipv4_length < sizeof(*ipv4) || ipv4_length > 60)
        return TC_ACT_UNSPEC;
    __u16 fragment_offset = ((__u16)ipv4->fragment_offset[0] << 8) |
                            ipv4->fragment_offset[1];
    if ((fragment_offset & 0x3fff) != 0)
        return TC_ACT_UNSPEC;

    // 10.255.0.2, the fixed ES-peer address in the reused topology.
    if (ipv4->source[0] != 10 || ipv4->source[1] != 255 ||
        ipv4->source[2] != 0 || ipv4->source[3] != 2)
        return TC_ACT_UNSPEC;

    struct udp_header *udp = data + sizeof(*outer_eth) + ipv4_length;
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_UNSPEC;
    if (udp->destination[0] != (VXLAN_PORT >> 8) ||
        udp->destination[1] != (VXLAN_PORT & 0xff))
        return TC_ACT_UNSPEC;

    __u8 *vxlan = (void *)(udp + 1);
    if ((void *)(vxlan + 8) > data_end)
        return TC_ACT_UNSPEC;
    if ((vxlan[0] & 0x08) == 0)
        return TC_ACT_UNSPEC;
    if (vxlan[4] != 0 || vxlan[5] != 0 || vxlan[6] != VXLAN_VNI)
        return TC_ACT_UNSPEC;

    struct eth_header *inner_eth = (void *)(vxlan + 8);
    if ((void *)(inner_eth + 1) > data_end)
        return TC_ACT_UNSPEC;

    // Mark only B/M or the fixed unknown-unicast case. The fixed known MAC,
    // non-ES peers, and non-VXLAN traffic retain their incoming mark.
    if ((inner_eth->destination[0] & 0x01) != 0 ||
        is_fixed_unknown(inner_eth->destination))
        skb->mark |= LOCAL_BIAS_MARK_BIT;

    return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
