#include <linux/bpf.h>
#include <bpf_helpers.h>

#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#include "../include.h"

#define FIBLOOKUP

//#define DEBUG

#ifdef DEBUG
#define bpf_printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
})
#endif

struct bpf_map_def SEC("maps") packets_map =
{
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct stats),
    .max_entries = 1
};

#ifndef FIBLOOKUP
static __always_inline void swapeth(struct ethhdr *eth)
{
    __u8 tmp[ETH_ALEN];

    memcpy(&tmp, &eth->h_source, ETH_ALEN);
    memcpy(&eth->h_source, &eth->h_dest, ETH_ALEN);
    memcpy(&eth->h_dest, &tmp, ETH_ALEN);
}
#endif

static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
    __u32 check = (__u32)iph->check;

    check += (__u32)htons(0x0100);
    iph->check = (__sum16)(check + (check >= 0xFFFF));

    return --iph->ttl;
}

static __always_inline void updatestats(__u16 len)
{
    // Update map.
    __u32 key = 0;
    struct stats *cnt = bpf_map_lookup_elem(&packets_map, &key);

    if (cnt)
    {
        cnt->pckts++;
        cnt->bytes += len;
    }
    else
    {
        struct stats newstats = {0};
        newstats.pckts = 1;
        newstats.bytes = len;

        bpf_map_update_elem(&packets_map, &key, &newstats, BPF_ANY);
    } 
}

SEC("xdpstats")
int prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;

    if (eth + 1 > (struct ethhdr *)data_end)
    {
        return XDP_DROP;
    }

    if (eth->h_proto != htons(ETH_P_IP))
    {
        return XDP_PASS;
    }

    struct iphdr *iph = data + sizeof (struct ethhdr);

    if (iph + 1 > (struct iphdr *)data_end)
    {
        return XDP_DROP;
    }

    if (iph->protocol != IPPROTO_UDP)
    {
        return XDP_PASS;
    }

    struct udphdr *udph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

    if (udph + 1 > (struct udphdr *)data_end)
    {
        return XDP_DROP;
    }

    #ifdef TARGETPORT
    if (udph->dest != htons(TARGETPORT))
    {
        return XDP_PASS;
    }
    #endif

    if (iph->ttl <= 1)
    {
        return XDP_PASS;
    }

    #ifdef FIBLOOKUP
    // Perform a FIB lookup to check for forwarding.
    struct bpf_fib_lookup params = {0};

    params.family = AF_INET;
    params.tos = iph->tos;
    params.l4_protocol = iph->protocol;
    params.tot_len = ntohs(iph->tot_len);
    params.ipv4_src = iph->saddr;
    params.ipv4_dst = iph->daddr;

    params.ifindex = ctx->ingress_ifindex;

    int fwd = bpf_fib_lookup(ctx, &params, sizeof(params), BPF_FIB_LOOKUP_OUTPUT);

    // Now check if we should forward this packet.
    if (fwd == BPF_FIB_LKUP_RET_SUCCESS)
    {
        // Reinitialize headers.
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        
        eth = data;

        if (eth + 1 > (struct ethhdr *)data_end)
        {
            return XDP_DROP;
        }

        iph = data + sizeof(struct ethhdr);

        if (unlikely(iph + 1 > (struct iphdr *)data_end))
        {
            return XDP_DROP;
        }

        // Update stats map.
        __u16 len = (long)ctx->data_end - (long)ctx->data;

        updatestats(len);

        // Decrease IP's TTL.
        ip_decrease_ttl(iph);

        // Swap ethernet source/destination MAC addresses.
        memcpy(eth->h_source, params.smac, ETH_ALEN);
        memcpy(eth->h_dest, params.dmac, ETH_ALEN);

        // TX path.
        return XDP_TX;
    }
    #else
        // No FIB lookup, so just switch ethernet MAC addresses.
        swapeth(eth);

        // Update stats map.
        __u16 len = (long)ctx->data_end - (long)ctx->data;

        updatestats(len);

        // Decrease IP's TTL.
        ip_decrease_ttl(iph);

        return XDP_TX;
    #endif

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";