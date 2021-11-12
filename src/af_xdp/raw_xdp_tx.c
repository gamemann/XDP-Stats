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

struct bpf_map_def SEC("maps") xsks_map =
{
    .type = BPF_MAP_TYPE_XSKMAP,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = MAXCPUS
};

struct bpf_map_def SEC("maps") packets_map =
{
    .type = BPF_MAP_TYPE_ARRAY,
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

    // If FIB lookup is defined, perform lookup and set correct MAC addresses.
    #ifdef FIBLOOKUP
    struct bpf_fib_lookup params = {0};

    params.family = AF_INET;
    params.tos = iph->tos;
    params.l4_protocol = iph->protocol;
    params.tot_len = ntohs(iph->tot_len);
    params.ipv4_src = iph->saddr;
    params.ipv4_dst = iph->daddr;

    params.ifindex = ctx->ingress_ifindex;

    int fwd = bpf_fib_lookup(ctx, &params, sizeof(params), BPF_FIB_LOOKUP_OUTPUT);

    // Drop packet if FIB lookup fails.
    if (fwd != BPF_FIB_LKUP_RET_SUCCESS)
    {
        return XDP_DROP;
    }

    // Reinitialize headers.
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

    // Swap ethernet source/destination MAC addresses.
    memcpy(eth->h_source, params.smac, ETH_ALEN);
    memcpy(eth->h_dest, params.dmac, ETH_ALEN);
    #else
    // Otherwise, switch ethernet MAC addresses.
    swapeth(eth);
    #endif

    // Decrease IP's TTL.
    ip_decrease_ttl(iph);

    #ifdef DEBUG
        bpf_printk("Redirecting packet to RX queue %d.\n", ctx->rx_queue_index);
    #endif

    // Redirect to AF_XDP sockets for count.
    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
}

char _license[] SEC("license") = "GPL";