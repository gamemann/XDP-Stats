#include <linux/bpf.h>
#include <bpf_helpers.h>

#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#include "../include.h"

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
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct stats),
    .max_entries = 1
};

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

    #ifdef DEBUG
        bpf_printk("Redirecting packet to RX queue %d.\n", ctx->rx_queue_index);
    #endif

    // Redirect to AF_XDP sockets for count.
    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
}

char _license[] SEC("license") = "GPL";