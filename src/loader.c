#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>
#include <error.h>
#include <errno.h>

#include <bpf.h>
#include <libbpf.h>
#include <linux/if_link.h>

#include <net/if.h>
#include <arpa/inet.h>

#include "loader.h"
#include "af_xdp/af_xdp.h"

const struct option longopts[] =
{
    {"interface", required_argument, NULL, 'i'},
    {"time", required_argument, NULL, 't'},
    {"afxdp", no_argument, NULL, 'x'},
    {"xdptx", no_argument, NULL, 'r'},
    {"cores", required_argument, NULL, 'c'},
    {NULL, 0, NULL, 0}
};

__u8 cont = 1;

void sighndl(int tmp)
{
    cont = 0;
}

unsigned int bpf_num_possible_cpus();

void parsecmdline(int argc, char *argv[], struct cmdline *cmd)
{
    int c = -1;

    while ((c = getopt_long(argc, argv, "i:t:xrc:", longopts, NULL)) != -1)
    {
        switch (c)
        {
            case 'i':
                cmd->interface = optarg;

                break;

            case 't':
                cmd->time = atoi(optarg);

                break;

            case 'x':
                cmd->afxdp = 1;

                break;

            case 'r':
                cmd->rawxdptx = 1;

                break;

            case 'c':
                cmd->cores = atoi(optarg);

                break;

            case '?':
                fprintf(stderr, "Missing argument value.\n");

                break;
        }
    }
}

int main(int argc, char *argv[])
{
    // Parse command line.
    struct cmdline cmd = {0};
    parsecmdline(argc, argv, &cmd);

    if (cmd.interface == NULL)
    {
        fprintf(stderr, "Please specify an interface with the '-i' flag.\n");

        return EXIT_FAILURE;
    }

    int ifidx = if_nametoindex(cmd.interface);

    if (ifidx < 0)
    {
        fprintf(stderr, "Interface index less than 0.\n");

        return EXIT_FAILURE;
    }

    char *objfile = "/etc/pen-test/raw_xdp.o";

    if (cmd.afxdp)
    {
        objfile = "/etc/pen-test/afxdp_raw.o";
    }
    else if (cmd.rawxdptx)
    {
        objfile = "/etc/pen-test/raw_xdp_tx.o";
    }

    struct bpf_object *obj = NULL;
    int bpffd = -1;

    bpf_prog_load(objfile, BPF_PROG_TYPE_XDP, &obj, &bpffd);

    if (bpffd < 0)
    {
        fprintf(stderr, "Error loading BPF program.\n");

        return EXIT_FAILURE;
    }

    __u32 flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;


    int err = bpf_set_link_xdp_fd(ifidx, bpffd, flags);

    if (err)
    {
        fprintf(stderr, "Error attaching XDP program :: %s (%d).\n", strerror(-err), -err);

        return EXIT_FAILURE;
    }

    int pcktmap = -1;

    pcktmap = bpf_object__find_map_fd_by_name(obj, "packets_map");

    if (pcktmap < 0)
    {
        fprintf(stderr, "Error finding packets_map.\n");

        return EXIT_FAILURE;
    }

    if (cmd.afxdp)
    {
        int xsksmap = bpf_object__find_map_fd_by_name(obj, "xsks_map");

        setupxsk(cmd.interface, ifidx, pcktmap, xsksmap, flags, cmd.cores);
    }

    signal(SIGINT, sighndl);

    __u32 timelap = 0;

    unsigned int cpucnt = bpf_num_possible_cpus();

    __u64 totpckts = 0;
    __u64 totbytes = 0;

    __u64 pcktcntlast = 0;
    __u64 bytecntlast = 0;

    while (cont)
    {
        sleep(1);

        if (cmd.time > 0 && timelap >= cmd.time)
        {
            break;
        }

        timelap++;

        __u64 pcktcount = 0;
        __u64 bytecount = 0;

        __u32 key = 0;

        __u64 pps = 0;
        __u64 bps = 0;

        if (cmd.afxdp)
        {
            struct stats *cnt = NULL;

            if (bpf_map_lookup_elem(pcktmap, &key, cnt) != 0)
            {
                fprintf(stderr, "Failed lookup. Pckt map => %d.\n", pcktmap);
                continue;
            }

            if (cnt)
            {
                pcktcount = cnt->pckts;
                bytecount = cnt->bytes;
            }
        }
        else
        {
            struct stats cnt[cpucnt];

            if (bpf_map_lookup_elem(pcktmap, &key, cnt) != 0)
            {
                continue;
            }

            for (unsigned int i = 0; i < cpucnt; i++)
            {
                if (cnt[i].pckts > 0)
                {
                    pcktcount += cnt[i].pckts;
                }

                if (cnt[i].bytes > 0)
                {
                    bytecount += cnt[i].bytes;
                }
            }
        }

        totpckts = pcktcount;
        totbytes = bytecount;
        
        pps = totpckts - pcktcntlast;
        bps = totbytes - bytecntlast;

        fprintf(stdout, "%llu PPS | %llu BPS (%s).\n", pps, bps, (cmd.afxdp) ? "AF_XDP DROP" : (cmd.rawxdptx) ? "XDP TX" : "XDP DROP");

        pcktcntlast = pcktcount;
        bytecntlast = bytecount;
    }

    __u64 avgpps = 0;

    if (totpckts > 0 && timelap > 0)
    {
        avgpps = totpckts / timelap;
    }

    __u64 avgbps = 0;

    if (totbytes > 0 && timelap > 0)
    {
        avgbps = totbytes / timelap;
    }

    fprintf(stdout, "Packets Tot => %llu. Avg PPS => %llu.\n Bytes Tot => %llu. Avg BPS => %llu.\n Seconds => %u. AF_XDP => %s.\n", totpckts, avgpps, totbytes, avgbps, timelap, (cmd.afxdp) ? "Yes" : "No");

    bpf_set_link_xdp_fd(ifidx, -1, flags);

    if (cmd.afxdp)
    {
        cleanupxsk(cmd.cores);
    }
    
    return EXIT_SUCCESS;
}