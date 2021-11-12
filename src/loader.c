#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>
#include <error.h>
#include <errno.h>
#include <sys/resource.h>

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
    {"tx", no_argument, NULL, 'r'},
    {"cores", required_argument, NULL, 'c'},
    {"skb", no_argument, NULL, 's'},
    {"offload", no_argument, NULL, 'o'},
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

    while ((c = getopt_long(argc, argv, "i:t:xrc:so", longopts, NULL)) != -1)
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
                cmd->tx = 1;

                break;

            case 'c':
                cmd->cores = atoi(optarg);

                break;

            case 's':
                cmd->skb = 1;

                break;

            case 'o':
                cmd->offload = 1;

                break;

            case '?':
                fprintf(stderr, "Missing argument value.\n");

                break;
        }
    }
}

/**
 * Raises the RLimit.
 * 
 * @return Returns 0 on success (EXIT_SUCCESS) or 1 on failure (EXIT_FAILURE).
 */
int raise_rlimit()
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

    if (setrlimit(RLIMIT_MEMLOCK, &r))
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/**
 * Attempts to attach or detach (progfd = -1) a BPF/XDP program to an interface.
 * 
 * @param ifidx The index to the interface to attach to.
 * @param progfd A file description (FD) to the BPF/XDP program.
 * @param cmd A pointer to a cmdline struct that includes command line arguments (mostly checking for offload/HW mode set).
 * 
 * @return Returns the flag (int) it successfully attached the BPF/XDP program with or a negative value for error.
 */
int attachxdp(int ifidx, int progfd, struct cmdline *cmd)
{
    int err;

    char *smode;

    uint32_t flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
    uint32_t mode = XDP_FLAGS_DRV_MODE;

    smode = "DRV/native";

    if (cmd->offload)
    {
        smode = "HW/offload";

        mode = XDP_FLAGS_HW_MODE;
    }
    else if (cmd->skb)
    {
        smode = "SKB/generic";
        mode = XDP_FLAGS_SKB_MODE;
    }

    flags |= mode;

    int exit = 0;

    while (!exit)
    {
        // Try loading program with current mode.
        int err;

        err = bpf_set_link_xdp_fd(ifidx, progfd, flags);

        if (err || progfd == -1)
        {
            const char *errmode;

            // Decrease mode.
            switch (mode)
            {
                case XDP_FLAGS_HW_MODE:
                    mode = XDP_FLAGS_DRV_MODE;
                    flags &= ~XDP_FLAGS_HW_MODE;
                    errmode = "HW/offload";

                    break;

                case XDP_FLAGS_DRV_MODE:
                    mode = XDP_FLAGS_SKB_MODE;
                    flags &= ~XDP_FLAGS_DRV_MODE;
                    errmode = "DRV/native";

                    break;

                case XDP_FLAGS_SKB_MODE:
                    // Exit program and set mode to -1 indicating error.
                    exit = 1;
                    mode = -err;
                    errmode = "SKB/generic";

                    break;
            }

            if (progfd != -1)
            {
                fprintf(stderr, "Could not attach with %s mode (%s)(%d).\n", errmode, strerror(-err), err);
            }
            
            if (mode != -err)
            {
                smode = (mode == XDP_FLAGS_HW_MODE) ? "HW/offload" : (mode == XDP_FLAGS_DRV_MODE) ? "DRV/native" : (mode == XDP_FLAGS_SKB_MODE) ? "SKB/generic" : "N/A";
                flags |= mode;
            }
        }
        else
        {
            fprintf(stdout, "Loaded XDP program in %s mode.\n", smode);

            break;
        }
    }

    return mode;
}

int main(int argc, char *argv[])
{
    // Raise RLimit
    if (raise_rlimit() != 0)
    {
        fprintf(stderr, "Error setting rlimit. Please ensure you're running this program as a privileged user.\n");

        return EXIT_FAILURE;
    }
    
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

    char *objfile = "/etc/xdpstats/raw_xdp.o";

    if (cmd.afxdp)
    {
        objfile = "/etc/xdpstats/afxdp_raw.o";
    }
    else if (cmd.tx)
    {
        if (cmd.afxdp)
        {
            objfile = "/etc/xdpstats/afxdp_raw_xdp_tx.o";
        }
        else
        {
            objfile = "/etc/xdpstats/raw_xdp_tx.o";
        }
    }

    struct bpf_object *obj = NULL;
    int bpffd = -1;

    bpf_prog_load(objfile, BPF_PROG_TYPE_XDP, &obj, &bpffd);

    if (bpffd < 0)
    {
        fprintf(stderr, "Error loading BPF program.\n");

        return EXIT_FAILURE;
    }

    // Attach XDP program with DRV mode.
    int flags = attachxdp(ifidx, bpffd, &cmd);

    if (flags != XDP_FLAGS_HW_MODE && flags != XDP_FLAGS_DRV_MODE && flags != XDP_FLAGS_SKB_MODE)
    {
        fprintf(stderr, "Error attaching XDP program :: %s (%d)\n", strerror(flags), flags);

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

        setupxsk(cmd.interface, ifidx, pcktmap, xsksmap, (__u32)flags, cmd.cores, cmd.tx);
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

        totpckts = pcktcount;
        totbytes = bytecount;
        
        pps = totpckts - pcktcntlast;
        bps = totbytes - bytecntlast;

        fprintf(stdout, "%llu PPS | %llu BPS (%s %s).\n", pps, bps, (cmd.afxdp) ? "AF_XDP" : "XDP", (cmd.tx) ? "TX" : "DROP");

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

    fprintf(stdout, "Packets Total => %llu. Avg PPS => %llu.\n Bytes Total => %llu. Avg BPS => %llu.\n Seconds => %u. AF_XDP => %s.\n", totpckts, avgpps, totbytes, avgbps, timelap, (cmd.afxdp) ? "Yes" : "No");

    attachxdp(ifidx, -1, &cmd);

    if (cmd.afxdp)
    {
        cleanupxsk(cmd.cores);
    }
    
    return EXIT_SUCCESS;
}