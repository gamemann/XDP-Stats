#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <getopt.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmpv6.h>

#include <sys/sysinfo.h>

#include <linux/types.h>

#include <bpf.h>
#include <libbpf.h>
#include <xsk.h>

#include "../include.h"
#include "af_xdp.h"

//#define DEBUG

static int progfd;
__u32 flags = XDP_FLAGS_DRV_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;

struct xsk_umem_info *umem[MAXCPUS];
struct xsk_socket_info *xsk_socket[MAXCPUS];

/**
 * Retrieves maximum CPU count (useful for RX queue calculation).
 * 
 * @return Number of CPUs.
**/
unsigned int bpf_num_possible_cpus()
{
    static const char *fcpu = "/sys/devices/system/cpu/possible";
    unsigned int start, end, possible_cpus = 0;
    char buff[128];
    FILE *fp;
    int n;

    fp = fopen(fcpu, "r");

    if (!fp) 
    {
        printf("Failed to open %s: '%s'!\n", fcpu, strerror(errno));
        exit(1);
    }

    while (fgets(buff, sizeof(buff), fp)) 
    {
        n = sscanf(buff, "%u-%u", &start, &end);

        if (n == 0) 
        {
            printf("Failed to retrieve # possible CPUs!\n");

            return 0;
        } 
        else if (n == 1) 
        {
            end = start;
        }

        possible_cpus = start == 0 ? end + 1 : 0;

        break;
    }

    fclose(fp);

    return possible_cpus;
}

static inline __u32 xsk_ring_prod__free(struct xsk_ring_prod *r)
{
    r->cached_cons = *r->consumer + r->size;
    return r->cached_cons - r->cached_prod;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, __u64 frame)
{
    assert(xsk->umem_frame_free < NUM_FRAMES);

    xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static void complete_tx(struct xsk_socket_info *xsk)
{
    unsigned int completed;
    uint32_t idx_cq;

    if (!xsk->outstanding_tx)
    {
        return;
    }

    sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

    /* Collect/free completed TX buffers */
    completed = xsk_ring_cons__peek(&xsk->umem->cq, XSK_RING_CONS__DEFAULT_NUM_DESCS, &idx_cq);

    if (completed > 0) 
    {
        for (int i = 0; i < completed; i++)
        {
            xsk_free_umem_frame(xsk, *xsk_ring_cons__comp_addr(&xsk->umem->cq, idx_cq++));
        }

        xsk_ring_cons__release(&xsk->umem->cq, completed);
        xsk->outstanding_tx -= completed < xsk->outstanding_tx ? completed : xsk->outstanding_tx;
    }
}

static struct xsk_umem_info *configure_xsk_umem(void *buffer, __u64 size)
{
    struct xsk_umem_info *umem;
    int ret;

    umem = calloc(1, sizeof(*umem));

    if (!umem)
    {
        return NULL;
    }

    ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, NULL);

    if (ret) 
    {
        errno = -ret;
        return NULL;
    }

    umem->buffer = buffer;

    return umem;
}

static __u64 xsk_alloc_umem_frame(struct xsk_socket_info *xsk)
{
    __u64 frame;

    if (xsk->umem_frame_free == 0)
    {
        return INVALID_UMEM_FRAME;
    }

    frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
    xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;

    return frame;
}

static __u64 xsk_umem_free_frames(struct xsk_socket_info *xsk)
{
    return xsk->umem_frame_free;
}

static struct xsk_socket_info *xsk_configure_socket(struct xsk_umem_info *umem, int rxqueue, int ifidx, const char *dev)
{
    struct xsk_socket_config xsk_cfg;
    struct xsk_socket_info *xsk_info;
    __u32 idx;
    __u32 prog_id = 0;
    int i;
    int ret;

    xsk_info = calloc(1, sizeof(*xsk_info));

    if (!xsk_info)
    {
        fprintf(stderr, "xsk_info = NULL\n");

        return NULL;
    }

    xsk_info->umem = umem;
    xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    xsk_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
    xsk_cfg.xdp_flags = flags;
    xsk_cfg.bind_flags = 0;

    ret = xsk_socket__create(&xsk_info->xsk, dev, rxqueue, umem->umem, &xsk_info->rx, &xsk_info->tx, &xsk_cfg);

    if (ret)
    {
        //fprintf(stderr, "xdp_socket__create :: Error.\n");

        goto error_exit;
    }

    // Initialize umem frame allocation.
    for (i = 0; i < NUM_FRAMES; i++)
    {
        xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;
    }

    xsk_info->umem_frame_free = NUM_FRAMES;

    // Stuff the receive path with buffers, we assume we have enough.
    ret = xsk_ring_prod__reserve(&xsk_info->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);

    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
    {
        fprintf(stderr, "ret != XSK_RING_PROD__DEFAULT_NUM_DESCS :: Error.\n");

        goto error_exit;
    }

    for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
    {
        *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) = xsk_alloc_umem_frame(xsk_info);
    }

    xsk_ring_prod__submit(&xsk_info->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

    return xsk_info;

    error_exit:
    errno = -ret;

    return NULL;
}

void *PollXSK(void *data)
{
    struct thread_info *ti = (struct thread_info *)data;

    struct pollfd fds[2];
    int ret, nfds = 1;

    unsigned int cpucnt = bpf_num_possible_cpus();

    memset(fds, 0, sizeof(fds));
    fds[0].fd = xsk_socket__fd(ti->xsk->xsk);
    fds[0].events = POLLIN;

    struct sysinfo sysinf = {0};

    #ifdef DEBUG
        fprintf(stdout, "[XSK] Starting to poll for FD %d (%d)...\n", ti->xsk->xsk->fd, fds[0].fd);
    #endif

    while (1)
    {
        ret = poll(fds, nfds, -1);

        if (ret != 1)
        {
            continue;
        }

        __u32 idx_rx, idx_fq = 0;

        unsigned int rcvd = xsk_ring_cons__peek(&ti->xsk->rx, RX_BATCH_SIZE, &idx_rx);

        if (!rcvd)
        {
            continue;
        }

        #ifdef DEBUG
            fprintf(stdout, "[XSK] Received %d packets from AF_XDP socket from queue ID %d\n", rcvd, ti->id);
        #endif

        int stockframes;

        stockframes = xsk_prod_nb_free(&ti->xsk->umem->fq, xsk_umem_free_frames(ti->xsk));

        if (stockframes > 0)
        {
            #ifdef DEBUG
                fprintf(stdout, "[XSK] We have %d stock frames.\n", stockframes);
            #endif

            ret = xsk_ring_prod__reserve(&ti->xsk->umem->fq, rcvd, &idx_fq);

            while (ret != stockframes)
            {
                ret = xsk_ring_prod__reserve(&ti->xsk->umem->fq, rcvd, &idx_fq);
            }

            for (int j = 0; j < stockframes; j++)
            {
                *xsk_ring_prod__fill_addr(&ti->xsk->umem->fq, idx_fq++) = xsk_alloc_umem_frame(ti->xsk);
            }

            xsk_ring_prod__submit(&ti->xsk->umem->fq, stockframes);
        }

        for (int j = 0; j < rcvd; j++)
        {
            __u64 addr = xsk_ring_cons__rx_desc(&ti->xsk->rx, idx_rx)->addr;
            __u32 len = xsk_ring_cons__rx_desc(&ti->xsk->rx, idx_rx++)->len;

            void *pckt = xsk_umem__get_data(ti->xsk->umem->buffer, addr);

            if (!pckt)
            {
                fprintf(stdout, "[XSK] Packet not true; freeing frame.\n");

                xsk_free_umem_frame(ti->xsk, addr);

                continue;
            }

            // Update map.
            __u32 key = 0;
            struct stats cnt = {0};
            
            if (bpf_map_lookup_elem(ti->pcktmap, &key, &cnt) == 0)
            {
                cnt.pckts++;
                cnt.bytes += len;
            }
            else
            {
                cnt.pckts = 1;
                cnt.bytes = len;
            }

            if (bpf_map_update_elem(ti->pcktmap, &key, &cnt, BPF_ANY) != 0)
            {
                fprintf(stdout, "Failed to update map.\n");
            }

            // Send packet back out TX.
            __u32 tx_idx = 0;

            ret = xsk_ring_prod__reserve(&ti->xsk->tx, 1, &tx_idx);

            if (ret != 1)
            {
                #ifdef DEBUG
                    fprintf(stderr, "[XSK] No more TX slots available.\n");
                #endif

                xsk_free_umem_frame(ti->xsk, addr);

                continue;
            }
        }

        xsk_ring_cons__release(&ti->xsk->rx, rcvd);
    }

    #ifdef DEBUG
        fprintf(stdout, "[XSK] Exiting poll...\n");
    #endif

    if (ti->xsk->xsk != NULL)
    {
	    xsk_socket__delete(ti->xsk->xsk);
    }

    if (ti->xsk->umem->umem != NULL)
    {
	    xsk_umem__delete(ti->xsk->umem->umem);
    }

    free(ti);

    pthread_exit(NULL);
}

void *PollXSKTX(void *data)
{
    struct thread_info *ti = (struct thread_info *)data;

    struct pollfd fds[2];
    int ret, nfds = 1;

    unsigned int cpucnt = bpf_num_possible_cpus();

    memset(fds, 0, sizeof(fds));
    fds[0].fd = xsk_socket__fd(ti->xsk->xsk);
    fds[0].events = POLLIN;

    struct sysinfo sysinf = {0};

    #ifdef DEBUG
        fprintf(stdout, "[XSK] Starting to poll for FD %d (%d)...\n", ti->xsk->xsk->fd, fds[0].fd);
    #endif

    while (1)
    {
        ret = poll(fds, nfds, -1);

        if (ret != 1)
        {
            continue;
        }

        __u32 idx_rx, idx_fq = 0;

        unsigned int rcvd = xsk_ring_cons__peek(&ti->xsk->rx, RX_BATCH_SIZE, &idx_rx);

        if (!rcvd)
        {
            continue;
        }

        #ifdef DEBUG
            fprintf(stdout, "[XSK] Received %d packets from AF_XDP socket from queue ID %d\n", rcvd, ti->id);
        #endif

        int stockframes;

        stockframes = xsk_prod_nb_free(&ti->xsk->umem->fq, xsk_umem_free_frames(ti->xsk));

        if (stockframes > 0)
        {
            #ifdef DEBUG
                fprintf(stdout, "[XSK] We have %d stock frames.\n", stockframes);
            #endif

            ret = xsk_ring_prod__reserve(&ti->xsk->umem->fq, rcvd, &idx_fq);

            while (ret != stockframes)
            {
                ret = xsk_ring_prod__reserve(&ti->xsk->umem->fq, rcvd, &idx_fq);
            }

            for (int j = 0; j < stockframes; j++)
            {
                *xsk_ring_prod__fill_addr(&ti->xsk->umem->fq, idx_fq++) = xsk_alloc_umem_frame(ti->xsk);
            }

            xsk_ring_prod__submit(&ti->xsk->umem->fq, stockframes);
        }

        for (int j = 0; j < rcvd; j++)
        {
            __u64 addr = xsk_ring_cons__rx_desc(&ti->xsk->rx, idx_rx)->addr;
            __u32 len = xsk_ring_cons__rx_desc(&ti->xsk->rx, idx_rx++)->len;

            void *pckt = xsk_umem__get_data(ti->xsk->umem->buffer, addr);

            if (!pckt)
            {
                fprintf(stdout, "[XSK] Packet not true; freeing frame.\n");

                xsk_free_umem_frame(ti->xsk, addr);

                continue;
            }

            // Update map.
            __u32 key = 0;
            struct stats cnt = {0};
            
            if (bpf_map_lookup_elem(ti->pcktmap, &key, &cnt) == 0)
            {
                cnt.pckts++;
                cnt.bytes += len;
            }
            else
            {
                cnt.pckts = 1;
                cnt.bytes = len;
            }

            if (bpf_map_update_elem(ti->pcktmap, &key, &cnt, BPF_ANY) != 0)
            {
                fprintf(stdout, "Failed to update map.\n");
            }

            // Send packet back out TX.
            __u32 tx_idx = 0;

            ret = xsk_ring_prod__reserve(&ti->xsk->tx, 1, &tx_idx);

            if (ret != 1)
            {
                #ifdef DEBUG
                    fprintf(stderr, "[XSK] No more TX slots available.\n");
                #endif

                xsk_free_umem_frame(ti->xsk, addr);

                continue;
            }

            xsk_ring_prod__tx_desc(&ti->xsk->tx, tx_idx)->addr = addr;
            xsk_ring_prod__tx_desc(&ti->xsk->tx, tx_idx)->len = len;
            xsk_ring_prod__submit(&ti->xsk->tx, 1);
            ti->xsk->outstanding_tx++;
        }

        xsk_ring_cons__release(&ti->xsk->rx, rcvd);
        complete_tx(ti->xsk);
    }

    #ifdef DEBUG
        fprintf(stdout, "[XSK] Exiting poll...\n");
    #endif

    if (ti->xsk->xsk != NULL)
    {
	    xsk_socket__delete(ti->xsk->xsk);
    }

    if (ti->xsk->umem->umem != NULL)
    {
	    xsk_umem__delete(ti->xsk->umem->umem);
    }

    free(ti);

    pthread_exit(NULL);
}

/**
 * Sets up XSK (AF_XDP) sockets.
 * 
 * @param dev The interface the XDP program exists on (string).
 * @param ifidx The interface the XDP program exists on (index number).
 * @param pcktmap FD of packets map.
 * @param xsksmap FD of XSKS map.
 * @param xdpflags The XDP attachment flags.
 * 
 * @return Returns 0 on success or 1 on failure.
**/
int setupxsk(const char *dev, int ifidx, int pcktmap, int xsksmap, __u32 xdpflags, __u32 cores, __u8 tx)
{
    flags = xdpflags;
    int ret;
    int xsks_map_fd;
    void *packet_buffer;
    __u64 packet_buffer_size;
    struct bpf_object *bpf_obj = NULL;

    int cpus = (cores > 0) ? cores : bpf_num_possible_cpus();

    fprintf(stdout, "Attempting to setup AF_XDP sockets. Dev => %s. Index => %d. Cores => %d.\n", dev, ifidx, cpus);

    // Allocate memory for NUM_FRAMES of the default XDP frame size.
    packet_buffer_size = NUM_FRAMES * FRAME_SIZE;

    if (posix_memalign(&packet_buffer, getpagesize(), packet_buffer_size)) 
    {
        fprintf(stderr, "ERROR :: Can't allocate buffer memory for XSK sockets => \"%s\".\n", strerror(errno));

        return EXIT_FAILURE;
    }

    for (unsigned int i = 0; i < cpus; i++)
    {
        int rxq = i;

        // Initialize shared packet_buffer for umem usage.
        umem[i] = configure_xsk_umem(packet_buffer, packet_buffer_size);

        if (umem[i] == NULL) 
        {
            fprintf(stderr, "ERROR :: Can't create umem \"%s\"\n", strerror(errno));

            continue;
        }

        // Open and configure the AF_XDP (xsk) socket.
        xsk_socket[i] = xsk_configure_socket(umem[i], i, ifidx, (const char *)dev);

        if (xsk_socket[i] == NULL) 
        {
            fprintf(stderr, "ERROR :: Can't setup AF_XDP socket \"%s\"\n", strerror(errno));

            continue;
        }

        int fd = xsk_socket__fd(xsk_socket[i]->xsk);

        if (bpf_map_update_elem(xsksmap, &rxq, &fd, BPF_ANY) != 0)
        {
            fprintf(stderr, "Error updating XSK map for queue #%d. (XSKS map => %d. FD => %d).\n", i, xsksmap, fd);

            continue;
        }

        struct thread_info *ti = malloc(sizeof(struct thread_info));

        ti->id = i;
        ti->xsk = xsk_socket[i];
        ti->pcktmap = pcktmap;
        ti->xsksmap = xsksmap;

        pthread_t tid;

        pthread_create(&tid, NULL, (tx) ? PollXSKTX : PollXSK, (void *)ti);

        fprintf(stdout, "Created XSK socket #%d (FD => %d) (Map => %d)\n", i, fd, xsksmap);
    }

    return EXIT_SUCCESS;
}

/**
 * Cleans up XSK (AF_XDP) sockets.
 * 
 * @return Void
**/
void cleanupxsk(__u32 cores)
{
    int cpus = (cores > 0) ? cores : bpf_num_possible_cpus();

    for (int i = 0; i < cpus; i++)
    {
        if (xsk_socket[i] != NULL)
        {
            xsk_socket__delete(xsk_socket[i]->xsk);
        }

        if (umem[i] != NULL)
        {
            xsk_umem__delete(umem[i]->umem);
        }
    }
}