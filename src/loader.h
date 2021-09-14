#pragma once

#define MAXCPUS 256

struct cmdline
{
    char *interface;
    __u32 time;
    unsigned int afxdp : 1;
    unsigned int rawxdptx : 1;
    __u32 cores;
};

struct stats
{
    __u64 pckts;
    __u64 bytes;
};