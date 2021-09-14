#pragma once

#define MAXCPUS 256

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#ifndef htons
#define htons(x) ((__be16)___constant_swab16((x)))
#endif

#ifndef ntohs
#define ntohs(x) ((__be16)___constant_swab16((x)))
#endif

#ifndef htonl
#define htonl(x) ((__be32)___constant_swab32((x)))
#endif

#ifndef ntohl
#define ntohl(x) ((__be32)___constant_swab32((x)))
#endif
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#ifndef htons
#define htons(x) (x)
#endif

#ifndef ntohs
#define ntohs(X) (x)
#endif

#ifndef htonl
#define htonl(x) (x)
#endif

#ifndef ntohl
#define ntohl(x) (x)
#endif
#endif

#define TARGETPORT 27015

struct stats
{
    __u64 pckts;
    __u64 bytes;
};

#ifndef AF_INET
#define AF_INET 2
#endif