#include "cpaux.h"

/* This file is a part of implementation of anciliary routines
   defined in `cpaux.h` */

#define ARRAY_SZ(arr) (sizeof(arr)/sizeof((arr)[0]))

/*
 *  bpf code for matching ICMPv4 messages:
 *      - echo reply        = 0  = 0x0
 *      - dest unreachable  = 3  = 0x3
 *      - time exceeded     = 11 = 0xb
 *  according to https://stackoverflow.com/q/49577061 and
 *  https://stackoverflow.com/q/39540291, it seems bpf works on the
 *  content you received rather than the raw byte stream.
 *  the kernel document (https://lwn.net/Articles/582493/) have
 *  mentioned that bpf code works on non raw ethernet packet as well,
 *  but did not describe how it affects the filtering process.
 */

static struct sock_filter code[] = {
    { 0xb1, 0, 0, 0x00000000 },
    { 0x50, 0, 0, 0x00000000 },
    { 0x15, 3, 0, 0x00000000 },
    { 0x15, 2, 0, 0x00000003 },
    { 0x15, 1, 0, 0x0000000b },
    { 0x6,  0, 0, 0x00000000 },
    { 0x6,  0, 0, 0xffffffff },
};

static const struct sock_fprog bpf = {
    .len    = ARRAY_SZ(code),
    .filter = code,
};

int create_v4raw(void){
    struct protoent *proto = NULL;
    int tmpfd, res;
    
    proto = getprotobyname("icmp");
    tmpfd = socket(AF_INET, SOCK_RAW, proto->p_proto);
    if (tmpfd == -1){
        perror("create v4 raw socket");
        goto create_error;
    }
    res = fcntl(tmpfd, F_SETFL, O_NONBLOCK);
    if (res == -1){
        perror("set v4 raw nonblock");
        goto fcntl_error;
    }

    res = setsockopt(tmpfd, SOL_SOCKET, SO_ATTACH_FILTER,
                     &bpf, sizeof(struct sock_fprog));
    if (res == -1){
        perror("attach bpf code on v4 raw");
        goto bpf_attach_fail;
    }
    
    return tmpfd;
    /* error handling area */
bpf_attach_fail:
    ; /* do nothing */
fcntl_error:
    close(tmpfd);
create_error:
    return -1;
}

int create_v6raw(void){
    struct protoent *proto = NULL;
    struct icmp6_filter v6filter;
    int tmpfd, res;

    proto = getprotobyname("ipv6-icmp");
    tmpfd = socket(AF_INET6, SOCK_RAW, proto->p_proto);
    if (tmpfd == -1){
        perror("create v6 raw socket");
        goto create_error;
    }
    res = fcntl(tmpfd, F_SETFL, O_NONBLOCK);
    if (res == -1){
        perror("set v6 raw nonblock");
        goto fcntl_error;
    }

    ICMP6_FILTER_SETBLOCKALL(&v6filter);
    ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY,    &v6filter);
    ICMP6_FILTER_SETPASS(ICMP6_TIME_EXCEEDED, &v6filter);
    ICMP6_FILTER_SETPASS(ICMP6_DST_UNREACH,   &v6filter);
    
    res = setsockopt(tmpfd, IPPROTO_ICMPV6, ICMP6_FILTER,
                     &v6filter, sizeof(struct icmp6_filter));
    if (res == -1){
        perror("v6 raw set filter");
        goto set_filter_error;
    }

    return tmpfd;
    /* error handling area */
set_filter_error:
    ; /* nothing to do */
fcntl_error:
    close(tmpfd);
create_error:
    return -1;
}
