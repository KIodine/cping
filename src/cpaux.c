#include "cpaux.h"


/* --- declarations ----------------------------------------- */

/* stuffing the rest of icmp packet with alphabet */
static inline size_t icmp_stuffing(unsigned char *buf, size_t len);

/* --- static data ------------------------------------------ */

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

#define ARRAY_SZ(arr) (sizeof(arr)/sizeof((arr)[0]))
static struct sock_filter code[] = {
    { 0xb1, 0, 0, 0x00000000 },
    { 0x50, 0, 0, 0x00000000 },
    { 0x15, 3, 0, 0x00000000 },
    { 0x15, 2, 0, 0x00000003 },
    { 0x15, 1, 0, 0x0000000b },
    { 0x6, 0, 0, 0x00000000 },
    { 0x6, 0, 0, 0xffffffff },
};

static const struct sock_fprog bpf = {
    .len    = ARRAY_SZ(code),
    .filter = code,
};

/* --- auxiliary routine definitions ------------------------ */

/* see http://www.faqs.org/rfcs/rfc1071.html */
uint16_t inet_checksum16(char* buf, unsigned int len){
    uint32_t  u32buf = 0;
    uint16_t *u16arr;
    unsigned int u16len;

    u16arr = (uint16_t*)buf;
    u16len = len >> 1;
    
    for (;u16len--;){
        u32buf += u16arr[u16len];
    }
    if (len & 0x1){
        /* have odd bytes */
        u32buf += (uint32_t)(((uint8_t*)buf)[len - 1]);
    }

    /* add back the carry bits */
    u32buf  = (u32buf >> 16) + (u32buf & 0xFFFF);
    u32buf += (u32buf >> 16);

    return (uint16_t)((~u32buf) & 0xFFFF);
}

ssize_t init_icmp_pack(void *buf, size_t len){
    static const size_t min_sz_req = 32;
    struct icmp *icmp = NULL;
    unsigned char *buffer = buf;

    if (len < min_sz_req){
        return -1;
    }
    icmp = buf;
    icmp->icmp_type  = 0;
    icmp->icmp_code  = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_id    = 0;
    icmp->icmp_seq   = 0;
    debug_printf("stuffing %ld bytes"NL, len - 8);
    icmp_stuffing((buffer + 8), (len - 8));
    
    return 0;
}

static inline
size_t icmp_stuffing(unsigned char *buf, size_t len){
    size_t i = 0;
    int base = 97; /* ord(a) = 97 */
    for (;i < len; ++i){
        buf[i] = base + (i % 26);
    }
    return i;
}

int setup_icmp_er(
    int family, void *buf, size_t len, uint16_t id, uint16_t seq
){
    struct icmp *icmp = buf;
    uint16_t chksum   = 0;

    if (family == AF_INET){
        icmp->icmp_type  = ICMP_ECHO;
    } else {   /* AF_INET6 */
        icmp->icmp_type  = ICMP6_ECHO_REQUEST;
    }
    icmp->icmp_code  = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_id    = htons(id);
    icmp->icmp_seq   = htons(seq);
    if (family == AF_INET){
        chksum = inet_checksum16(buf, len);
        icmp->icmp_cksum = chksum;
        
        assert(inet_checksum16(buf, len) == 0);
    } else {
        /* IPv6 stack will calculate this */
        icmp->icmp_cksum = 0;
    }
    debug_printf("setup checksum = %X"NL, chksum);

    return 0;
}

int verify_v4_packet(void *buf, size_t len, uint16_t id, uint16_t seq){
    struct icmp *icmp = NULL;
    char *bytes  = NULL;
    int   type   = -1;
    int   hdrlen = 0;
    uint16_t packet_id, packet_seq;
    const unsigned int min_v4_icmp_sz = 20UL + 8UL;

    ASSUME(
        len >= min_v4_icmp_sz,
        "received packet stream short than v4 minimum "
        "length of 28: %lu", len
    );

    bytes  = buf;
    hdrlen = 4*(bytes[0] & 0xF);
    debug_printf("offset = %d"NL, hdrlen);
    bytes += hdrlen; /* skip header */

    icmp = (struct icmp*)bytes;
    type = icmp->icmp_type;

    debug_printf("v4 received chksum = %X"NL, icmp->icmp_cksum);
    assert(inet_checksum16(bytes, len - hdrlen) == 0);

    switch (type){
    case ICMP_ECHOREPLY:
        /* no need to move the pointer */;
        debug_printf("received ECHO_REPLY4"NL); break;
    case ICMP_DEST_UNREACH:
    case ICMP_TIME_EXCEEDED:
        /* skip icmp header and IPv4 header */
        ASSUME(
            len >= (20UL*2 + 8UL*2),
            "packet shorter than minimum requirement of DST_UNREACH "
            "and TIME_EXCEED (56): %lu"NL, len
        );
        debug_printf("received DST_UNREACH4 or TIME_EXCEEDED4"NL);
        bytes += 8UL;
        bytes += 4UL*(bytes[0] & 0xF);
        icmp = (struct icmp*)bytes; break;
    default:
        debug_printf("not handling code4: %d"NL, type);
        type = -1;
        goto no_handle;
    }

    packet_id  = ntohs(icmp->icmp_id);
    packet_seq = ntohs(icmp->icmp_seq);

    debug_printf(
        "v4 verified: type=%3d, id=%3d, seq=%3d"NL,
        type, packet_id, packet_seq
    );
    
    if (packet_id != id || packet_seq != seq){
        /* it's not for us */
        debug_printf("v4 received others"NL);
        type = -1;
    } else {
        debug_printf("v4 verify success"NL);
    }
no_handle:
    return type;
}

int verify_v6_packet(void *buf, size_t len, uint16_t id, uint16_t seq){
    struct icmp6_hdr *icmp6 = NULL;
    char *bytes = NULL;
    int   type6 = -1;
    uint16_t packet_id, packet_seq;
    const unsigned int min_v6_icmp_sz = 8UL;

    ASSUME(
        len >= min_v6_icmp_sz,
        "received packet stream short than v6 minimum "
        "length of 8: %lu", len
    );

    /* no need to skip IPv6 hdr cause we won't receive it */
    bytes = buf;

    icmp6 = (struct icmp6_hdr*)bytes;
    type6 = icmp6->icmp6_type;

    debug_printf("v6 received checksum = %X"NL, icmp6->icmp6_cksum);

    switch (type6){
    case ICMP6_ECHO_REPLY:
        /* do nothing */;
        debug_printf("received ECHO_REPLY6"NL); break;
    case ICMP6_DST_UNREACH:
    case ICMP6_TIME_EXCEEDED:
        ASSUME(
            len >= (min_v6_icmp_sz + 48UL),
            "received packet stream short than v6 minimum length of "
            "error msg = 56 : %lu"NL, len
        );
        debug_printf("received DST_UNREACH6 or TIME_EXCEEDED6");
        bytes += 8UL;
        bytes += 40UL;
        icmp6 = (struct icmp6_hdr*)bytes; break;
    default:
        debug_printf("not handling type6: %d"NL, type6);
        type6 = -1;
        goto no_handle;
    }

    packet_id  = ntohs(icmp6->icmp6_id);
    packet_seq = ntohs(icmp6->icmp6_seq);

    debug_printf(
        "verified: type=%3d, id=%3d, seq=%3d"NL,
        type6, packet_id, packet_seq
    );

    if (packet_id != id || packet_seq != seq){
        type6 = -1;
    } else {
        debug_printf("v6 verify success"NL);
    }
no_handle:
    return type6;
}

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
