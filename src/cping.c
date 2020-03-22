#include "cping.h"


#ifdef __GNUC__
    #define ThreadLocal __thread
#else
    #error "No corresponding ThreadLocal specifier set"
#endif

#define NL "\n"
#define PREFIX "[cping]"

#ifndef NDEBUG
    #define debug_printf(fmt, ...) printf(PREFIX fmt, ##__VA_ARGS__)
#else
    #define debug_printf(ignore, ...) ((void)0)
#endif


/* reads until error occurs */
static inline void clear_buffer(int fd, void *buf, size_t len);

/* create and setup IPv4 raw socket */
static int create_v4raw(void);
/* create and setup IPv6 raw socket */
static int create_v6raw(void);
/* make ICMP echo request pack */
static ssize_t init_icmp_pack(void *buf, size_t len);
static size_t icmp_stuffing(unsigned char *buf, size_t len);
static uint16_t inet_checksum16(char *buf, unsigned int len);
static int setup_icmp_er(int family, void *buf, size_t len, uint16_t id, uint16_t seq);

static int verify_v4_packet(void *buf, size_t len, uint16_t id, uint16_t seq);
static int verify_v6_packet(void *buf, size_t len, uint16_t id, uint16_t seq);


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
    .len = ARRAY_SZ(code),
    .filter = code,
};

/* --- static funtion --------------------------------------- */

static inline
void clear_buffer(int fd, void *buf, size_t len){
    /*
        read until `EAGAIN` or other error occurs
        assert the fd is non-blocking mode
    */
    for (;0 < read(fd, buf, len););
    return;
}

/* should use `char*` as argument? */
static
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
    /* stuffing */
    debug_printf("stuffing %ld bytes"NL, len - 8);
    icmp_stuffing((buffer + 8), (len - 8));
    return 0;
}

static
size_t icmp_stuffing(unsigned char *buf, size_t len){
    size_t i = 0;
    int base = 97; /* ord(a) = 97 */
    /* stuffing lowercase alphabets in buffer */
    for (;i < len; ++i){
        buf[i] = base + (i % 26);
    }
    return i;
}

static
uint16_t inet_checksum16(char* buf, unsigned int len){
    uint32_t  u32buf = 0;
    uint16_t *u16arr;
    unsigned int u16len;

    u16arr = (uint16_t*)buf;
    u16len = len >> 1;
    
    for (unsigned int i = 0; i < u16len; ++i){
        u32buf += u16arr[i];
    }
/*
    for (;u16len--;){
        u32buf += u16arr[u16len];
    }
*/
    if (len & 0x1){
        /* have odd bytes */
        u32buf += (uint32_t)(((uint8_t*)buf)[len - 1]);
    }

    /* add back the carry bits */
    u32buf  = (u32buf >> 16) + (u32buf & 0xFFFF);
    u32buf += (u32buf >> 16);

    return (uint16_t)((~u32buf) & 0xFFFF);
};

static
int setup_icmp_er(
    int family, void *buf, size_t len, uint16_t id, uint16_t seq
){
    struct icmp *icmp = buf;
    uint16_t chksum   = 0;

    /*  FIXME
        - [X] incorrect checksum on IPv4?
            -> no, it's just a silly misconception.
    */

    /* reset checksum */
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

static inline
int timespec2ms(struct timespec *ts){
    return (ts->tv_sec*1000UL + ts->tv_nsec/1000000UL);
}

static
int verify_v4_packet(void *buf, size_t len, uint16_t id, uint16_t seq){
    struct icmp *icmp = NULL;
    char *bytes  = NULL;
    int   type   = -1;
    int   hdrlen = 0;
    uint16_t packet_id, packet_seq;

    bytes  = buf;
    hdrlen = 4*(bytes[0] & 0xF);
    bytes += hdrlen; /* skip header */

    icmp = (struct icmp*)bytes;
    type = icmp->icmp_code;

    debug_printf("v4 received chksum = %X"NL, icmp->icmp_cksum);
    assert(inet_checksum16(bytes, len - hdrlen) == 0);

    if (type == ICMP_ECHOREPLY){
        /* no need to move the pointer */;
    } else if (type == ICMP_DEST_UNREACH || type == ICMP_TIME_EXCEEDED){
        /* skip icmp header and IPv4 header */
        bytes += 8UL;
        bytes += 4UL*(bytes[0] & 0xF);
        icmp = (struct icmp*)bytes;
    } else {
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
    }
no_handle:
    return type;
}

static
int verify_v6_packet(void *buf, size_t len, uint16_t id, uint16_t seq){
    struct icmp6_hdr *icmp6 = NULL;
    char *bytes = NULL;
    int   type6 = -1;
    uint16_t packet_id, packet_seq;

    /* no need to skip IPv6 hdr cause we won't receive it */
    bytes = buf;

    icmp6 = (struct icmp6_hdr*)bytes;
    type6 = icmp6->icmp6_type;

    debug_printf("v6 received checksum = %X"NL, icmp6->icmp6_cksum);
    //assert(inet_checksum16(bytes, len) == 0);

    if (type6 == ICMP6_ECHO_REPLY){
        /* do nothing */;
    } else if (type6 == ICMP6_DST_UNREACH || type6 == ICMP6_TIME_EXCEEDED){
        /* skip icmp6 header and IPv6 header */
        bytes += 8UL;
        bytes += 40UL;
        icmp6 = (struct icmp6_hdr*)bytes;
    } else {
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
    }
no_handle:
    return type6;
}

static int create_v4raw(void){
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

    /* the filter works fine */
    
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

static int create_v6raw(void){
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

    /* this works fine, it is the packet malformed */
    //ICMP6_FILTER_SETBLOCKALL(&v6filter);
    ICMP6_FILTER_SETBLOCKALL(&v6filter);
    //ICMP6_FILTER_SETPASS(ICMP6_ECHO_REQUEST,  &v6filter);
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

/* ---------------------------------------------------------- */

int cping_init(struct cping_ctx *cpctx){
    int tmpfd = -1;

    /* try create IPv4 raw socket */
    tmpfd = create_v4raw();
    if (tmpfd == -1){
        goto v4sock_error;
    }
    cpctx->v4fd = tmpfd;

    /* try create IPv6 raw socket */
    tmpfd = create_v6raw();
    if (tmpfd == -1){
        goto v6sock_error;
    }
    cpctx->v6fd = tmpfd;


    tmpfd = epoll_create(8); /* size is just a hint */
    if (tmpfd == -1){
        perror("create epoll fd");
        goto epfd_error;
    }
    cpctx->epfd = tmpfd;

    /* `malloc` on linux always returns "valid" pointer */
    cpctx->paclen = 8UL + 32UL; /* icmp header + payload */
    cpctx->icmp_pack = malloc(cpctx->paclen);
    memset(cpctx->icmp_pack, 0, 40);
    init_icmp_pack(cpctx->icmp_pack, cpctx->paclen);

    cpctx->buflen = 1500; /* MTU of ethernet */
    cpctx->rcv_buf = malloc(cpctx->buflen);
    memset(cpctx->rcv_buf, 0, cpctx->buflen);

    /* >>> init cache if implemented <<< */

    return 0;
    /* error handling area */
epfd_error:
    close(cpctx->v6fd);
v6sock_error:
    close(cpctx->v4fd);
v4sock_error:
    return -1;
}

void cping_fini(struct cping_ctx *cpctx){
    close(cpctx->v4fd);
    close(cpctx->v6fd);
    close(cpctx->epfd);
    free(cpctx->icmp_pack);
    free(cpctx->rcv_buf);
    /* release cache if implemented */
    return;
}

int cping_once(
        struct cping_ctx *cpctx, const char *host, int family,
        const int timeout, struct timespec *delay
){
    struct addrinfo hint, *gai_res, *gai_tmp;
    int gai_ret = 0, ret = 0, snd_fd;
    uint16_t snd_id, snd_seq = 0;
    
    /*  TODO
        - [X] just write naive code first
        - [X] verify `inet_checksum16`
        - [ ] clean scattering local variable declaration
        - [ ] add proper error handling

        QUESTION:
        - exposing error or just die?
            1) if we can handle, handle it
            2) if it is cause by user, return and prompt user
            3) if it is cause by us but we can't handle, die
    */

    hint.ai_family   = family;
    if (family == AF_INET){
        hint.ai_protocol = IPPROTO_ICMP;
    } else if (family == AF_INET6){
        hint.ai_protocol = IPPROTO_ICMPV6;
    } else {
        fprintf(stderr, "unexpected family %d"NL, family);
        abort();
    }

    /* this is what we use to identify the packet */
    snd_id = random() & 0xFFFF;

    debug_printf(
        "generate id=%3d, seq=%3d"NL, snd_id, snd_seq
    );

    hint.ai_socktype = SOCK_RAW;
    /* return only if local has ability to send */
    hint.ai_flags    = AI_ADDRCONFIG;
    
    /* get from cache mechanism of directly from `getaddrinfo` */
    /* service is irrelevent */
    gai_ret = getaddrinfo(host, NULL, &hint, &gai_res);
    if (gai_ret != 0){
        fprintf(stderr, "getaddrinfo: %s"NL, gai_strerror(gai_ret));
        return -1;
    }

    /* afterward, we can assert `family should be `AF_INET` or `AF_INET6` */
    if (family == AF_INET){
        debug_printf("send use v4fd"NL);
        snd_fd = cpctx->v4fd;
    } else{
        debug_printf("send use v6fd"NL);
        snd_fd = cpctx->v6fd;
    }

    setup_icmp_er(
        family, cpctx->icmp_pack, cpctx->paclen, snd_id, snd_seq
    );
    /* try until a valid address is found */
    for (gai_tmp = gai_res; gai_tmp != NULL; gai_tmp = gai_tmp->ai_next){
        /* address should have identical family as `snd_fd` */
        ret = sendto(
            snd_fd, cpctx->icmp_pack, cpctx->paclen, 0,
            gai_tmp->ai_addr, gai_tmp->ai_addrlen
        );
        if (ret > 0){
            /* expecting 64 actually */
            debug_printf("`sendto` send = %d"NL, ret);
            break;
        } else {
            debug_printf("`sendto` ret = %d"NL, ret);
        }
    }
    if (gai_tmp != NULL){
        /* cache only the valid address or the whole addrinfo chain? */
    } else {
        fprintf(
            stderr, "can't find valid address for host: %s with family", host
        );
        freeaddrinfo(gai_res);
        return -1;
    }
    freeaddrinfo(gai_res);


    struct timespec t0, dt, t_st, t_rem;
    int wait_timeout = timeout;
    
    ret = clock_gettime(CLOCK_MONOTONIC, &t0);

    struct sockaddr_storage saddr_store;
    struct epoll_event ep_event = {0};
    socklen_t sastlen;
    int fd = -1, icmp_code = 0;

    /* TODO: generalize the `cpctx->v4fd` below this comment */

    ep_event.events = EPOLLET|EPOLLIN;
    ep_event.data.fd = snd_fd;

    debug_printf("register fd = %d"NL, snd_fd);
    ret = epoll_ctl(cpctx->epfd, EPOLL_CTL_ADD, snd_fd, &ep_event);
    if (ret != 0){
        perror("register fd into epoll");
        return -1;
    }
    /*
        wait until:
        - [X] timeout occurs
        - [X] received expected packet
        reduce `wait_timeout` after every not successful retrive.
    */
    for (;;){
        clock_gettime(CLOCK_MONOTONIC, &t_st);
        ret = epoll_wait(cpctx->epfd, &ep_event, 1, wait_timeout);
        clock_gettime(CLOCK_MONOTONIC, &t_rem);
        if (ret < 0){
            perror("waiting for fd ready");
            return -1;
        }
        if (ret == 0){
            /* timeout */
            debug_printf("recv timeouts"NL);
            icmp_code = -1;
            break;
        }
        /* receive from fd and check is right icmp packet */
        fd = ep_event.data.fd;
        assert(fd == snd_fd);
        
        int nrcv;
        char present[256] = {0};

        for (;;){
            nrcv = recvfrom(
                fd, cpctx->rcv_buf, cpctx->buflen, 0,
                (struct sockaddr*)&saddr_store, &sastlen
            );
            debug_printf("nrcv = %d"NL, nrcv);
            /* measure packet delay */
            ret = clock_gettime(CLOCK_MONOTONIC, &dt);
            
            if (nrcv <= 0){
                if (errno == EAGAIN){
                    /* all data have been read */
                    break;
                } else {
                    /* other error, need to dereg fd anyway */
                    perror("receiving datagram");
                    inet_ntop(family, &saddr_store, present, 256);
                    debug_printf(
                        "nrcv = %d, errno = %d, addr = %s"NL,
                        nrcv, errno, present
                    );
                    icmp_code = -1;
                    goto eploop_break;
                }
            }
            
            if (fd == cpctx->v4fd){
                debug_printf("verifying v4 packet"NL);
                icmp_code = verify_v4_packet(
                    cpctx->rcv_buf, nrcv, snd_id, snd_seq
                );
            } else if (fd == cpctx->v6fd){
                debug_printf("verifying v6 packet"NL);
                icmp_code = verify_v6_packet(
                    cpctx->rcv_buf, nrcv, snd_id, snd_seq
                );
            } else {
                /* should be unreachable */
                abort();
            }
            if (icmp_code >= 0){
                /* successfully handled packet, `icmp_code` is set */
                goto eploop_break;
            }
        }
        debug_printf("did not received interested packet"NL);
        t_rem.tv_sec  = t_rem.tv_sec  - t_st.tv_sec;
        t_rem.tv_nsec = t_rem.tv_nsec - t_st.tv_nsec;
        /*
            assert that `t_rem` is always greater equal than `t_st`
            and not too big from `wait_timeout`
        */
        wait_timeout -= timespec2ms(&t_rem);
        if (wait_timeout < 0){
            debug_printf("time quota consumed, break"NL);
            icmp_code = -1;
            break;
        }
    }
eploop_break:
    debug_printf("deregister fd = %d"NL, snd_fd);
    ret = epoll_ctl(cpctx->epfd, EPOLL_CTL_DEL, snd_fd, NULL);
    if (ret != 0){
        perror("remove fd from epoll fd");
        return -1;
    }
    /* calculate delay */
    delay->tv_sec  = dt.tv_sec  - t0.tv_sec;
    delay->tv_nsec = dt.tv_nsec - t0.tv_nsec;

    return icmp_code;
}
