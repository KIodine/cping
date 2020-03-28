#include "cping.h"
#include "cpaux.h"
#include "cpcache.h"

/* --- static function declarations ------------------------- */

static inline int timespec2ms(struct timespec *ts);

static int sonar(
    struct cping_ctx *cpctx, int snd_fd, struct sockaddr *addr,
    socklen_t addrlen, int timeout, struct timespec *delay
);

/* --- static funtion --------------------------------------- */

static inline
int timespec2ms(struct timespec *ts){
    return (ts->tv_sec*1000UL + ts->tv_nsec/1000000UL);
}

static int sonar(
    struct cping_ctx *cpctx, int snd_fd, struct sockaddr *addr,
    socklen_t addrlen, int timeout, struct timespec *delay
){
    struct sockaddr_storage saddr_store = {0};
    struct epoll_event ev = {0};
    struct timespec t_wait_start, t_wait_end, t_snd, t_rcv;
    socklen_t sastlen = 0;
    int rcv_fd, nrcv, ret, icmp_code = 0;
    uint16_t snd_id, snd_seq;

    snd_id  = random() & 0xFFFF;
    snd_seq = 0;

    debug_printf("setup id = %d, seq = %d"NL, snd_id, snd_seq);

    setup_icmp_er(
        addr->sa_family, cpctx->icmp_pack, cpctx->paclen,
        snd_id, snd_seq
    );

    ret = sendto(
        snd_fd, cpctx->icmp_pack, cpctx->paclen, 0, addr, addrlen
    );
    if (ret == -1){
        perror("send ICMP packet");
        icmp_code = -1;
        goto finish;
    }
    clock_gettime(CLOCK_MONOTONIC, &t_snd);

    for (;;){
        clock_gettime(CLOCK_MONOTONIC, &t_wait_start);
        ret = epoll_wait(cpctx->epfd, &ev, 1, timeout);
        clock_gettime(CLOCK_MONOTONIC, &t_wait_end);
        if (ret < 0){
            perror("waiting for fd ready");
            goto finish;
        }
        if (ret == 0){
            /* No fd is ready, indicating timeout. */
            icmp_code = -1;
            clock_gettime(CLOCK_MONOTONIC, &t_rcv);
            goto finish;
        }
        rcv_fd = ev.data.fd;
        assert(rcv_fd == snd_fd);

        for (;;){
            nrcv = recvfrom(
                rcv_fd, cpctx->rcv_buf, cpctx->buflen, 0,
                (struct sockaddr*)&saddr_store, &sastlen
            );
            clock_gettime(CLOCK_MONOTONIC, &t_rcv);
            if (nrcv == -1){
                if (errno == EAGAIN){
                    /* Nothing to receive, `epoll_wait` again. */
                    break;
                } else {
                    perror("receiving packet");
                    icmp_code = -1;
                    goto finish;
                }
            }
            if (rcv_fd == cpctx->v4fd){
                icmp_code = verify_v4_packet(
                    cpctx->rcv_buf, nrcv, snd_id, snd_seq
                );
            } else if (rcv_fd == cpctx->v6fd){
                icmp_code = verify_v6_packet(
                    cpctx->rcv_buf, nrcv, snd_id, snd_seq
                );
            } else {
                fprintf(stderr, "unexpected file descriptor");
                abort();
            }
            if (icmp_code >= 0){
                goto finish;
            }
        }
        t_wait_end.tv_sec  -= t_wait_start.tv_sec;
        t_wait_end.tv_nsec -= t_wait_start.tv_nsec;
        /*
            assume that `t_rem` is always greater equal than `t_st`
            and not too big from `wait_timeout`
        */
       timeout -= timespec2ms(&t_wait_end);
       if (timeout < 0){
           icmp_code = -1;
           break;
       }
    }
finish:
    delay->tv_sec  = t_rcv.tv_sec  - t_snd.tv_sec;
    delay->tv_nsec = t_rcv.tv_nsec - t_snd.tv_nsec;

    return icmp_code;
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
    cpctx->paclen = ICMP_HDR_SZ + 32UL; /* icmp header + payload */
    cpctx->icmp_pack = malloc(cpctx->paclen);
    memset(cpctx->icmp_pack, 0, cpctx->paclen);
    init_icmp_pack(cpctx->icmp_pack, cpctx->paclen);

    cpctx->buflen = ETH_MTU;
    cpctx->rcv_buf = malloc(cpctx->buflen);
    memset(cpctx->rcv_buf, 0, cpctx->buflen);

    /* >>> init cache if implemented <<< */
    struct timespec tmp_to = {0};
    tmp_to.tv_sec = 300;
    cpctx->cache = cpcache_alloc(&tmp_to);

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
    if (cpctx == NULL){
        return;
    }
    close(cpctx->v4fd);
    close(cpctx->v6fd);
    close(cpctx->epfd);
    free(cpctx->icmp_pack);
    free(cpctx->rcv_buf);
    
    /* release cache if implemented */
    cpcache_free(cpctx->cache);

    return;
}

int cping_once(
        struct cping_ctx *cpctx, const char *host, int family,
        const int timeout, struct timespec *delay
){
    struct addrinfo *gai_res;
    int ret = 0, icmp_code = 0;


    if (family != AF_INET && family != AF_INET6){
        fprintf(stderr, "unexpected family %d"NL, family);
        abort();
    }

    /* get addrinfo from cache. the cache calls getaddrinfo if requested
        host is not found. */
    ret = cpcache_getaddrinfo(cpctx->cache, host, family, &gai_res);
    if (ret != 0){
        fprintf(stderr, "`cpcache_getaddrinfo`: %s"NL, gai_strerror(ret));
        return -1;
    }
    
    icmp_code = cping_addr_once(
        cpctx, gai_res->ai_addr, gai_res->ai_addrlen, timeout, delay
    );

    return icmp_code;
}

int cping_addr_once(
    struct cping_ctx *cpctx, struct sockaddr *addr, socklen_t addrlen,
    int timeout, struct timespec *delay
){
    struct epoll_event ep_event = {0};
    int ret, snd_fd, family, icmp_code = 0;

    family = addr->sa_family;

    switch(family){
    case AF_INET:
        snd_fd = cpctx->v4fd; break;
    case AF_INET6:
        snd_fd = cpctx->v6fd; break;
    default:
        fprintf(stderr, "unexpected family %d"NL, family);
        abort();
    }
    
    if (timeout < 0){
        fprintf(stderr, "timeout less than zero is not allowed"NL);
        return -1;
    }

    ep_event.events = EPOLLIN|EPOLLET;
    ep_event.data.fd = snd_fd;
    
    ret = epoll_ctl(cpctx->epfd, EPOLL_CTL_ADD, snd_fd, &ep_event);
    if (ret != 0){
        perror("register fd into epoll");
        return -1;
    }

    icmp_code = sonar(
        cpctx, snd_fd, (struct sockaddr*)addr, addrlen, timeout, delay
    );
    
    ret = epoll_ctl(cpctx->epfd, EPOLL_CTL_DEL, snd_fd, NULL);
    if (ret != 0){
        perror("remove fd from epoll fd");
        return -1;
    }

    return icmp_code;
}