#include "cping.h"
#include "cpaux.h"
#include "cpcache.h"


/* Store return data of `sonar`. */
struct sonar_res {
    struct sockaddr_storage addr;
    socklen_t               addrlen;
    struct timespec         delay;
};

struct sonar_arg {
    int              snd_fd;
    int              timeout;
    struct sockaddr *addr;
    socklen_t        addrlen;
};

/* --- static function declarations ------------------------- */

static inline int timespec2ms(struct timespec *ts);

/* Send, recv and verify the packet, this function assumes
   the waiting epoll fd have exactly one socket fd registered. */
static int sonar(
    struct cping_ctx *cpctx, int snd_fd, struct sockaddr *addr,
    socklen_t addrlen, int timeout, struct sonar_res *sres
);

/* --- static funtion --------------------------------------- */

static
void ts_diff(
    struct timespec *restrict dt, struct timespec *restrict t1,
    struct timespec *restrict t0
){
    dt->tv_sec  = t1->tv_sec  - t0->tv_sec;
    dt->tv_nsec = t1->tv_nsec - t0->tv_nsec;
    if (dt->tv_nsec < 0){
        dt->tv_sec  -= 1;
        dt->tv_nsec += 1000000000;
    }
    return;
}

static inline
int timespec2ms(struct timespec *ts){
    return (ts->tv_sec*1000UL + ts->tv_nsec/1000000UL);
}

/* TODO: use ancilliary data to compress the amount of parameter */
static int sonar(
    struct cping_ctx *cpctx, int snd_fd, struct sockaddr *addr,
    socklen_t addrlen, int timeout, struct sonar_res *sres
){
    struct sockaddr_storage *saddr_store;
    struct epoll_event       ev = {0};
    struct timespec t_wait_start, t_wait_end, t_wait_dt,
                    t_snd, t_rcv;
    struct timespec *delay;
    socklen_t       *sastlen;
    int      rcv_fd, nrcv, ret, icmp_type = 0;
    uint16_t snd_id, snd_seq;

    /* Aliasing sres data. */
    saddr_store = &sres->addr;      assert(saddr_store != NULL);
    sastlen     = &sres->addrlen;
    delay       = &sres->delay;

    snd_id  = random() & 0xFFFF;
    snd_seq = 0;

    debug_printf("setup id = %d, seq = %d"NL, snd_id, snd_seq);

    setup_icmp_er(
        addr->sa_family, cpctx->icmp_pack, cpctx->paclen,
        snd_id, snd_seq
    );

    ev.events  = EPOLLIN|EPOLLET;
    ev.data.fd = snd_fd;
    ret = epoll_ctl(cpctx->epfd, EPOLL_CTL_ADD, snd_fd, &ev);
    if (ret != 0){
        perror("register fd into epoll");
        return -1;
    }

    ret = sendto(
        snd_fd, cpctx->icmp_pack, cpctx->paclen, 0, addr, addrlen
    );
    if (ret == -1){
        perror("send ICMP packet");
        icmp_type = -1;
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
            icmp_type = -1;
            clock_gettime(CLOCK_MONOTONIC, &t_rcv);
            goto finish;
        }
        rcv_fd = ev.data.fd;

        if (rcv_fd != snd_fd){
            fprintf(stderr, "assumption violated"NL);
            abort();
        }

        for (;;){
            nrcv = recvfrom(
                rcv_fd, cpctx->rcv_buf, cpctx->buflen, 0,
                (struct sockaddr*)saddr_store, sastlen
            );
            clock_gettime(CLOCK_MONOTONIC, &t_rcv);
            if (nrcv == -1){
                if (errno == EAGAIN){
                    /* Nothing to receive, `epoll_wait` again. */
                    break;
                } else {
                    perror("receiving packet");
                    icmp_type = -1;
                    goto finish;
                }
            } else {
                debug_printf("recv = %d"NL, nrcv);
            }

            /* Use family as switch than fd? */
            if (rcv_fd == cpctx->v4fd){
                icmp_type = verify_v4_packet(
                    cpctx->rcv_buf, nrcv, snd_id, snd_seq
                );
            } else if (rcv_fd == cpctx->v6fd){
                icmp_type = verify_v6_packet(
                    cpctx->rcv_buf, nrcv, snd_id, snd_seq
                );
            } else {
                fprintf(stderr, "unexpected file descriptor");
                abort();
            }
            if (icmp_type >= 0){
                goto finish;
            }
        }

        ts_diff(&t_wait_dt, &t_wait_end, &t_wait_start);

        /*
            assume that `t_rem` is always greater equal than `t_st`
            and not too big from `wait_timeout`
        */
       timeout -= timespec2ms(&t_wait_dt);
       if (timeout < 0){
           icmp_type = -1;
           break;
       }
    }
finish:
    ret = epoll_ctl(cpctx->epfd, EPOLL_CTL_DEL, snd_fd, NULL);
    if (ret != 0){
        perror("remove fd from epoll fd");
        return -1;
    }

    delay->tv_sec  = t_rcv.tv_sec  - t_snd.tv_sec;
    delay->tv_nsec = t_rcv.tv_nsec - t_snd.tv_nsec;

    return icmp_type;
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
    int ret = 0, icmp_type = 0;


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
    
    icmp_type = cping_addr_once(
        cpctx, gai_res->ai_addr, gai_res->ai_addrlen, timeout, delay
    );

    return icmp_type;
}

int cping_addr_once(
    struct cping_ctx *cpctx, struct sockaddr *addr, socklen_t addrlen,
    int timeout, struct timespec *delay
){
    struct sonar_res   sres     = {0};
    int ret, snd_fd, family, icmp_type = 0;

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

    icmp_type = sonar(
        cpctx, snd_fd, (struct sockaddr*)addr, addrlen, timeout, &sres
    );

    delay->tv_sec  = sres.delay.tv_sec;
    delay->tv_nsec = sres.delay.tv_nsec;

    return icmp_type;
}

/*
struct list *cping_tracert(cpctx, host, family, timeout, maxhop):
    struct trnode *head, *tmp;
    for i in range(1, maxhop):
        setsockopt(snd_fd, domain, optlevel, &limit, sizeof(limit))
        alloc node
        for j in range(try):
            do sonar
            if response:
                record address
                record delay
        getnameinfo // the max length of fqdn is 253*.
        append node
        if reached target host:
            break
    limit = -1 // recover setting.
    setsockopt(snd_fd, domain, proto, &limit, sizeof(limit))
    return head;

*256 in raw bytes actually, human-readable part is 253.

*/

#define NAME_SZ 256UL
struct trnode *cping_tracert(
    struct cping_ctx *cpctx, const char *host, int ver, const int timeout,
    const int maxhop
){
    struct sonar_res sres = {0};
    struct trnode   *head = NULL, **cur;
    struct addrinfo *ai   = NULL;
    char fqdn[NAME_SZ] = {0};
    int ret = 0, limit = 0, icmp_type = 0, snd_fd = 0;
    int lvl, opt, namelen;
#ifndef NDEBUG
    char present[INET6_ADDRSTRLEN];
#endif
    
    cur = &head;
    
    ret = cpcache_getaddrinfo(cpctx->cache, host, ver, &ai);

    switch(ver){
    case AF_INET:
        lvl    = IPPROTO_IP;
        opt    = IP_TTL;
        snd_fd = cpctx->v4fd; break;
    case AF_INET6:
        lvl    = IPPROTO_IPV6;
        opt    = IPV6_UNICAST_HOPS;
        snd_fd = cpctx->v6fd; break;
    default:
        fprintf(stderr, "unexpected family %d"NL, ver);
        abort();
    }

    for (int i = 1; i < maxhop; ++i){
        limit = i;
        ret = setsockopt(snd_fd, lvl, opt, &limit, sizeof(limit));
        if (ret == -1){
            perror("set TTL/hoplimit error");
        }


        *cur = calloc(1, sizeof(struct trnode));
        
        /* --- */
        /* NOTE: You can't leave this zero. */
        sres.addrlen = sizeof(struct sockaddr_storage);
        debug_printf("current hop: %d"NL, limit);
        ret = sonar(
            cpctx, snd_fd, ai->ai_addr, ai->ai_addrlen, timeout,
            &sres
        );
        debug_printf("sonar ret type: %d"NL, ret);

        assert(sres.addrlen != 0);
        if (ret >= 0){
            /* TODO: decrease space usage. */
            (*cur)->addr    = calloc(1, sizeof(struct sockaddr_storage));
            (*cur)->addrlen = sres.addrlen;
            memcpy((*cur)->addr,  &sres.addr,  sizeof(struct sockaddr_storage));
            debug_printf("addr copied"NL);
        } else {
            /* TODO: handle timeout situation. */
            debug_printf("! addr not copied"NL);
        }
        memcpy(&(*cur)->delay, &sres.delay, sizeof(struct timespec));

#ifndef NDEBUG
        memset(present, 0, INET6_ADDRSTRLEN);
        debug_printf("`sres` family = %d"NL, sres.addr.ss_family);
        switch (ver){
        case AF_INET:
            inet_ntop(
                ver, &((struct sockaddr_in*)&sres.addr)->sin_addr,
                present, INET6_ADDRSTRLEN
            ); break;
        case AF_INET6:
            inet_ntop(
                ver, &((struct sockaddr_in6*)&sres.addr)->sin6_addr,
                present, INET6_ADDRSTRLEN
            ); break;
        }
        debug_printf(
            "result from `%s`, (len=%u)"NL, present, sres.addrlen
        );
#endif
        if (ret >= 0){
            memset(fqdn, 0, NAME_SZ);
            ret = getnameinfo(
                (struct sockaddr*)&sres.addr, sres.addrlen,
                fqdn, NAME_SZ, NULL, 0, 0
            );
            if (ret != 0){
                debug_printf("%s"NL, gai_strerror(ret));
            }

            namelen         = strlen(fqdn);
            (*cur)->namelen = namelen;
            (*cur)->fqdn    = malloc(namelen + 1);
            memcpy((*cur)->fqdn, fqdn, namelen + 1);
            debug_printf("fqdn=%s"NL, fqdn);
        }

        cur = &(*cur)->next;

        debug_printf(" --- --- --- "NL);

        ret = memcmp(ai->ai_addr, &sres.addr, ai->ai_addrlen);
        if (ret == 0){
            debug_printf("compare equal, break now"NL);
            break;
        }
    }
    /* recover kernel default. */
    limit = -1;
    ret = setsockopt(snd_fd, lvl, opt, &limit, sizeof(limit));

    return head;
}

void freetrnode(struct trnode *head){
    struct trnode *hold;
    if (head == NULL){
        return;
    }
    for (;head != NULL;){
        hold = head;
        head = head->next;
        free(hold->addr);
        free(hold->fqdn);
        free(hold);
    }
    return;
}