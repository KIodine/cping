#include "cping.h"
#include "cpaux.h"


/* --- static function declarations ------------------------- */

static inline int timespec2ms(struct timespec *ts);

/* --- static funtion --------------------------------------- */

static inline
int timespec2ms(struct timespec *ts){
    return (ts->tv_sec*1000UL + ts->tv_nsec/1000000UL);
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
    return;
}

int cping_once(
        struct cping_ctx *cpctx, const char *host, int family,
        const int timeout, struct timespec *delay
){
    struct addrinfo hint, *gai_res, *gai_tmp;
    struct timespec t0, dt, t_st, t_rem;
    int wait_timeout = timeout;
    int ret = 0, snd_fd;
    int fd = -1, icmp_code = 0;
    int nrcv;
    uint16_t snd_id, snd_seq = 0;

    struct sockaddr_storage saddr_store;
    struct sockaddr_in  *addr4;
    struct sockaddr_in6 *addr6;
    struct epoll_event ep_event = {0};
    socklen_t sastlen = sizeof(struct sockaddr_storage);
    char present[INET6_ADDRSTRLEN] = {0};


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
    
    /* get from cache mechanism or directly from `getaddrinfo` */
    /* service is irrelevent */
    ret = getaddrinfo(host, NULL, &hint, &gai_res);
    if (ret != 0){
        fprintf(stderr, "getaddrinfo: %s"NL, gai_strerror(ret));
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
        debug_printf("`sendto` send = %d"NL, ret);
        if (ret > 0){
#ifndef NDEBUG
            memset(present, 0, INET6_ADDRSTRLEN);
            if (gai_tmp->ai_family == AF_INET){
                addr4 = (struct sockaddr_in *)gai_tmp->ai_addr;
                inet_ntop(gai_tmp->ai_family, &addr4->sin_addr, present, INET6_ADDRSTRLEN);
            } else {
                addr6 = (struct sockaddr_in6 *)gai_tmp->ai_addr;
                inet_ntop(gai_tmp->ai_family, &addr6->sin6_addr, present, INET6_ADDRSTRLEN);
            }

            debug_printf("send packet to %s"NL, present);
#endif
            /* expecting 40 actually */
            break;
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

    
    ret = clock_gettime(CLOCK_MONOTONIC, &t0);

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
        
        fd = ep_event.data.fd;
        assert(fd == snd_fd);

        for (;;){
            nrcv = recvfrom(
                fd, cpctx->rcv_buf, cpctx->buflen, 0,
                (struct sockaddr*)&saddr_store, &sastlen
            );
#ifndef NDEBUG
            memset(present, 0, INET6_ADDRSTRLEN);
            debug_printf("`sastlen` = %u"NL, sastlen);
            if (family== AF_INET){
                addr4 = (struct sockaddr_in *)&saddr_store;
                inet_ntop(AF_INET, &addr4->sin_addr, present, INET6_ADDRSTRLEN);
            } else {
                addr6 = (struct sockaddr_in6 *)&saddr_store;
                inet_ntop(AF_INET6, &addr6->sin6_addr, present, INET6_ADDRSTRLEN);
            }
#endif
            debug_printf("recv packet from %s"NL, present);
            
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
            assume that `t_rem` is always greater equal than `t_st`
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
    
    delay->tv_sec  = dt.tv_sec  - t0.tv_sec;
    delay->tv_nsec = dt.tv_nsec - t0.tv_nsec;

    return icmp_code;
}
