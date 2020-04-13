#include "cping.h"
#include "cpaux.h"
#include "tsutil.h"
#include "addrutil.h"


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

    return;
}

int cping_once(
        struct cping_ctx *cpctx, const char *host, int family,
        const int timeout, struct timespec *delay
){
    struct addrinfo *gai_res, ai_hint = {0};
    int ret = 0, icmp_type = 0;


    ai_hint.ai_family   = family;
    ai_hint.ai_flags    = AI_ADDRCONFIG;
    ai_hint.ai_socktype = SOCK_RAW;
    switch (family){
    case AF_INET:
        ai_hint.ai_protocol = IPPROTO_ICMP;   break;
    case AF_INET6:
        ai_hint.ai_protocol = IPPROTO_ICMPV6; break;
    default:
        ASSUME(0, "unexpected family %d"NL, family);
    }

    ret = getaddrinfo(host, NULL, &ai_hint, &gai_res);
    if (ret != 0){
        fprintf(stderr, "can't getaddrinfo: %s"NL, gai_strerror(ret));
        return -1;
    }
    
    icmp_type = cping_addr_once(
        cpctx, gai_res->ai_addr, gai_res->ai_addrlen, timeout, delay
    );

    freeaddrinfo(gai_res);

    return icmp_type;
}

int cping_addr_once(
    struct cping_ctx *cpctx, struct sockaddr *addr, socklen_t addrlen,
    int timeout, struct timespec *delay
){
    struct srv_res sres = {0};
    int ret, icmp_type = 0;

    if (timeout < 0){
        fprintf(stderr, "timeout less than zero is not allowed"NL);
        return -1;
    }

    /* `addrlen` indicates the length of buffer. */
    sres.addrlen = sizeof(struct sockaddr_storage);
    ret = icmp_srv(
        cpctx, (struct sockaddr*)addr, addrlen, &sres, timeout
    );
    icmp_type = sres.icmp_type;

    delay->tv_sec  = sres.delay.tv_sec;
    delay->tv_nsec = sres.delay.tv_nsec;

    return icmp_type;
}

struct trnode *cping_tracert(
    struct cping_ctx *cpctx, struct sockaddr *const addr,
    const socklen_t addrlen, const int timeout, const int maxhop
){
    struct srv_res sres = {0};
    struct trnode   *head = NULL, **cur;
#define NAME_SZ 256UL
    char fqdn[NAME_SZ] = {0};
    int ret = 0, limit = 0, icmp_type = 0, snd_fd = 0;
    int lvl, opt, namelen;
    
    cur = &head;

    switch(addr->sa_family){
    case AF_INET:
        lvl    = IPPROTO_IP;
        opt    = IP_TTL;
        snd_fd = cpctx->v4fd; break;
    case AF_INET6:
        lvl    = IPPROTO_IPV6;
        opt    = IPV6_UNICAST_HOPS;
        snd_fd = cpctx->v6fd; break;
    default:
        ASSUME(0, "unexpected family %d"NL, addr->sa_family);
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
        ret = icmp_srv(
            cpctx, addr, addrlen, &sres, timeout
        );
        icmp_type = sres.icmp_type;
        debug_printf("icmp_srv ret type: %d"NL, icmp_type);

        assert(sres.addrlen != 0);
        if (icmp_type >= 0){

            size_t addr_sz;
            switch (sres.addr_stor.ss_family){
            case AF_INET:
                addr_sz = sizeof(struct sockaddr_in);  break;
            case AF_INET6:
                addr_sz = sizeof(struct sockaddr_in6); break;
            }
            (*cur)->addr    = calloc(1, addr_sz);
            (*cur)->addrlen = sres.addrlen;
            memcpy((*cur)->addr,  &sres.addr_stor,  addr_sz);
            
            debug_printf("addr copied"NL);
        } else {
            /* Just leave these fields NULL. */;
            debug_printf("! addr not copied"NL);
        }
        memcpy(&(*cur)->delay, &sres.delay, sizeof(struct timespec));

        if (icmp_type >= 0){
            memset(fqdn, 0, NAME_SZ);
            ret = getnameinfo(
                (struct sockaddr*)&sres.addr_stor, sres.addrlen,
                fqdn, NAME_SZ, NULL, 0, 0
            );
            if (ret != 0){
                fprintf(stderr, "%s"NL, gai_strerror(ret));
            }

            namelen         = strlen(fqdn);
            (*cur)->namelen = namelen;
            (*cur)->fqdn    = malloc(namelen + 1);
            memcpy((*cur)->fqdn, fqdn, namelen + 1);
            debug_printf("fqdn=%s"NL, fqdn);
        }

        cur = &(*cur)->next;

        debug_printf(" --- --- --- "NL);

        ret = addr_cmp(addr, (struct sockaddr*)&sres.addr_stor);
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
