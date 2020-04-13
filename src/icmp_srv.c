#include "cping.h"
#include "cpaux.h"
#include "tsutil.h"


int icmp_srv(
    struct cping_ctx *cpctx, struct sockaddr *addr, socklen_t addrlen,
    struct srv_res *sres, int timeout
){
    struct epoll_event ev = {0};
    struct timespec t_wait_st, t_wait_dt, t_snd;
    uint16_t snd_id, snd_seq;
    long dt_ms;
    int snd_fd, rcv_fd, nrcv, tmp, ret = 0;

    snd_id  = random() & 0xFFFF;
    snd_seq = 0;

    switch (addr->sa_family){
    case AF_INET:
        snd_fd = cpctx->v4fd; break;
    case AF_INET6:
        snd_fd = cpctx->v6fd; break;
    default:
        ASSUME(0, "unexpected family");
    }

    setup_icmp_er(
        addr->sa_family, cpctx->icmp_pack, cpctx->paclen,
        snd_id, snd_seq
    );

    ev.events = EPOLLIN|EPOLLET;
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
        goto finish;
    }
    clock_gettime(CLOCK_MONOTONIC, &t_snd);

    for (;;){
        clock_gettime(CLOCK_MONOTONIC, &t_wait_st);
        ret = epoll_wait(cpctx->epfd, &ev, 1, timeout);
        clock_gettime(CLOCK_MONOTONIC, &t_wait_dt);
        if (ret < 0){
            perror("waiting fpr fd ready");
            goto finish;
        }
        if (ret == 0){
            /* No fd available, indicate timeout. */
            clock_gettime(CLOCK_MONOTONIC, &sres->delay);
            sres->icmp_type = -1;
            ret = -1; goto finish;
        }
        
        rcv_fd = ev.data.fd;
        ASSUME(rcv_fd == snd_fd, "assumption violated"NL);

        for (;;){
            nrcv = recvfrom(
                rcv_fd, cpctx->rcv_buf, cpctx->buflen, 0,
                (struct sockaddr*)&sres->addr_stor, &sres->addrlen
            );
            clock_gettime(CLOCK_MONOTONIC, &sres->delay);

            if (nrcv == -1){
                if (errno == EAGAIN){
                    break; /* Nothing to receive, goto wait again. */
                } else {
                    perror("receiving packet");
                    ret = -1; goto finish;
                }
            } else {
                debug_printf("recv = %d"NL, nrcv);
            }

            switch(sres->addr_stor.ss_family){
            case AF_INET:
                /* TODO: upgrade `verify_*_packet`, store both type and
                   code in return value. */
                sres->icmp_type = verify_v4_packet(
                    cpctx->rcv_buf, nrcv, snd_id, snd_seq
                ); break;
            case AF_INET6:
                sres->icmp_type = verify_v6_packet(
                    cpctx->rcv_buf, nrcv, snd_id, snd_seq
                ); break;
            default:
                ASSUME(0, "unexpected family"NL);
            }
            if (sres->icmp_type >= 0){
                goto finish;
            }
        }

        ts_sub(&t_wait_dt, &t_wait_dt, &t_wait_st);
        /*
            Assuming `t_wait_dt` is gt/ge than `t_wait_st` and
            not to big from `t_wait_st`.
        */
       ts_to_unit(TIMESPEC_TO_MS, &t_wait_dt, &dt_ms);
       timeout -= dt_ms;
       if (timeout <= 0){
           ret = -1; goto finish;
       }
    }
finish:
    /* Use `tmp` so it won't clobber `ret`. */
    tmp = epoll_ctl(cpctx->epfd, EPOLL_CTL_DEL, snd_fd, NULL);
    if (tmp != 0){
        perror("remove fd from epoll fd");
        return -1;
    }

    ts_sub(&sres->delay, &sres->delay, &t_snd);

    return ret;
}
