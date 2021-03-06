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
    int snd_fd, rcv_fd, nrcv, ret = 0;

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

    /* TODO:
        Eliminate the need of adding & removing fds each time `icmp_srv`
        being called.
        If doing so, moving add and remove routine to initializer and
        finalizer.
     */

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
        /* if (rcv_fd != snd_fd) <ignore|clean buffer, wait next> */
        /*
            In that way, we might receive messages from previous
            call. Do we clean it right away or lazily handle it?
            -> Clean it right away, since we use edge-trigger mode.
               If we don't read, we'll lost the fd permanently.
        */

        for (;;){
            nrcv = recvfrom(
                rcv_fd, cpctx->rcv_buf, cpctx->buflen, 0,
                (struct sockaddr*)&sres->addr_stor, &sres->addrlen
            );
            if (rcv_fd != snd_fd){
                /* Read it anyway because we use edge-trigger mode. */
                debug_printf("received packet from not interested fd"NL);
                break;
            }

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
            /* Packet does not have matching `snd_id` and `snd_seq`. */
            debug_printf("might received packets from previous call"NL);
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

    ts_sub(&sres->delay, &sres->delay, &t_snd);

    return ret;
}
