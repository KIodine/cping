#ifndef CPING_H
#define CPING_H

#define _GNU_SOURCE /* for `struct timespec` stuff */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

/* system specific headers */
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <sys/epoll.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <linux/filter.h>


struct cping_ctx {
    int v4fd;
    int v6fd;
    int epfd;
    void *icmp_pack;
    void *rcv_buf;
    size_t paclen;
    size_t buflen;
    /* some cache data structure like hashtable/tree */
};


int  cping_init(struct cping_ctx *cpctx);
void cping_fini(struct cping_ctx *cpctx);

/*
    return val:
    - val >= 0
        icmp code
    - val < 0
        error
*/
int  cping_once(struct cping_ctx *cpctx, const char *host, int ver,
                const int timeout, struct timespec *delay);

/* ---------------------------------------------------- */

/*  PROPOSAL:
    - ping multiple ip at once
    - monitor multiple ip
    - tracert
*/

#endif /* CPING_H */