#ifndef CPING_H
#define CPING_H

#define _GNU_SOURCE /* for `struct timespec` stuff */

/*
    we only introduce symbols for declaration and programming
    use.
*/

/* system specific headers */
#include <time.h>
#include <sys/types.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "cpcache.h"

/*  PROPOSAL
    - [ ] move helper function to other source file and not expose
          their symbol.
*/


struct cping_ctx {
    int v4fd;
    int v6fd;
    int epfd;
    void *icmp_pack;
    void *rcv_buf;
    size_t paclen;
    size_t buflen;
    /* some cache data structure like hashtable/tree */
    struct addrif_cache *cache;
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

int  cping_tracert(struct cping_ctx *cpctx, const char *host, int ver,
                   const int timeout, const int maxhop);
/* ---------------------------------------------------- */

/*  PROPOSAL:
    - ping multiple ip at once
    - monitor multiple ip
    - tracert
*/

#endif /* CPING_H */