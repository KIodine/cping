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


struct cping_ctx {
    int v4fd;
    int v6fd;
    int epfd;
    void *icmp_pack;
    void *rcv_buf;
    size_t paclen;
    size_t buflen;
};


struct trnode {
    char            *fqdn;
    struct sockaddr *addr;
    struct timespec  delay;
    size_t           namelen;
    socklen_t        addrlen;
    struct trnode   *next;
};

/* Initialize `struct cping_ctx`. */
int  cping_init(struct cping_ctx *cpctx);
/* Finalize `struct cping_ctx`. */
void cping_fini(struct cping_ctx *cpctx);

/*
    Send ICMP echo request to host. If return value is greater/equal than
    0, it is the ICMP type we received, otherwise (< 0) indicates error.
    Note that the underlying sockets are setup only ICMP echo reply,
    time exceeded and destination unreachable are allowed to pass.
*/
int cping_once(
    struct cping_ctx *cpctx, const char *host, int ver, int timeout,
    struct timespec *delay
);

/*  Tracking passing nodes on way to target, returns a list-like
    structure. */
struct trnode *cping_tracert(
    struct cping_ctx *cpctx, struct sockaddr *const saddr,
    const socklen_t socklen, const int timeout, const int maxhop
);
/*  Release resources used by `struct trnode`. */
void freetrnode(struct trnode *head);


/* lower level APIs */

/* Send ICMP echo request using addr. This routine is the underlying
   function of `cping_once`. */
int cping_addr_once(
    struct cping_ctx *cpctx, struct sockaddr *addr, socklen_t addrlen,
    int timeout, struct timespec *delay
);

/* ---------------------------------------------------- */

/*  PROPOSAL:
    - ping multiple ip at once
    - monitor multiple ip
*/

#endif /* CPING_H */