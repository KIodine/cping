#ifndef CPCACHE_H
#define CPCACHE_H

#define _GNU_SOURCE
#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <netdb.h>
#include <string.h>


#include "avltree.h"


#define NL "\n"

#ifndef NDEBUG
    #define debug_printf(fmt, ...) printf(PREFIX fmt, ##__VA_ARGS__)
#else
    #define debug_printf(ignore, ...) ((void)0)
#endif


/*  TODO:
    - reduce subjects need to compare.
*/

/*  QUESTIONS:
    - aggresive cache expiration?
*/

struct addrif_cache;
struct ai_cache_entry;


struct addrif_cache {
    struct timespec timeout;
    struct avltree tree;
};

/* cache structure contain `struct addrinfo` and information for comparison. */
struct ai_cache_entry {
    int     family;
    char   *host;       /* `char*` is unsafe I guess */
    size_t  hostlen;
    struct addrinfo *ai;
    struct timespec  expire;
    struct avlnode   node;
};

struct addrif_cache *cpcache_alloc(struct timespec *timeout);
void cpcache_free(struct addrif_cache *aicache);

/* cache interface mocking `getaddrinfo` */
int cpcache_getaddrinfo(
    struct addrif_cache *aicache, char *host,
    const struct addrinfo *hint, struct addrinfo **pai
);

#endif /* CPCACHE_H */