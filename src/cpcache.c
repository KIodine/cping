#include "cpcache.h"

#undef  PREFIX
#define PREFIX "[cpcache]"

/* --- static function declarations ------------------------- */

/*
    stores diffrence in `dt` in the manner of `dt = t1 - t0`.
    this function assumes all 3 arguments are distinct pointer.
*/
static void ts_diff(struct timespec *restrict dt, struct timespec *restrict t1, struct timespec *restrict t0);
static long clock_diff_ns(struct timespec *restrict t0, struct timespec *restrict t1);
static long clock_diff_us(struct timespec *restrict t0, struct timespec *restrict t1);

static int cache_comparator(struct avlnode const *a, struct avlnode const *b);
static void cache_free(struct avlnode *node);
static struct ai_cache_entry *cache_alloc(
    const char *host, int family, struct addrinfo *ai,
    struct timespec *timeout
);
/* --- static function definitions -------------------------- */

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

static
long clock_diff_ns(struct timespec *restrict t0, struct timespec *restrict t1){
    struct timespec dt;
    ts_diff(&dt, t1, t0);
    return (dt.tv_sec*1000000000 + dt.tv_nsec);
}


static
long clock_diff_us(struct timespec *restrict t0, struct timespec *restrict t1){
    struct timespec dt;
    ts_diff(&dt, t1, t0);
    return (dt.tv_sec*1000000 + dt.tv_nsec/1000);
}

/* TODO: implement `cache_comparator` */
static
int cache_comparator(
    const struct avlnode *a, const struct avlnode *b
){
    struct ai_cache_entry *ai_a, *ai_b;
    int cmpres;
    ai_a = container_of(a, struct ai_cache_entry, node);
    ai_b = container_of(b, struct ai_cache_entry, node);
    
    /* compare family, than `strcmp` host */
    if (ai_a->family > ai_b->family){
        return NODE_GT;
    } else if (ai_a->family < ai_b->family){
        return NODE_LT;
    }
    debug_printf("comparing `%s` and `%s`"NL, ai_a->host, ai_b->host);
    cmpres = strcmp(ai_a->host, ai_b->host);
    debug_printf("cmpres is %d"NL, cmpres);

    return cmpres;
}

static
struct ai_cache_entry *cache_alloc(
    const char *host, int family, struct addrinfo *ai,
    struct timespec *timeout
){
    struct ai_cache_entry *entry;
    char  *host_str;
    size_t hostlen;

    hostlen = strlen(host);
    entry = calloc(1, sizeof(struct ai_cache_entry));
    host_str = calloc(hostlen + 1, sizeof(char));
    memcpy(host_str, host, hostlen + 1);

    entry->ai      = ai;
    entry->host    = host_str;
    entry->hostlen = hostlen;
    entry->family  = family;
    
    clock_gettime(CLOCK_MONOTONIC, &entry->expire);
    entry->expire.tv_sec  += timeout->tv_sec;
    entry->expire.tv_nsec += timeout->tv_nsec;

    return entry;
}


/* `cache_free` */
static
void cache_free(struct avlnode *node){
    struct ai_cache_entry *ai;
    if (node == NULL){
        return;
    }
    cache_free(node->child[CLD_L]);
    cache_free(node->child[CLD_R]);
    ai = container_of(node, struct ai_cache_entry, node);
    freeaddrinfo(ai->ai);
    free(ai->host);
    free(ai);
    return;
}

/* --- exposed APIs ------------------------------------------ */

/* TODO: implement `cpcache_alloc`, `cpcache_free`, `cpcache_getaddrinfo` */
struct addrif_cache *cpcache_alloc(struct timespec *timeout){
    struct addrif_cache *ai_cache = NULL;

    ai_cache = calloc(1, sizeof(struct addrif_cache));
    ai_cache->timeout.tv_sec  = timeout->tv_sec;
    ai_cache->timeout.tv_nsec = timeout->tv_nsec;

    avl_tree_init(&ai_cache->tree, cache_comparator);

    return ai_cache;
}

/* `cpcache_free` */
void cpcache_free(struct addrif_cache *aicache){
    cache_free(aicache->tree.root);
    free(aicache);
    return;
}

/* `cpcache_getaddrinfo` */
int cpcache_getaddrinfo(
    struct addrif_cache *aicache, char *host, int family,
    struct addrinfo **pai
){
    struct ai_cache_entry cache_hint, *cache_res;
    struct avlnode *tmpnd;
    struct addrinfo ai_hint;
    struct timespec now;
    int gai_ret = 0;
    size_t hostlen;

    hostlen = strlen(host);

    cache_hint.family  = family;
    cache_hint.host    = host;
    cache_hint.hostlen = hostlen;

    ai_hint.ai_family = family;
    if (family == AF_INET){
        ai_hint.ai_protocol = IPPROTO_ICMP;
    } else {
        ai_hint.ai_protocol = IPPROTO_ICMPV6;
    }
    ai_hint.ai_socktype = SOCK_RAW;
    ai_hint.ai_flags    = AI_ADDRCONFIG;

    tmpnd = avl_get(&aicache->tree, &cache_hint.node);
    if (tmpnd == NULL){
        debug_printf(
            "unknown host: %s, try get from getaddrinfo"NL, host
        );
        gai_ret = getaddrinfo(host, NULL, &ai_hint, pai);
        if (gai_ret == 0){
            debug_printf(
                "successfully get `%s` from getaddrinfo"NL, host
            );
            cache_res = cache_alloc(
                host, family, *pai, &aicache->timeout
            );
            avl_insert(&aicache->tree, &cache_res->node);
        } else {
            debug_printf("can't get addrinfo of host: %s"NL, host);
        }
    } else {
        debug_printf("host %s was cached"NL, host);
        cache_res = container_of(tmpnd, struct ai_cache_entry, node);
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec  > cache_res->expire.tv_sec ||
            now.tv_nsec > cache_res->expire.tv_nsec
        ){
            debug_printf("cached result expired, try get new one"NL);
            gai_ret = getaddrinfo(host, NULL, &ai_hint, pai);
            if (gai_ret == 0){
                freeaddrinfo(cache_res->ai);
                cache_res->ai = *pai;
                clock_gettime(CLOCK_MONOTONIC, &cache_res->expire);
                cache_res->expire.tv_sec  += aicache->timeout.tv_sec;
                cache_res->expire.tv_nsec += aicache->timeout.tv_nsec;
            } else {
                debug_printf("cannot update cache of host: %s"NL, host);
                debug_printf("reason: %s"NL, gai_strerror(gai_ret));
            }
        } else {
            debug_printf(
                "return cached result of host: `%s`"NL, cache_res->host
            );
            *pai = cache_res->ai;
        }
    }

    return gai_ret;
}
