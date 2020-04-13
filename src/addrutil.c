#include "addrutil.h"

#define NL "\n"

int addr_cmp(struct sockaddr *a, struct sockaddr *b){
    int ret;
    struct in_addr  *a_addr4, *b_addr4;
    struct in6_addr *a_addr6, *b_addr6;
    int cmp_sz;

    if (a->sa_family > b->sa_family){
        ret =  1; goto finish;
    } else if (a->sa_family < b->sa_family){
        ret = -1; goto finish;
    }

    switch (a->sa_family){
    case AF_INET:
        a_addr4 = &((struct sockaddr_in*)a)->sin_addr;
        b_addr4 = &((struct sockaddr_in*)b)->sin_addr;
        cmp_sz = sizeof(struct in_addr);
        ret = memcmp(a_addr4, b_addr4, cmp_sz); break;
    case AF_INET6:
        a_addr6 = &((struct sockaddr_in6*)a)->sin6_addr;
        b_addr6 = &((struct sockaddr_in6*)b)->sin6_addr;
        cmp_sz = sizeof(struct in6_addr);
        ret = memcmp(a_addr6, b_addr6, cmp_sz); break;
    default:
        ASSUME(0, "unsupported family: %d"NL, a->sa_family);
    }

finish:
    return ret;
}

int addr_cpy(
    struct sockaddr *restrict dst, struct sockaddr *restrict src
){
    int cpy_sz;

    switch (src->sa_family){
    case AF_INET:
        cpy_sz = sizeof(struct sockaddr_in);  break;
    case AF_INET6:
        cpy_sz = sizeof(struct sockaddr_in6); break;
    default:
        ASSUME(0, "unsupported family %d"NL, src->sa_family);
    }
    memcpy(dst, src, cpy_sz);
    
    return 0;
}
