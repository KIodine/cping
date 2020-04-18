#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#undef _GNU_SOURCE
#include "cping.h"



#define NL "\n"

#define ARRAY_SZ(arr) (sizeof(arr)/sizeof((arr)[0]))


static inline
double timespec2ms_d(struct timespec *ts){
    double sec, nsec;
    sec = ((double)ts->tv_sec)*1e3;
    nsec = ((double)ts->tv_nsec)/1e6;
    return sec + nsec;
}

/*  TODO:
    - test timeout mechanism
    - test `dst_unreach` code verifying
    - add test ping `www.example.com`
*/

struct test_tuple {
    char *host;
    int family;
    int timeout;
    int expect;
    char *err_msg;
};


struct test_tuple tests[] = {
    {"127.0.0.1", AF_INET, 1000, ICMP_ECHOREPLY, "can't ping v4"NL},
    {"::1", AF_INET6, 1000, ICMP6_ECHO_REPLY, "can't ping v6"NL},
    {"www.example.com", AF_INET, 1000, ICMP_ECHOREPLY, "can't ping \"www.example.com\""NL},
    {"www.example.com", AF_INET, 10, -1, "expect timeout"NL},
    //{"192.168.100.244", AF_INET, 1000, ICMP_DEST_UNREACH, "expect unreachable"NL},
};
const int test_count = ARRAY_SZ(tests);


int basic_test(void){
    struct cping_ctx cp;
    struct timespec  delay;
    struct test_tuple *tt;
    int ret = 0, exit_code = 0;
    /* move tests here */

    ret = cping_init(&cp);
    if (ret == -1){
        fprintf(stderr, "can't init cping"NL);
        return EXIT_FAILURE;
    }

    for (int i = 0; i < test_count; ++i){
        tt = &tests[i];
        ret = cping_once(
            &cp, tt->host, tt->family, tt->timeout, &delay
        );
        printf("[test]using time: %.3f ms"NL, timespec2ms_d(&delay));
        if (ret != tt->expect){
            fprintf(stderr, "%s", tt->err_msg);
            fprintf(stderr, "test stopped at test case No.%d"NL, i+1);
            exit_code = EXIT_FAILURE;
            goto finish;
        }
    }
    printf("we've all %d registered test passed"NL, test_count);
finish:
    cping_fini(&cp);
    return exit_code;
}

int traceroute_test(void){
    struct addrinfo *ai, ai_hint = {0};
    struct cping_ctx cp;
    struct trnode *tr;
    double fdelay;
    char present[256] = {0};
    int ret = 0;

    ret = cping_init(&cp);
    if (ret == -1){
        fprintf(stderr, "can't init cping"NL);
        return EXIT_FAILURE;
    }

    ai_hint.ai_family   = AF_INET;
    ai_hint.ai_socktype = SOCK_RAW;
    ai_hint.ai_protocol = IPPROTO_ICMP;
    ai_hint.ai_flags    = 0;
    ret = getaddrinfo("www.example.com", NULL, &ai_hint, &ai);
    if (ret == -1){
        fprintf(stderr, "can't get addrinfo: %s"NL, gai_strerror(ret));
    }

    tr = cping_tracert(&cp, ai->ai_addr, ai->ai_addrlen, 300, 30);
    int i = 0;
    for (struct trnode *tmp = tr; tmp != NULL; tmp = tmp->next){
        struct sockaddr_in *addr4;
        char *fqdn;

        memset(present, 0, 256);
        
        addr4 = (struct sockaddr_in*)tmp->addr;
        if (addr4 != NULL){
            printf(
                "[test]family = %d"NL, tmp->addr->sa_family
            );
            inet_ntop(
                AF_INET, &addr4->sin_addr,
                present, 256
            );
            fqdn = tmp->fqdn;
            fdelay = timespec2ms_d(&tmp->delay);
        } else {
            printf("[test] can't get node name"NL);
            present[0] = 'x';
            fqdn = "*";
            fdelay = -1.0;
        }
        
        printf(
            "[%2d]fqdn:  %s"NL
            "    addr:  %s"NL
            "    delay: %.3f ms"NL,
            i, fqdn, present, fdelay
        );
        ++i;
    }
    freetrnode(tr);
    freeaddrinfo(ai);

    cping_fini(&cp);

    return ret;
}

int main(void){
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    basic_test();
    traceroute_test();
    return 0;
}