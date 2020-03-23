#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cping.h"

#define NL "\n"

#define ARRAY_SZ(arr) (sizeof(arr)/sizeof((arr)[0]))


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

int main(void){
    basic_test();
    return 0;
}