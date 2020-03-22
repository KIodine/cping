#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cping.h"

#define NL "\n"

int main(void){
    struct cping_ctx cp;
    struct timespec  delay;
    int ret = 0, exit_code;
    
    ret = cping_init(&cp);
    if (ret == -1){
        fprintf(stderr, "can't init cping"NL);
        return EXIT_FAILURE;
    }

    ret = cping_once(&cp, "127.0.0.1", AF_INET, 1000, &delay);
    if (ret == -1){
        fprintf(stderr, "can't ping v4"NL);
        exit_code = EXIT_FAILURE;
        goto finish;
    }
    printf(
        "[main]code = %d, sec = %ld, nsec = %ld"NL,
        ret, delay.tv_sec, delay.tv_nsec
    );

    ret = cping_once(&cp, "::1", AF_INET6, 1000, &delay);
    if (ret == -1){
        fprintf(stderr, "can't ping v6"NL);
        exit_code = EXIT_FAILURE;
        goto finish;
    }
    printf(
        "[main]code = %d, sec = %ld, nsec = %ld"NL,
        ret, delay.tv_sec, delay.tv_nsec
    );
finish:
    cping_fini(&cp);
    return 0;
}