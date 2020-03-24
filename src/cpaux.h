#ifndef CPAUX_H
#define CPAUX_H

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


/*
    auxiliary routines for library `cping`, including macros and
    helper functions.
    putting the includes here would avoid symbols from polluting
    autocompletion, also make the library header much cleaner.

    note that source files including this header must be put into `ld`
    prior than other compilation units
*/


#define NL "\n"
#define PREFIX "[cping]"

#ifndef NDEBUG
    #define debug_printf(fmt, ...) printf(PREFIX fmt, ##__VA_ARGS__)
#else
    #define debug_printf(ignore, ...) ((void)0)
#endif


#define ICMP_HDR_SZ 8UL
#define ETH_MTU     1500UL


/* create and setup IPv4 raw socket */
int create_v4raw(void);
/* create and setup IPv6 raw socket */
int create_v6raw(void);
/* make ICMP echo request pack */
ssize_t init_icmp_pack(void *buf, size_t len);
uint16_t inet_checksum16(char *buf, unsigned int len);
int setup_icmp_er(int family, void *buf, size_t len, uint16_t id, uint16_t seq);

int verify_v4_packet(void *buf, size_t len, uint16_t id, uint16_t seq);
int verify_v6_packet(void *buf, size_t len, uint16_t id, uint16_t seq);


#endif /* CPAUX_H */