#ifndef CPAUX_H
#define CPAUX_H

#include <stdint.h>
#include <arpa/inet.h> /* inet_htons */

/* auxiliary routines for `cping.c` */

uint16_t inet_checksum16(const void *buf, unsigned int len);

/*
    inet_checksum
    make packets(v4, v6)
*/



#endif /* CPAUX_H */