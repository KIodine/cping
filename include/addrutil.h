#ifndef ADDRUTIL_H
#define ADDRUTIL_H

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>

#include "dbg_common.h"


int addr_cmp(struct sockaddr *restrict a, struct sockaddr *restrict b);
int addr_cpy(struct sockaddr *restrict dst, struct sockaddr *restrict src);


#endif /* ADDRUTIL_H */