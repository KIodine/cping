# The cping Library
A library provide simple ping functionality in C API.

This library requires root privilege to create a raw socket.

# Table Of Content

# Feature
Provide C level interface for programmer.

# Build
```
make static
# or
make shared
```

# Example
```
#include "cping.h"

struct cping_ctx cp;
struct trnode *trhead;
struct timespec delay;
int icmp_type;

/* Initialize cping instance */
ret = cping_init(&cp);
if (ret != 0){
    fprintf(stderr, "Can't init cping\n");
}

/* Ping host with specific address family. */
icmp_type = cping_once(
    &cp, <host>, <AF_INET|AF_INET6>, <timeout:ms>, &delay
);

/* Or you have certain address. */
icmp_type = cping_addr_once(
    &cp, <addr>, <addrlen>, <timeout:ms>, &delay
);

/* Tracing route to host with maximum hop <maxhop>. */
trhead = cping_tracert(
    &cp, <addr>, <addrlen>, <timeout:ms>, <maxhop>
);

/* Iterate over nodes in linked-list flavor. */
for (struct trnode *cur = trhead; cur != NULL; cur = cur->next){
    /* do something to `cur` node. */
}

freetrnode(trhead);
trhead = NULL;


/* Finally releases resources used by instance. */
cping_fini(&cp);

```

# License
[![License](http://img.shields.io/:license-mit-blue.svg?style=flat-square)](http://badges.mit-license.org)

cping is distributed under MIT license.