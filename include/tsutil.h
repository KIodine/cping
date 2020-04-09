#ifndef TIMESEPCUTIL_H
#define TIMESPECUTIL_H

#define _GNU_SOURCE
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <sys/time.h>

/* TODO: support negative arithmetic? */

enum {
    TIMESPEC_TO_MS = 0,
    TIMESPEC_TO_US,
    TIMESPEC_TO_NS,
};

int ts_add(struct timespec *r, struct timespec *a, struct timespec *b);
int ts_sub(struct timespec *r, struct timespec *a, struct timespec *b);

int ts_cmp(struct timespec *a, struct timespec *b);

int ts_to_unit(int unit, struct timespec *ts, long *res);
int unit_to_ts(int unit, long val, struct timespec *res);

#endif /* TIMESPECUTIL_H */