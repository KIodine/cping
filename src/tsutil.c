#include "tsutil.h"

static const long NSEC_PER_SEC = 1000000000L;
static const long USEC_PER_SEC = 1000000L;
static const long MSEC_PER_SEC = 1000L;

static inline long to_ms(struct timespec *ts);
static inline long to_us(struct timespec *ts);
static inline long to_ns(struct timespec *ts);


static inline long to_ms(struct timespec *ts){
    return (ts->tv_sec*1000 + ts->tv_nsec/1000000);
}

static inline long to_us(struct timespec *ts){
    return (ts->tv_sec*1000000 + ts->tv_nsec/1000);
}

static inline long to_ns(struct timespec *ts){
    return (ts->tv_sec*NSEC_PER_SEC + ts->tv_nsec);
}


int ts_add(
    struct timespec *r, struct timespec *a, struct timespec *b
){
    r->tv_sec  = a->tv_sec  + b->tv_sec;
    r->tv_nsec = a->tv_nsec + b->tv_nsec;
    if (r->tv_nsec > NSEC_PER_SEC){
        r->tv_sec  += 1;
        r->tv_nsec -= NSEC_PER_SEC;
    }
    return 0;
}

int ts_sub(
    struct timespec *r, struct timespec *a, struct timespec *b
){
    r->tv_sec  = a->tv_sec  - b->tv_sec;
    r->tv_nsec = a->tv_nsec - b->tv_nsec;
    if (r->tv_nsec < 0){
        r->tv_sec  -= 1;
        r->tv_nsec += NSEC_PER_SEC;
    }
    return 0;
}

int ts_cmp(struct timespec *a, struct timespec *b){
    int res;
    if (a->tv_sec > b->tv_sec){
        res = 1;  goto finish;
    } else if (a->tv_sec < b->tv_sec){
        res = -1; goto finish;
    }
    /* continue to compare `struct timespec::tv_nsec`. */
    if (a->tv_nsec > b->tv_nsec){
        res = 1;  goto finish;
    } else if (a->tv_nsec < b->tv_nsec){
        res = -1; goto finish;
    }
    res = 0;
finish:
    return res;
}

int ts_to_unit(int unit, struct timespec *ts, long *res){
    int ret = 0;
    switch (unit){
    case TIMESPEC_TO_MS:
        *res = to_ms(ts); break;
    case TIMESPEC_TO_US:
        *res = to_us(ts); break;
    case TIMESPEC_TO_NS:
        *res = to_ns(ts); break;
    default:
        errno = EINVAL;
        ret   = -1;
    }
    return ret;
}

int unit_to_ts(int unit, long val, struct timespec *res){
    int ret = 0;
    switch (unit){
    case TIMESPEC_TO_MS:
        res->tv_sec  = val/MSEC_PER_SEC;
        res->tv_nsec = val*USEC_PER_SEC; break;
    case TIMESPEC_TO_US:
        res->tv_sec  = val/USEC_PER_SEC;
        res->tv_nsec = val*MSEC_PER_SEC; break;
    case TIMESPEC_TO_NS:
        res->tv_sec  = val/NSEC_PER_SEC;
        res->tv_nsec = val;              break;
    default:
        errno = EINVAL;
        ret   = -1;
    }
    return ret;
}
