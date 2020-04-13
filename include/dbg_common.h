#ifndef CPINGDBG_H
#define CPINGDBG_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#define NL     "\n"
#define DBG_PREFIX "[cping|dbg|%s:%d]"
#define ERR_PREFIX "[cping|err|%s:%d]"
#define FATAL_PREFIX "[cping|fatal|%s:%d]"

#ifndef NDEBUG
    #define debug_printf(fmt, ...)\
    printf(DBG_PREFIX fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#else
    #define debug_printf(fmt, ...) ((void)0)
#endif

#define error_printf(fmt, ...)\
fprintf(stderr, ERR_PREFIX fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#define ASSUME(cond, errmsg, ...)\
if (!(cond)){\
    fprintf(stderr, FATAL_PREFIX errmsg, __FILE__, __LINE__, ##__VA_ARGS__);\
    abort();\
}

#endif /* CPINGDBG_H*/