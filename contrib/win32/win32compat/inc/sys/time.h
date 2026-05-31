#pragma once
#if defined(__GNUC__)
# include_next <sys/time.h>
#else
# include "../crtheaders.h"
# include SYS_TIME_H
#endif
#include <sys/utime.h>
#include <time.h>

#define utimbuf _utimbuf
#define utimes w32_utimes

struct itimerval {
	struct timeval it_interval; /* Timer interval */
	struct timeval it_value;    /* Current value */
};

#define ITIMER_REAL 0

int usleep(unsigned int);
int gettimeofday(struct timeval *, void *);
int w32_utimes(const char *, struct timeval *);
