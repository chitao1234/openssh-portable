#pragma once
#if defined(__GNUC__)
# include_next <time.h>
#else
# include "crtheaders.h"
# include TIME_H
#endif

#define localtime w32_localtime
#define ctime w32_ctime
#define nanosleep w32_nanosleep

struct tm *localtime_r(const time_t *, struct tm *);
struct tm *w32_localtime(const time_t* sourceTime);
char *w32_ctime(const time_t* sourceTime);
int w32_nanosleep(const struct timespec *, struct timespec *);
