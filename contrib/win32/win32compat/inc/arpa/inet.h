#ifndef COMPAT_INET_H
#define COMPAT_INET_H 1

#include <sys/socket.h>

const char *w32_inet_ntop(int, const void *, char *, socklen_t);
#ifndef WIN32COMPAT_IMPL
# define inet_ntop(a,b,c,d) w32_inet_ntop((a), (b), (c), (d))
#endif

#endif
