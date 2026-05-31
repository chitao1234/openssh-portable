#pragma once

#include <sys/types.h>
#include <winsock2.h>

#ifndef HAVE_NFDS_T
typedef unsigned int nfds_t;
#endif

#ifndef POLLIN
# define POLLIN 0x0001
#endif
#ifndef POLLPRI
# define POLLPRI 0x0002
#endif
#ifndef POLLOUT
# define POLLOUT 0x0004
#endif
#ifndef POLLERR
# define POLLERR 0x0008
#endif
#ifndef POLLHUP
# define POLLHUP 0x0010
#endif
#ifndef POLLNVAL
# define POLLNVAL 0x0020
#endif
#ifndef INFTIM
# define INFTIM (-1)
#endif
