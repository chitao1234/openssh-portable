#pragma once

#ifndef __STDC__
#define __STDC__ 1
#endif
#if defined(__GNUC__)
# include_next <sys/types.h>
#else
# include "../crtheaders.h"
# include SYS_TYPES_H
#endif

#ifndef _DEV_T_DEFINED
#define _DEV_T_DEFINED
typedef unsigned int _dev_t;
#endif
#ifndef dev_t
typedef _dev_t dev_t;
#endif

#ifndef _INO_T_DEFINED
#define _INO_T_DEFINED
typedef unsigned short _ino_t;
#endif
#ifndef ino_t
typedef _ino_t ino_t;
#endif

#ifndef _MODE_T_
#define _MODE_T_
typedef unsigned short _mode_t;
typedef _mode_t mode_t;
#endif

#ifndef _PID_T_
#define _PID_T_
typedef int _pid_t;
#endif
#ifndef pid_t
typedef _pid_t pid_t;
#endif

#ifndef _OFF_T_DEFINED
#define _OFF_T_DEFINED
typedef long long off_t;
#endif

#ifndef _OFF64_T_DEFINED
#define _OFF64_T_DEFINED
typedef long long _off64_t;
#ifndef off64_t
typedef long long off64_t;
#endif
#endif

#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef int ssize_t;
#endif

typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef unsigned int nfds_t;

/* copied from Windows SDK corecrt_wstdio.h to accomodate FILE definition via types.h in Unix */
#ifndef _FILE_DEFINED
#define _FILE_DEFINED
typedef struct _iobuf
{
	void* _Placeholder;
} FILE;
#endif
