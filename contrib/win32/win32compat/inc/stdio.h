#pragma once
#if defined(__GNUC__)
# include_next <stdio.h>
#else
# include "crtheaders.h"
# include STDIO_H
#endif

/* stdio.h overrides */
FILE* w32_fopen_utf8(const char *, const char *);
#ifndef WIN32COMPAT_IMPL
# define fopen w32_fopen_utf8
#endif

char* w32_fgets(char *str, int n, FILE *stream);
#ifndef WIN32COMPAT_IMPL
# define fgets w32_fgets
#endif

int w32_setvbuf(FILE *stream,char *buffer, int mode, size_t size);
#ifndef WIN32COMPAT_IMPL
# define setvbuf w32_setvbuf
#endif

/* stdio.h additional definitions */
#define popen _popen
#define pclose _pclose

FILE* w32_fdopen(int fd, const char *mode);
#ifndef WIN32COMPAT_IMPL
# define fdopen(a,b)	w32_fdopen((a), (b))
#endif

int w32_rename(const char *old_name, const char *new_name);
#ifndef WIN32COMPAT_IMPL
# define rename w32_rename
#endif
