#pragma once
#if defined(__GNUC__)
# include <corecrt_wstdlib.h>
# include <sec_api/stdlib_s.h>
# include_next <stdlib.h>
#else
# include "crtheaders.h"
# include STDLIB_H
#endif

#if defined(__GNUC__)
errno_t w32_dupenv_s(char **buffer, size_t *number_of_elements,
    const char *varname);
errno_t w32_wdupenv_s(wchar_t **buffer, size_t *number_of_elements,
    const wchar_t *varname);
errno_t w32_get_wpgmptr(wchar_t **value);
# define _dupenv_s w32_dupenv_s
# define _wdupenv_s w32_wdupenv_s
# define _get_wpgmptr w32_get_wpgmptr
#endif

#define environ _environ
void freezero(void *, size_t);
int setenv(const char *name, const char *value, int rewrite);
#define system w32_system
int w32_system(const char *command);
char* realpath(const char *pathname, char *resolved);
