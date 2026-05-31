#pragma once

#ifdef mkdir
#define W32_RESTORE_MKDIR
#undef mkdir
#endif

#if defined(__GNUC__)
# include_next <direct.h>
#else
# include "crtheaders.h"
# include DIRECT_H
#endif

int w32_mkdir(const char *pathname, unsigned short mode);

#ifdef W32_RESTORE_MKDIR
#define mkdir(path, mode) w32_mkdir((path), (mode))
#undef W32_RESTORE_MKDIR
#endif
