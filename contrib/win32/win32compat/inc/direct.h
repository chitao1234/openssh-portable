#pragma once

#if defined(__GNUC__)
# include_next <direct.h>
#else
# include "crtheaders.h"
# include DIRECT_H
#endif

int w32_mkdir(const char *pathname, unsigned short mode);
#undef mkdir
#define mkdir(path, mode) w32_mkdir((path), (mode))
