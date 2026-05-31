#pragma once
#if defined(__GNUC__)
# include_next <ctype.h>
#else
# include "crtheaders.h"
# include CTYPE_H
#endif

#define isascii __isascii
