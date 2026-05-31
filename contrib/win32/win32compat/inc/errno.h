#pragma once

#if defined(__GNUC__)
# include_next <errno.h>
#else
# include "crtheaders.h"
# include ERRNO_H
#endif

#ifndef EOTHER
# define EOTHER 131
#endif
