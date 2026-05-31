#pragma once

#include "sys/types.h"

#undef WIFEXITED
#undef WIFSTOPPED
#undef WIFSIGNALED
#undef WEXITSTATUS
#undef WTERMSIG
#undef WCOREDUMP
#undef WCOREFLAG

#define _W_INT(w)	(*(int *)&(w))
#define WIFEXITED(w)	(!((_W_INT(w)) & 0377))
#define WIFSTOPPED(w)	((_W_INT(w)) & 0100)
#define WIFSIGNALED(w)	(!WIFEXITED(w) && !WIFSTOPPED(w))
#define WEXITSTATUS(w)	(int)(WIFEXITED(w) ? ((_W_INT(w) >> 8) & 0377) : -1)
#define WTERMSIG(w)	(int)(WIFSIGNALED(w) ? (_W_INT(w) & 0177) : -1)
#define WCOREFLAG	0x80
#define WCOREDUMP(w)	((_W_INT(w)) & WCOREFLAG)

#ifndef WNOHANG
#define WNOHANG 1
#endif

#ifndef WUNTRACED
#define WUNTRACED 2
#endif

pid_t waitpid(int pid, int *status, int options);
