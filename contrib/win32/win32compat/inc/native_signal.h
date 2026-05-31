#pragma once

#undef signal
#undef raise
#undef SIGINT
#undef SIGILL
#undef SIGSEGV
#undef SIGTERM
#undef SIGFPE
#undef SIGABRT
#undef SIG_DFL
#undef SIG_IGN
#undef SIG_ERR
#undef NSIG

#if defined(__GNUC__)
# include_next <signal.h>
#else
# include "crtheaders.h"
# include SIGNAL_H
#endif
