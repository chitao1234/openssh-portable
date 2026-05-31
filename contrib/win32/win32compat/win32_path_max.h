#pragma once

/* Maximum potential path size when Windows long paths are enabled. */
#ifndef WIN32_PATH_MAX
#define WIN32_PATH_MAX 32768
#endif

#if !defined(PATH_MAX) || PATH_MAX < WIN32_PATH_MAX
#ifdef PATH_MAX
#undef PATH_MAX
#endif
#define PATH_MAX WIN32_PATH_MAX
#endif
