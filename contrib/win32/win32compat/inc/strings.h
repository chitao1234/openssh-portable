#pragma once

#if !defined(HAVE_BZERO) && !defined(HAVE_DECL_BZERO)
#define bzero(p,l) memset((void *)(p),0,(size_t)(l))
#endif

#if defined(HAVE_DECL_BZERO) && HAVE_DECL_BZERO == 1
void bzero(void *, size_t);
#endif

void
explicit_bzero(void *b, size_t len);
