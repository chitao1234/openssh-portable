/*
 * Compatibility implementations for Microsoft secure CRT entry points used by
 * the Win32 port.  MinGW headers expose these functions, but the default
 * msvcrt.dll import library does not provide them on older Windows systems.
 */

#if defined(__MINGW32__)
# define _CRTBLD
# define __LIBMSVCRT__
#endif

#include <windows.h>
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <share.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <wchar.h>
#include <wctype.h>

#ifndef _TRUNCATE
# define _TRUNCATE ((size_t)-1)
#endif

#ifndef STRUNCATE
# define STRUNCATE 80
#endif

static size_t
w32_strnlen(const char *s, size_t maxlen)
{
	size_t i;

	for (i = 0; i < maxlen && s[i] != '\0'; i++)
		;
	return i;
}

static size_t
w32_wcsnlen(const wchar_t *s, size_t maxlen)
{
	size_t i;

	for (i = 0; i < maxlen && s[i] != L'\0'; i++)
		;
	return i;
}

static errno_t
w32_clear_char(char *dst, size_t size, errno_t err)
{
	if (dst != NULL && size > 0)
		dst[0] = '\0';
	return err;
}

static errno_t
w32_clear_wchar(wchar_t *dst, size_t size, errno_t err)
{
	if (dst != NULL && size > 0)
		dst[0] = L'\0';
	return err;
}

errno_t __cdecl
strcpy_s(char *dst, rsize_t size, const char *src)
{
	size_t len;

	if (dst == NULL || size == 0)
		return EINVAL;
	if (src == NULL)
		return w32_clear_char(dst, size, EINVAL);
	len = strlen(src);
	if (len + 1 > size)
		return w32_clear_char(dst, size, ERANGE);
	memcpy(dst, src, len + 1);
	return 0;
}

errno_t __cdecl
strcat_s(char *dst, rsize_t size, const char *src)
{
	size_t dst_len, src_len;

	if (dst == NULL || size == 0)
		return EINVAL;
	if (src == NULL)
		return w32_clear_char(dst, size, EINVAL);
	dst_len = w32_strnlen(dst, size);
	if (dst_len == size)
		return w32_clear_char(dst, size, EINVAL);
	src_len = strlen(src);
	if (dst_len + src_len + 1 > size)
		return w32_clear_char(dst, size, ERANGE);
	memcpy(dst + dst_len, src, src_len + 1);
	return 0;
}

errno_t __cdecl
strncpy_s(char *dst, size_t size, const char *src, size_t count)
{
	size_t copy_len;

	if (dst == NULL || size == 0)
		return EINVAL;
	if (src == NULL)
		return w32_clear_char(dst, size, EINVAL);
	if (count == 0) {
		dst[0] = '\0';
		return 0;
	}
	if (count == _TRUNCATE) {
		copy_len = strlen(src);
		if (copy_len >= size) {
			memcpy(dst, src, size - 1);
			dst[size - 1] = '\0';
			return STRUNCATE;
		}
		memcpy(dst, src, copy_len + 1);
		return 0;
	}

	copy_len = w32_strnlen(src, count);
	if (copy_len + 1 > size)
		return w32_clear_char(dst, size, ERANGE);
	memcpy(dst, src, copy_len);
	dst[copy_len] = '\0';
	return 0;
}

errno_t __cdecl
wcscpy_s(wchar_t *dst, rsize_t size, const wchar_t *src)
{
	size_t len;

	if (dst == NULL || size == 0)
		return EINVAL;
	if (src == NULL)
		return w32_clear_wchar(dst, size, EINVAL);
	len = wcslen(src);
	if (len + 1 > size)
		return w32_clear_wchar(dst, size, ERANGE);
	wmemcpy(dst, src, len + 1);
	return 0;
}

errno_t __cdecl
wcscat_s(wchar_t *dst, rsize_t size, const wchar_t *src)
{
	size_t dst_len, src_len;

	if (dst == NULL || size == 0)
		return EINVAL;
	if (src == NULL)
		return w32_clear_wchar(dst, size, EINVAL);
	dst_len = w32_wcsnlen(dst, size);
	if (dst_len == size)
		return w32_clear_wchar(dst, size, EINVAL);
	src_len = wcslen(src);
	if (dst_len + src_len + 1 > size)
		return w32_clear_wchar(dst, size, ERANGE);
	wmemcpy(dst + dst_len, src, src_len + 1);
	return 0;
}

errno_t __cdecl
wcsncpy_s(wchar_t *dst, size_t size, const wchar_t *src, size_t count)
{
	size_t copy_len;

	if (dst == NULL || size == 0)
		return EINVAL;
	if (src == NULL)
		return w32_clear_wchar(dst, size, EINVAL);
	if (count == 0) {
		dst[0] = L'\0';
		return 0;
	}
	if (count == _TRUNCATE) {
		copy_len = wcslen(src);
		if (copy_len >= size) {
			wmemcpy(dst, src, size - 1);
			dst[size - 1] = L'\0';
			return STRUNCATE;
		}
		wmemcpy(dst, src, copy_len + 1);
		return 0;
	}

	copy_len = w32_wcsnlen(src, count);
	if (copy_len + 1 > size)
		return w32_clear_wchar(dst, size, ERANGE);
	wmemcpy(dst, src, copy_len);
	dst[copy_len] = L'\0';
	return 0;
}

errno_t __cdecl
wcsncat_s(wchar_t *dst, size_t size, const wchar_t *src, size_t count)
{
	size_t dst_len, copy_len;

	if (dst == NULL || size == 0)
		return EINVAL;
	if (src == NULL)
		return w32_clear_wchar(dst, size, EINVAL);
	dst_len = w32_wcsnlen(dst, size);
	if (dst_len == size)
		return w32_clear_wchar(dst, size, EINVAL);
	if (count == _TRUNCATE) {
		copy_len = wcslen(src);
		if (dst_len + copy_len + 1 > size) {
			copy_len = size - dst_len - 1;
			wmemcpy(dst + dst_len, src, copy_len);
			dst[dst_len + copy_len] = L'\0';
			return STRUNCATE;
		}
	} else {
		copy_len = w32_wcsnlen(src, count);
		if (dst_len + copy_len + 1 > size)
			return w32_clear_wchar(dst, size, ERANGE);
	}
	wmemcpy(dst + dst_len, src, copy_len);
	dst[dst_len + copy_len] = L'\0';
	return 0;
}

errno_t __cdecl
_wcslwr_s(wchar_t *str, size_t size)
{
	size_t i;

	if (str == NULL || size == 0)
		return EINVAL;
	for (i = 0; i < size; i++) {
		if (str[i] == L'\0')
			return 0;
		str[i] = (wchar_t)towlower(str[i]);
	}
	str[0] = L'\0';
	return EINVAL;
}

errno_t __cdecl
wcstombs_s(size_t *converted, char *dst, size_t dst_size,
    const wchar_t *src, size_t count)
{
	int needed, written;
	size_t allowed;

	if (converted != NULL)
		*converted = 0;
	if (src == NULL)
		return EINVAL;

	needed = WideCharToMultiByte(CP_ACP, 0, src, -1, NULL, 0, NULL, NULL);
	if (needed <= 0)
		return EILSEQ;
	if (converted != NULL)
		*converted = (size_t)needed;
	if (dst == NULL)
		return dst_size == 0 ? 0 : EINVAL;
	if (dst_size == 0)
		return EINVAL;

	allowed = dst_size;
	if (count != _TRUNCATE && count + 1 < allowed)
		allowed = count + 1;
	if ((size_t)needed > allowed)
		return w32_clear_char(dst, dst_size, ERANGE);

	written = WideCharToMultiByte(CP_ACP, 0, src, -1, dst, (int)dst_size,
	    NULL, NULL);
	if (written <= 0)
		return w32_clear_char(dst, dst_size, EILSEQ);
	return 0;
}

static int
w32_vsnprintf_s(char *dst, size_t dst_size, size_t count, const char *fmt,
    va_list ap)
{
	va_list aq;
	size_t limit;
	int ret;

	if (dst == NULL || dst_size == 0 || fmt == NULL) {
		errno = EINVAL;
		return -1;
	}

	limit = dst_size;
	if (count != _TRUNCATE && count + 1 < limit)
		limit = count + 1;

	va_copy(aq, ap);
#if defined(__MINGW32__)
	ret = __mingw_vsnprintf(dst, limit, fmt, aq);
#else
	ret = vsnprintf(dst, limit, fmt, aq);
#endif
	va_end(aq);
	if (ret < 0 || (size_t)ret >= limit) {
		if (count == _TRUNCATE && dst_size > 0)
			dst[dst_size - 1] = '\0';
		else
			dst[0] = '\0';
		errno = ERANGE;
		return -1;
	}
	return ret;
}

int __cdecl
vsnprintf_s(char *dst, size_t dst_size, size_t count, const char *fmt,
    va_list ap)
{
	return w32_vsnprintf_s(dst, dst_size, count, fmt, ap);
}

int __cdecl
_vsnprintf_s(char *dst, size_t dst_size, size_t count, const char *fmt,
    va_list ap)
{
	return w32_vsnprintf_s(dst, dst_size, count, fmt, ap);
}

int __cdecl
_snprintf_s(char *dst, size_t dst_size, size_t count, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = w32_vsnprintf_s(dst, dst_size, count, fmt, ap);
	va_end(ap);
	return ret;
}

static int
w32_vsnwprintf_s(wchar_t *dst, size_t dst_size, size_t count,
    const wchar_t *fmt, va_list ap)
{
	va_list aq;
	size_t limit;
	int ret;

	if (dst == NULL || dst_size == 0 || fmt == NULL) {
		errno = EINVAL;
		return -1;
	}

	limit = dst_size;
	if (count != _TRUNCATE && count + 1 < limit)
		limit = count + 1;

	va_copy(aq, ap);
	ret = vswprintf(dst, limit, fmt, aq);
	va_end(aq);
	if (ret < 0 || (size_t)ret >= limit) {
		if (count == _TRUNCATE && dst_size > 0)
			dst[dst_size - 1] = L'\0';
		else
			dst[0] = L'\0';
		errno = ERANGE;
		return -1;
	}
	return ret;
}

int __cdecl
vswprintf_s(wchar_t *dst, size_t dst_size, const wchar_t *fmt, va_list ap)
{
	return w32_vsnwprintf_s(dst, dst_size, dst_size - 1, fmt, ap);
}

int __cdecl
swprintf_s(wchar_t *dst, size_t dst_size, const wchar_t *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = w32_vsnwprintf_s(dst, dst_size, dst_size - 1, fmt, ap);
	va_end(ap);
	return ret;
}

int __cdecl
_vsnwprintf_s(wchar_t *dst, size_t dst_size, size_t count,
    const wchar_t *fmt, va_list ap)
{
	return w32_vsnwprintf_s(dst, dst_size, count, fmt, ap);
}

int __cdecl
_snwprintf_s(wchar_t *dst, size_t dst_size, size_t count,
    const wchar_t *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = w32_vsnwprintf_s(dst, dst_size, count, fmt, ap);
	va_end(ap);
	return ret;
}

int __cdecl
printf_s(const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vprintf(fmt, ap);
	va_end(ap);
	return ret;
}

int __cdecl
wprintf_s(const wchar_t *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vwprintf(fmt, ap);
	va_end(ap);
	return ret;
}

errno_t __cdecl
_putenv_s(const char *name, const char *value)
{
	char *entry;
	size_t name_len, value_len;
	int ret;

	if (name == NULL || *name == '\0' || strchr(name, '=') != NULL ||
	    value == NULL)
		return EINVAL;
	name_len = strlen(name);
	value_len = strlen(value);
	entry = malloc(name_len + value_len + 2);
	if (entry == NULL)
		return ENOMEM;
	memcpy(entry, name, name_len);
	entry[name_len] = '=';
	memcpy(entry + name_len + 1, value, value_len + 1);
	ret = _putenv(entry);
	free(entry);
	return ret == 0 ? 0 : errno;
}

errno_t __cdecl
_wputenv_s(const wchar_t *name, const wchar_t *value)
{
	wchar_t *entry;
	size_t name_len, value_len;
	int ret;

	if (name == NULL || *name == L'\0' || wcschr(name, L'=') != NULL ||
	    value == NULL)
		return EINVAL;
	name_len = wcslen(name);
	value_len = wcslen(value);
	entry = malloc((name_len + value_len + 2) * sizeof(*entry));
	if (entry == NULL)
		return ENOMEM;
	wmemcpy(entry, name, name_len);
	entry[name_len] = L'=';
	wmemcpy(entry + name_len + 1, value, value_len + 1);
	ret = _wputenv(entry);
	free(entry);
	return ret == 0 ? 0 : errno;
}

errno_t __cdecl
_wfopen_s(FILE **file, const wchar_t *filename, const wchar_t *mode)
{
	if (file == NULL)
		return EINVAL;
	*file = NULL;
	if (filename == NULL || mode == NULL)
		return EINVAL;
	*file = _wfopen(filename, mode);
	return *file != NULL ? 0 : errno;
}

errno_t __cdecl
_wsopen_s(int *fd, const wchar_t *filename, int oflag, int shflag, int pmode)
{
	if (fd == NULL)
		return EINVAL;
	*fd = -1;
	if (filename == NULL)
		return EINVAL;
	*fd = _wsopen(filename, oflag, shflag, pmode);
	return *fd != -1 ? 0 : errno;
}

wint_t __cdecl
_getwch(void)
{
	HANDLE input;
	INPUT_RECORD rec;
	DWORD mode, read;
	wchar_t ch;

	input = GetStdHandle(STD_INPUT_HANDLE);
	if (input != INVALID_HANDLE_VALUE && input != NULL &&
	    GetConsoleMode(input, &mode)) {
		for (;;) {
			if (!ReadConsoleInputW(input, &rec, 1, &read) ||
			    read != 1)
				break;
			if (rec.EventType == KEY_EVENT &&
			    rec.Event.KeyEvent.bKeyDown) {
				ch = rec.Event.KeyEvent.uChar.UnicodeChar;
				if (ch != L'\0')
					return ch;
			}
		}
	}

	if (input != INVALID_HANDLE_VALUE && input != NULL &&
	    ReadFile(input, &ch, sizeof(ch), &read, NULL) &&
	    read == sizeof(ch))
		return ch;
	return WEOF;
}

int __cdecl
_cputws(const wchar_t *str)
{
	HANDLE output;
	DWORD mode, written;
	int len, bytes;
	char *mb;

	if (str == NULL)
		return -1;
	output = GetStdHandle(STD_OUTPUT_HANDLE);
	if (output != INVALID_HANDLE_VALUE && output != NULL &&
	    GetConsoleMode(output, &mode)) {
		if (WriteConsoleW(output, str, (DWORD)wcslen(str), &written,
		    NULL))
			return 0;
		return -1;
	}

	len = WideCharToMultiByte(CP_UTF8, 0, str, -1, NULL, 0, NULL, NULL);
	if (len <= 0)
		return -1;
	mb = malloc((size_t)len);
	if (mb == NULL)
		return -1;
	bytes = WideCharToMultiByte(CP_UTF8, 0, str, -1, mb, len, NULL, NULL);
	if (bytes > 0)
		fputs(mb, stdout);
	free(mb);
	return bytes > 0 ? 0 : -1;
}

#if defined(__MINGW32__)
# if defined(_WIN64)
#  define W32_CRT_IMPORT(name) __imp_ ## name
# else
#  define W32_CRT_IMPORT(name) _imp__ ## name
# endif

void *W32_CRT_IMPORT(strcpy_s) = (void *)strcpy_s;
void *W32_CRT_IMPORT(strcat_s) = (void *)strcat_s;
void *W32_CRT_IMPORT(strncpy_s) = (void *)strncpy_s;
void *W32_CRT_IMPORT(wcscpy_s) = (void *)wcscpy_s;
void *W32_CRT_IMPORT(wcscat_s) = (void *)wcscat_s;
void *W32_CRT_IMPORT(wcsncpy_s) = (void *)wcsncpy_s;
void *W32_CRT_IMPORT(wcsncat_s) = (void *)wcsncat_s;
void *W32_CRT_IMPORT(wcstombs_s) = (void *)wcstombs_s;
void *W32_CRT_IMPORT(_wcslwr_s) = (void *)_wcslwr_s;
void *W32_CRT_IMPORT(vsnprintf_s) = (void *)vsnprintf_s;
void *W32_CRT_IMPORT(_vsnprintf_s) = (void *)_vsnprintf_s;
void *W32_CRT_IMPORT(_snprintf_s) = (void *)_snprintf_s;
void *W32_CRT_IMPORT(vswprintf_s) = (void *)vswprintf_s;
void *W32_CRT_IMPORT(swprintf_s) = (void *)swprintf_s;
void *W32_CRT_IMPORT(_vsnwprintf_s) = (void *)_vsnwprintf_s;
void *W32_CRT_IMPORT(_snwprintf_s) = (void *)_snwprintf_s;
void *W32_CRT_IMPORT(printf_s) = (void *)printf_s;
void *W32_CRT_IMPORT(wprintf_s) = (void *)wprintf_s;
void *W32_CRT_IMPORT(_putenv_s) = (void *)_putenv_s;
void *W32_CRT_IMPORT(_wputenv_s) = (void *)_wputenv_s;
void *W32_CRT_IMPORT(_wfopen_s) = (void *)_wfopen_s;
void *W32_CRT_IMPORT(_wsopen_s) = (void *)_wsopen_s;
void *W32_CRT_IMPORT(_getwch) = (void *)_getwch;
void *W32_CRT_IMPORT(_cputws) = (void *)_cputws;
#endif
