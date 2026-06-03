/*
 * Registry helper for installing or removing the diagnostic XP LSA
 * authentication package. This avoids XP reg.exe quoting problems for the
 * "Authentication Packages" REG_MULTI_SZ value.
 *
 * Build from the parent build directory:
 *   i686-w64-mingw32-gcc -Wall -Wextra -O0 -g \
 *       -o win32-lsa-auth-package-install.exe \
 *       ../openssh-portable/regress/misc/win32-lsa-auth-package-install.c \
 *       -ladvapi32
 *
 * Usage:
 *   win32-lsa-auth-package-install.exe install
 *   win32-lsa-auth-package-install.exe remove
 */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LSA_KEY "SYSTEM\\CurrentControlSet\\Control\\Lsa"
#define AUTH_PACKAGES "Authentication Packages"
#define PROBE_PACKAGE "win32-lsa-auth-package-probe"

static int
read_auth_packages(HKEY key, char **out, DWORD *out_bytes)
{
	DWORD type = 0, bytes = 0, err;
	char *buf;

	err = RegQueryValueExA(key, AUTH_PACKAGES, NULL, &type, NULL, &bytes);
	if (err != ERROR_SUCCESS) {
		printf("RegQueryValueExA(size) failed: %lu\n", err);
		return 1;
	}
	if (type != REG_MULTI_SZ) {
		printf("unexpected Authentication Packages type: %lu\n", type);
		return 1;
	}
	buf = (char *)calloc(1, bytes + 2);
	if (buf == NULL)
		return 1;
	err = RegQueryValueExA(key, AUTH_PACKAGES, NULL, &type, (BYTE *)buf,
	    &bytes);
	if (err != ERROR_SUCCESS) {
		printf("RegQueryValueExA(data) failed: %lu\n", err);
		free(buf);
		return 1;
	}
	buf[bytes] = '\0';
	buf[bytes + 1] = '\0';
	*out = buf;
	*out_bytes = bytes;
	return 0;
}

static int
package_present(const char *multi)
{
	const char *p;

	for (p = multi; *p != '\0'; p += strlen(p) + 1) {
		if (_stricmp(p, PROBE_PACKAGE) == 0)
			return 1;
	}
	return 0;
}

static DWORD
multi_sz_bytes(const char *multi)
{
	const char *p = multi;

	while (*p != '\0')
		p += strlen(p) + 1;
	return (DWORD)(p - multi + 1);
}

static void
print_packages(const char *multi)
{
	const char *p;

	printf("Authentication Packages:\n");
	for (p = multi; *p != '\0'; p += strlen(p) + 1)
		printf("  %s\n", p);
}

static int
write_auth_packages(HKEY key, const char *multi)
{
	DWORD bytes = multi_sz_bytes(multi), err;

	err = RegSetValueExA(key, AUTH_PACKAGES, 0, REG_MULTI_SZ,
	    (const BYTE *)multi, bytes);
	if (err != ERROR_SUCCESS) {
		printf("RegSetValueExA failed: %lu\n", err);
		return 1;
	}
	return 0;
}

static int
install_package(HKEY key, const char *old, DWORD old_bytes)
{
	char *next;
	DWORD add_bytes = sizeof(PROBE_PACKAGE);
	int ret;

	if (package_present(old)) {
		print_packages(old);
		return 0;
	}

	next = (char *)calloc(1, old_bytes + add_bytes + 1);
	if (next == NULL)
		return 1;
	if (old_bytes > 0)
		memcpy(next, old, old_bytes - 1);
	memcpy(next + old_bytes - 1, PROBE_PACKAGE, add_bytes);
	next[old_bytes - 1 + add_bytes] = '\0';

	ret = write_auth_packages(key, next);
	if (ret == 0)
		print_packages(next);
	free(next);
	return ret;
}

static int
remove_package(HKEY key, const char *old)
{
	const char *p;
	char *next, *out;
	int ret;

	next = (char *)calloc(1, multi_sz_bytes(old) + 1);
	if (next == NULL)
		return 1;
	out = next;
	for (p = old; *p != '\0'; p += strlen(p) + 1) {
		size_t len = strlen(p) + 1;
		if (_stricmp(p, PROBE_PACKAGE) == 0)
			continue;
		memcpy(out, p, len);
		out += len;
	}
	*out = '\0';

	ret = write_auth_packages(key, next);
	if (ret == 0)
		print_packages(next);
	free(next);
	return ret;
}

int
main(int argc, char **argv)
{
	HKEY key = NULL;
	char *multi = NULL;
	DWORD bytes = 0, err;
	int ret = 1;

	if (argc != 2 ||
	    (strcmp(argv[1], "install") != 0 && strcmp(argv[1], "remove") != 0)) {
		fprintf(stderr, "usage: %s install|remove\n", argv[0]);
		return 2;
	}

	err = RegOpenKeyExA(HKEY_LOCAL_MACHINE, LSA_KEY, 0,
	    KEY_QUERY_VALUE | KEY_SET_VALUE, &key);
	if (err != ERROR_SUCCESS) {
		printf("RegOpenKeyExA failed: %lu\n", err);
		goto done;
	}
	if (read_auth_packages(key, &multi, &bytes) != 0)
		goto done;

	if (strcmp(argv[1], "install") == 0)
		ret = install_package(key, multi, bytes);
	else
		ret = remove_package(key, multi);

done:
	free(multi);
	if (key != NULL)
		RegCloseKey(key);
	return ret;
}
