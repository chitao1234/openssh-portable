/*
 * Small XP-compatible ACL helper for Win32 OpenSSH tests.
 *
 * Build from the parent build directory:
 *   i686-w64-mingw32-gcc -Wall -Wextra -O0 -g \
 *       -o win32-acl-tool.exe \
 *       ../openssh-portable/regress/misc/win32-acl-tool.c \
 *       -ladvapi32
 *
 * Usage:
 *   win32-acl-tool.exe set-owner <path> <account>
 *   win32-acl-tool.exe set-sddl <path> <sddl>
 *   win32-acl-tool.exe show <path>
 */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void
usage(const char *prog)
{
	fprintf(stderr,
	    "usage: %s set-owner <path> <account>\n"
	    "       %s set-sddl <path> <sddl>\n"
	    "       %s show <path>\n",
	    prog, prog, prog);
}

static void
print_last_error(const char *what)
{
	fprintf(stderr, "%s failed: %lu\n", what, GetLastError());
}

static wchar_t *
utf8_to_utf16(const char *s)
{
	wchar_t *ret;
	int len;

	len = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
	if (len <= 0) {
		print_last_error("MultiByteToWideChar(size)");
		return NULL;
	}
	ret = (wchar_t *)calloc((size_t)len, sizeof(*ret));
	if (ret == NULL)
		return NULL;
	if (MultiByteToWideChar(CP_UTF8, 0, s, -1, ret, len) <= 0) {
		print_last_error("MultiByteToWideChar(data)");
		free(ret);
		return NULL;
	}
	return ret;
}

static char *
utf16_to_utf8(const wchar_t *s)
{
	char *ret;
	int len;

	len = WideCharToMultiByte(CP_UTF8, 0, s, -1, NULL, 0, NULL, NULL);
	if (len <= 0) {
		print_last_error("WideCharToMultiByte(size)");
		return NULL;
	}
	ret = (char *)calloc((size_t)len, sizeof(*ret));
	if (ret == NULL)
		return NULL;
	if (WideCharToMultiByte(CP_UTF8, 0, s, -1, ret, len, NULL,
	    NULL) <= 0) {
		print_last_error("WideCharToMultiByte(data)");
		free(ret);
		return NULL;
	}
	return ret;
}

static int
set_privilege(const wchar_t *privilege, BOOL enable)
{
	HANDLE token = NULL;
	TOKEN_PRIVILEGES tp;
	LUID luid;
	int ret = 1;

	if (!OpenProcessToken(GetCurrentProcess(),
	    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
		print_last_error("OpenProcessToken");
		goto done;
	}
	if (!LookupPrivilegeValueW(NULL, privilege, &luid)) {
		print_last_error("LookupPrivilegeValueW");
		goto done;
	}
	memset(&tp, 0, sizeof(tp));
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
	if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL) ||
	    GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		print_last_error("AdjustTokenPrivileges");
		goto done;
	}
	ret = 0;

done:
	if (token != NULL)
		CloseHandle(token);
	return ret;
}

static PSID
account_to_sid(const wchar_t *account)
{
	DWORD sid_len = 0, domain_len = 0;
	SID_NAME_USE use;
	PSID sid;
	wchar_t *domain;

	LookupAccountNameW(NULL, account, NULL, &sid_len, NULL, &domain_len,
	    &use);
	if (sid_len == 0) {
		print_last_error("LookupAccountNameW(size)");
		return NULL;
	}
	sid = calloc(1, sid_len);
	domain = calloc((size_t)domain_len + 1, sizeof(*domain));
	if (sid == NULL || domain == NULL) {
		free(sid);
		free(domain);
		return NULL;
	}
	if (!LookupAccountNameW(NULL, account, sid, &sid_len, domain,
	    &domain_len, &use)) {
		print_last_error("LookupAccountNameW(data)");
		free(sid);
		free(domain);
		return NULL;
	}
	free(domain);
	return sid;
}

static int
set_owner(const char *path_arg, const char *account_arg)
{
	wchar_t *path = NULL, *account = NULL;
	PSID sid = NULL;
	DWORD err;
	int ret = 1;

	path = utf8_to_utf16(path_arg);
	account = utf8_to_utf16(account_arg);
	if (path == NULL || account == NULL)
		goto done;
	sid = account_to_sid(account);
	if (sid == NULL)
		goto done;

	set_privilege(L"SeRestorePrivilege", TRUE);
	set_privilege(L"SeTakeOwnershipPrivilege", TRUE);
	err = SetNamedSecurityInfoW(path, SE_FILE_OBJECT,
	    OWNER_SECURITY_INFORMATION, sid, NULL, NULL, NULL);
	if (err != ERROR_SUCCESS) {
		fprintf(stderr, "SetNamedSecurityInfoW(owner) failed: %lu\n",
		    err);
		goto done;
	}
	ret = 0;

done:
	set_privilege(L"SeTakeOwnershipPrivilege", FALSE);
	set_privilege(L"SeRestorePrivilege", FALSE);
	free(path);
	free(account);
	free(sid);
	return ret;
}

static int
set_sddl(const char *path_arg, const char *sddl_arg)
{
	wchar_t *path = NULL, *sddl = NULL;
	PSECURITY_DESCRIPTOR sd = NULL;
	SECURITY_INFORMATION info = 0;
	int ret = 1;

	path = utf8_to_utf16(path_arg);
	sddl = utf8_to_utf16(sddl_arg);
	if (path == NULL || sddl == NULL)
		goto done;
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,
	    SDDL_REVISION_1, &sd, NULL)) {
		print_last_error("ConvertStringSecurityDescriptorToSecurityDescriptorW");
		goto done;
	}
	if (wcsstr(sddl, L"O:") != NULL)
		info |= OWNER_SECURITY_INFORMATION;
	if (wcsstr(sddl, L"G:") != NULL)
		info |= GROUP_SECURITY_INFORMATION;
	if (wcsstr(sddl, L"D:") != NULL)
		info |= DACL_SECURITY_INFORMATION;
	if (wcsstr(sddl, L"S:") != NULL)
		info |= SACL_SECURITY_INFORMATION;
	if (info == 0) {
		fprintf(stderr, "set-sddl requires at least one O:, G:, D:, or S: component\n");
		goto done;
	}

	set_privilege(L"SeRestorePrivilege", TRUE);
	set_privilege(L"SeTakeOwnershipPrivilege", TRUE);
	if (!SetFileSecurityW(path, info, sd)) {
		print_last_error("SetFileSecurityW");
		goto done;
	}
	ret = 0;

done:
	set_privilege(L"SeTakeOwnershipPrivilege", FALSE);
	set_privilege(L"SeRestorePrivilege", FALSE);
	if (sd != NULL)
		LocalFree(sd);
	free(path);
	free(sddl);
	return ret;
}

static int
show(const char *path_arg)
{
	PSECURITY_DESCRIPTOR sd = NULL;
	wchar_t *path = NULL, *sddl = NULL;
	char *sddl_utf8 = NULL;
	DWORD err;
	int ret = 1;

	path = utf8_to_utf16(path_arg);
	if (path == NULL)
		goto done;
	err = GetNamedSecurityInfoW(path, SE_FILE_OBJECT,
	    OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
	    DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &sd);
	if (err != ERROR_SUCCESS) {
		fprintf(stderr, "GetNamedSecurityInfoW failed: %lu\n", err);
		goto done;
	}
	if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(sd,
	    SDDL_REVISION_1, OWNER_SECURITY_INFORMATION |
	    GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &sddl,
	    NULL)) {
		print_last_error("ConvertSecurityDescriptorToStringSecurityDescriptorW");
		goto done;
	}
	sddl_utf8 = utf16_to_utf8(sddl);
	if (sddl_utf8 == NULL)
		goto done;
	printf("%s\n", sddl_utf8);
	ret = 0;

done:
	free(path);
	free(sddl_utf8);
	if (sddl != NULL)
		LocalFree(sddl);
	if (sd != NULL)
		LocalFree(sd);
	return ret;
}

int
main(int argc, char **argv)
{
	if (argc < 3) {
		usage(argv[0]);
		return 2;
	}
	if (strcmp(argv[1], "set-owner") == 0) {
		if (argc != 4) {
			usage(argv[0]);
			return 2;
		}
		return set_owner(argv[2], argv[3]);
	}
	if (strcmp(argv[1], "set-sddl") == 0) {
		if (argc != 4) {
			usage(argv[0]);
			return 2;
		}
		return set_sddl(argv[2], argv[3]);
	}
	if (strcmp(argv[1], "show") == 0) {
		if (argc != 3) {
			usage(argv[0]);
			return 2;
		}
		return show(argv[2]);
	}
	usage(argv[0]);
	return 2;
}
