/*
 * Diagnostic client for win32-lsa-auth-package-probe.dll.
 *
 * Build from the parent build directory:
 *   i686-w64-mingw32-gcc -Wall -Wextra -O0 -g \
 *       -o win32-lsa-auth-probe.exe \
 *       ../openssh-portable/regress/misc/win32-lsa-auth-probe.c \
 *       -ladvapi32 -lsecur32
 *
 * The matching package returns a diagnostic local-user token when LSASS
 * accepts the probe request. A useful XP result is a returned token plus an
 * LSASS-side trace in:
 *   C:\chi\win32-lsa-auth-package-probe.log
 */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#define SECURITY_WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ntsecapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#define OPENSSH_LSA_AUTH_PROBE_PACKAGE "OpenSSHLsaProbe"
#define OPENSSH_LSA_AUTH_PROBE_MAGIC 0x4f535841UL /* "OSXA" */
#define OPENSSH_LSA_AUTH_PROBE_VERSION 1

typedef struct _OPENSSH_LSA_AUTH_PROBE_REQUEST {
	ULONG magic;
	ULONG version;
	ULONG flags;
	ULONG user_bytes;
	ULONG domain_bytes;
	/* WCHAR user[], domain[] follow. */
} OPENSSH_LSA_AUTH_PROBE_REQUEST;

static void
init_lsa_string(LSA_STRING *s, const char *value)
{
	memset(s, 0, sizeof(*s));
	if (value == NULL)
		return;
	s->Buffer = (PCHAR)value;
	s->Length = (USHORT)strlen(value);
	s->MaximumLength = s->Length + 1;
}

static wchar_t *
utf8_to_utf16(const char *s)
{
	wchar_t *ret;
	int len;

	len = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
	if (len <= 0)
		return NULL;
	ret = (wchar_t *)calloc((size_t)len, sizeof(wchar_t));
	if (ret == NULL)
		return NULL;
	if (MultiByteToWideChar(CP_UTF8, 0, s, -1, ret, len) == 0) {
		free(ret);
		return NULL;
	}
	return ret;
}

static int
enable_privilege(const char *name)
{
	HANDLE token = NULL;
	TOKEN_PRIVILEGES tp;
	LUID luid;
	int ret = -1;

	if (!OpenProcessToken(GetCurrentProcess(),
	    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
		goto done;
	if (!LookupPrivilegeValueA(NULL, name, &luid))
		goto done;

	memset(&tp, 0, sizeof(tp));
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL))
		goto done;
	ret = 0;

done:
	if (token != NULL)
		CloseHandle(token);
	return ret;
}

static int
print_token_user(HANDLE token)
{
	TOKEN_USER *tu = NULL;
	DWORD needed = 0, name_len, domain_len;
	WCHAR name[256], domain[256];
	SID_NAME_USE use;
	int ret = -1;

	GetTokenInformation(token, TokenUser, NULL, 0, &needed);
	if (needed == 0)
		goto done;
	tu = (TOKEN_USER *)calloc(1, needed);
	if (tu == NULL)
		goto done;
	if (!GetTokenInformation(token, TokenUser, tu, needed, &needed))
		goto done;
	name_len = sizeof(name) / sizeof(name[0]);
	domain_len = sizeof(domain) / sizeof(domain[0]);
	if (!LookupAccountSidW(NULL, tu->User.Sid, name, &name_len, domain,
	    &domain_len, &use))
		goto done;
	wprintf(L"token user: %ls\\%ls\n", domain, name);
	ret = 0;

done:
	free(tu);
	return ret;
}

static int
spawn_as_token(HANDLE token, const char *cmd)
{
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	HANDLE primary = NULL;
	wchar_t *cmd_w = NULL;
	DWORD exit_code = 0;
	int ret = -1;

	if (!DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL,
	    SecurityImpersonation, TokenPrimary, &primary)) {
		printf("DuplicateTokenEx failed: %lu\n", GetLastError());
		goto done;
	}
	if ((cmd_w = utf8_to_utf16(cmd)) == NULL)
		goto done;

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

	if (!CreateProcessAsUserW(primary, NULL, cmd_w, NULL, NULL, TRUE,
	    0, NULL, NULL, &si, &pi)) {
		printf("CreateProcessAsUserW failed: %lu\n", GetLastError());
		goto done;
	}
	WaitForSingleObject(pi.hProcess, INFINITE);
	if (!GetExitCodeProcess(pi.hProcess, &exit_code))
		goto done;
	printf("child exit code: %lu\n", exit_code);
	ret = exit_code == 0 ? 0 : -1;

done:
	if (pi.hThread != NULL)
		CloseHandle(pi.hThread);
	if (pi.hProcess != NULL)
		CloseHandle(pi.hProcess);
	if (primary != NULL)
		CloseHandle(primary);
	free(cmd_w);
	return ret;
}

static void
usage(const char *prog)
{
	fprintf(stderr,
	    "usage: %s --user USER [--domain DOMAIN] [--package NAME]"
	    " [--cmd COMMAND]\n", prog);
}

int
main(int argc, char **argv)
{
	const char *user = NULL, *domain = ".", *package = NULL, *cmd = NULL;
	wchar_t *user_w = NULL, *domain_w = NULL;
	OPENSSH_LSA_AUTH_PROBE_REQUEST *request = NULL;
	size_t request_len, off, user_bytes, domain_bytes;
	LSA_STRING process_name, package_name, origin_name;
	LSA_HANDLE lsa = NULL;
	LSA_OPERATIONAL_MODE mode;
	ULONG auth_package = 0, profile_len = 0;
	TOKEN_SOURCE source;
	PVOID profile = NULL;
	HANDLE token = NULL;
	LUID logon_id;
	QUOTA_LIMITS quotas;
	NTSTATUS status, substatus = 0;
	int i, ret = 1;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--user") == 0 && i + 1 < argc)
			user = argv[++i];
		else if (strcmp(argv[i], "--domain") == 0 && i + 1 < argc)
			domain = argv[++i];
		else if (strcmp(argv[i], "--package") == 0 && i + 1 < argc)
			package = argv[++i];
		else if (strcmp(argv[i], "--cmd") == 0 && i + 1 < argc)
			cmd = argv[++i];
		else {
			usage(argv[0]);
			return 2;
		}
	}
	if (user == NULL) {
		usage(argv[0]);
		return 2;
	}
	if (package == NULL)
		package = OPENSSH_LSA_AUTH_PROBE_PACKAGE;

	user_w = utf8_to_utf16(user);
	domain_w = utf8_to_utf16(domain);
	if (user_w == NULL || domain_w == NULL)
		goto done;
	user_bytes = (wcslen(user_w) + 1) * sizeof(wchar_t);
	domain_bytes = (wcslen(domain_w) + 1) * sizeof(wchar_t);
	request_len = sizeof(*request) + user_bytes + domain_bytes;
	request = (OPENSSH_LSA_AUTH_PROBE_REQUEST *)calloc(1, request_len);
	if (request == NULL)
		goto done;
	request->magic = OPENSSH_LSA_AUTH_PROBE_MAGIC;
	request->version = OPENSSH_LSA_AUTH_PROBE_VERSION;
	request->user_bytes = (ULONG)user_bytes;
	request->domain_bytes = (ULONG)domain_bytes;
	off = sizeof(*request);
	memcpy((PBYTE)request + off, user_w, user_bytes);
	off += user_bytes;
	memcpy((PBYTE)request + off, domain_w, domain_bytes);

	enable_privilege("SeTcbPrivilege");
	init_lsa_string(&process_name, "openssh-lsa-auth-probe");
	status = LsaRegisterLogonProcess(&process_name, &lsa, &mode);
	if (status != STATUS_SUCCESS) {
		printf("LsaRegisterLogonProcess failed: 0x%08lx win32=%lu\n",
		    (unsigned long)status, LsaNtStatusToWinError(status));
		goto done;
	}
	init_lsa_string(&package_name, package);
	status = LsaLookupAuthenticationPackage(lsa, &package_name,
	    &auth_package);
	if (status != STATUS_SUCCESS) {
		printf("LsaLookupAuthenticationPackage(%s) failed: "
		    "0x%08lx win32=%lu\n", package, (unsigned long)status,
		    LsaNtStatusToWinError(status));
		goto done;
	}

	memset(&source, 0, sizeof(source));
	memcpy(source.SourceName, "sshlap", 6);
	if (!AllocateLocallyUniqueId(&source.SourceIdentifier)) {
		printf("AllocateLocallyUniqueId failed: %lu\n", GetLastError());
		goto done;
	}
	init_lsa_string(&origin_name, "openssh-lsa-auth-probe");
	status = LsaLogonUser(lsa, &origin_name, Network, auth_package,
	    request, (ULONG)request_len, NULL, &source, &profile, &profile_len,
	    &logon_id, &token, &quotas, &substatus);
	printf("LsaLogonUser package=%s status=0x%08lx substatus=0x%08lx "
	    "win32=%lu token=%p\n", package, (unsigned long)status,
	    (unsigned long)substatus, LsaNtStatusToWinError(status), token);
	if (status != STATUS_SUCCESS)
		goto done;

	print_token_user(token);
	if (cmd != NULL && spawn_as_token(token, cmd) != 0)
		goto done;
	ret = 0;

done:
	if (token != NULL)
		CloseHandle(token);
	if (profile != NULL)
		LsaFreeReturnBuffer(profile);
	if (lsa != NULL)
		LsaDeregisterLogonProcess(lsa);
	free(request);
	free(user_w);
	free(domain_w);
	return ret;
}
