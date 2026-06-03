/*
 * Diagnostic client for win32-lsa-auth-package-probe.dll.
 *
 * Build from the parent build directory:
 *   i686-w64-mingw32-gcc -Wall -Wextra -O0 -g \
 *       -o win32-lsa-auth-probe.exe \
 *       ../openssh-portable/regress/misc/win32-lsa-auth-probe.c \
 *       -ladvapi32 -lsecur32 -luserenv
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
#include <sddl.h>
#include <userenv.h>
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

typedef struct _SPAWN_OPTIONS {
	const char *cmd;
	const char *cwd;
	const char *stdio_file;
	DWORD flags;
	int use_stdio;
	int use_environment;
} SPAWN_OPTIONS;

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

static void
print_sid_details(const char *prefix, PSID sid, DWORD attrs)
{
	LPWSTR sid_string = NULL;
	WCHAR name[256], domain[256];
	DWORD name_len, domain_len;
	SID_NAME_USE use;

	name_len = sizeof(name) / sizeof(name[0]);
	domain_len = sizeof(domain) / sizeof(domain[0]);
	printf("%s", prefix);
	if (ConvertSidToStringSidW(sid, &sid_string)) {
		wprintf(L"%ls", sid_string);
		LocalFree(sid_string);
	}
	if (LookupAccountSidW(NULL, sid, name, &name_len, domain,
	    &domain_len, &use))
		wprintf(L" %ls\\%ls", domain, name);
	if (attrs != 0)
		printf(" attrs=0x%08lx", (unsigned long)attrs);
	printf("\n");
}

static void
print_token_details(HANDLE token)
{
	TOKEN_TYPE token_type;
	TOKEN_STATISTICS stats;
	TOKEN_GROUPS *groups = NULL;
	TOKEN_PRIVILEGES *privs = NULL;
	TOKEN_DEFAULT_DACL *dacl = NULL;
	DWORD needed = 0, i;

	if (GetTokenInformation(token, TokenType, &token_type,
	    sizeof(token_type), &needed))
		printf("token type: %s\n",
		    token_type == TokenPrimary ? "primary" : "impersonation");
	if (GetTokenInformation(token, TokenStatistics, &stats, sizeof(stats),
	    &needed)) {
		printf("token auth id: %lu:%ld token id: %lu:%ld "
		    "modified id: %lu:%ld\n",
		    stats.AuthenticationId.LowPart,
		    stats.AuthenticationId.HighPart, stats.TokenId.LowPart,
		    stats.TokenId.HighPart, stats.ModifiedId.LowPart,
		    stats.ModifiedId.HighPart);
	}

	GetTokenInformation(token, TokenDefaultDacl, NULL, 0, &needed);
	if (needed != 0 && (dacl = (TOKEN_DEFAULT_DACL *)calloc(1, needed)) !=
	    NULL && GetTokenInformation(token, TokenDefaultDacl, dacl, needed,
	    &needed))
		printf("token default dacl: %s\n",
		    dacl->DefaultDacl == NULL ? "NULL" : "present");
	free(dacl);

	GetTokenInformation(token, TokenGroups, NULL, 0, &needed);
	if (needed != 0 &&
	    (groups = (TOKEN_GROUPS *)calloc(1, needed)) != NULL &&
	    GetTokenInformation(token, TokenGroups, groups, needed, &needed)) {
		printf("token groups: %lu\n", (unsigned long)groups->GroupCount);
		for (i = 0; i < groups->GroupCount; i++)
			print_sid_details("  group: ", groups->Groups[i].Sid,
			    groups->Groups[i].Attributes);
	}
	free(groups);

	GetTokenInformation(token, TokenPrivileges, NULL, 0, &needed);
	if (needed != 0 &&
	    (privs = (TOKEN_PRIVILEGES *)calloc(1, needed)) != NULL &&
	    GetTokenInformation(token, TokenPrivileges, privs, needed,
	    &needed)) {
		printf("token privileges: %lu\n",
		    (unsigned long)privs->PrivilegeCount);
		for (i = 0; i < privs->PrivilegeCount; i++) {
			WCHAR name[128];
			DWORD len = sizeof(name) / sizeof(name[0]);

			if (LookupPrivilegeNameW(NULL, &privs->Privileges[i].Luid,
			    name, &len))
				wprintf(L"  privilege: %ls attrs=0x%08lx\n",
				    name, privs->Privileges[i].Attributes);
		}
	}
	free(privs);
}

static void
print_token_type(const char *prefix, HANDLE token)
{
	TOKEN_TYPE token_type;
	DWORD needed = 0;

	if (GetTokenInformation(token, TokenType, &token_type,
	    sizeof(token_type), &needed))
		printf("%s token type: %s\n", prefix,
		    token_type == TokenPrimary ? "primary" : "impersonation");
}

static int
spawn_as_token(HANDLE token, const SPAWN_OPTIONS *options)
{
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	HANDLE primary = NULL;
	HANDLE child_stdin = INVALID_HANDLE_VALUE;
	HANDLE child_stdout = INVALID_HANDLE_VALUE;
	wchar_t *cmd_w = NULL;
	wchar_t *cwd_w = NULL;
	wchar_t *stdio_file_w = NULL;
	LPVOID environment = NULL;
	DWORD exit_code = 0;
	int ret = -1;

	if (!DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL,
	    SecurityImpersonation, TokenPrimary, &primary)) {
		printf("DuplicateTokenEx failed: %lu\n", GetLastError());
		goto done;
	}
	print_token_type("primary duplicate", primary);
	if ((cmd_w = utf8_to_utf16(options->cmd)) == NULL)
		goto done;
	if (options->cwd != NULL && (cwd_w = utf8_to_utf16(options->cwd)) ==
	    NULL)
		goto done;
	if (options->stdio_file != NULL &&
	    (stdio_file_w = utf8_to_utf16(options->stdio_file)) == NULL)
		goto done;

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	si.cb = sizeof(si);
	if (stdio_file_w != NULL) {
		SECURITY_ATTRIBUTES sa;

		memset(&sa, 0, sizeof(sa));
		sa.nLength = sizeof(sa);
		sa.bInheritHandle = TRUE;
		child_stdin = CreateFileW(L"NUL", GENERIC_READ,
		    FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING,
		    FILE_ATTRIBUTE_NORMAL, NULL);
		child_stdout = CreateFileW(stdio_file_w, GENERIC_WRITE,
		    FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, CREATE_ALWAYS,
		    FILE_ATTRIBUTE_NORMAL, NULL);
		if (child_stdin == INVALID_HANDLE_VALUE ||
		    child_stdout == INVALID_HANDLE_VALUE) {
			printf("opening child stdio failed: %lu\n",
			    GetLastError());
			goto done;
		}
		si.dwFlags = STARTF_USESTDHANDLES;
		si.hStdInput = child_stdin;
		si.hStdOutput = child_stdout;
		si.hStdError = child_stdout;
	} else if (options->use_stdio) {
		si.dwFlags = STARTF_USESTDHANDLES;
		si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
		si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
		si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
	}
	if (options->use_environment &&
	    !CreateEnvironmentBlock(&environment, primary, TRUE)) {
		printf("CreateEnvironmentBlock failed: %lu\n", GetLastError());
		goto done;
	}

	if (!CreateProcessAsUserW(primary, NULL, cmd_w, NULL, NULL,
	    (options->use_stdio || stdio_file_w != NULL) ? TRUE : FALSE,
	    options->flags |
	    (environment != NULL ? CREATE_UNICODE_ENVIRONMENT : 0),
	    environment, cwd_w, &si, &pi)) {
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
	if (child_stdin != INVALID_HANDLE_VALUE)
		CloseHandle(child_stdin);
	if (child_stdout != INVALID_HANDLE_VALUE)
		CloseHandle(child_stdout);
	if (environment != NULL)
		DestroyEnvironmentBlock(environment);
	if (primary != NULL)
		CloseHandle(primary);
	free(stdio_file_w);
	free(cwd_w);
	free(cmd_w);
	return ret;
}

static void
usage(const char *prog)
{
	fprintf(stderr,
	    "usage: %s --user USER [--domain DOMAIN] [--package NAME]"
	    " [--logon-type network|batch|interactive] [--cmd COMMAND]"
	    " [--cwd DIR] [--create-flags none|no-window|detached]"
	    " [--no-stdio] [--stdio-file FILE] [--env]\n", prog);
}

static int
parse_logon_type(const char *s, SECURITY_LOGON_TYPE *out)
{
	if (strcmp(s, "network") == 0)
		*out = Network;
	else if (strcmp(s, "batch") == 0)
		*out = Batch;
	else if (strcmp(s, "interactive") == 0)
		*out = Interactive;
	else
		return -1;
	return 0;
}

static int
parse_create_flags(const char *s, DWORD *out)
{
	if (strcmp(s, "none") == 0)
		*out = 0;
	else if (strcmp(s, "no-window") == 0)
		*out = CREATE_NO_WINDOW;
	else if (strcmp(s, "detached") == 0)
		*out = DETACHED_PROCESS;
	else
		return -1;
	return 0;
}

int
main(int argc, char **argv)
{
	const char *user = NULL, *domain = ".", *package = NULL;
	SECURITY_LOGON_TYPE logon_type = Network;
	SPAWN_OPTIONS spawn_options;
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

	memset(&spawn_options, 0, sizeof(spawn_options));
	spawn_options.use_stdio = 1;
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--user") == 0 && i + 1 < argc)
			user = argv[++i];
		else if (strcmp(argv[i], "--domain") == 0 && i + 1 < argc)
			domain = argv[++i];
		else if (strcmp(argv[i], "--package") == 0 && i + 1 < argc)
			package = argv[++i];
		else if (strcmp(argv[i], "--cmd") == 0 && i + 1 < argc)
			spawn_options.cmd = argv[++i];
		else if (strcmp(argv[i], "--cwd") == 0 && i + 1 < argc)
			spawn_options.cwd = argv[++i];
		else if (strcmp(argv[i], "--stdio-file") == 0 &&
		    i + 1 < argc)
			spawn_options.stdio_file = argv[++i];
		else if (strcmp(argv[i], "--logon-type") == 0 && i + 1 < argc) {
			if (parse_logon_type(argv[++i], &logon_type) != 0) {
				usage(argv[0]);
				return 2;
			}
		} else if (strcmp(argv[i], "--create-flags") == 0 &&
		    i + 1 < argc) {
			if (parse_create_flags(argv[++i],
			    &spawn_options.flags) != 0) {
				usage(argv[0]);
				return 2;
			}
		} else if (strcmp(argv[i], "--no-stdio") == 0)
			spawn_options.use_stdio = 0;
		else if (strcmp(argv[i], "--env") == 0)
			spawn_options.use_environment = 1;
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
	status = LsaLogonUser(lsa, &origin_name, logon_type, auth_package,
	    request, (ULONG)request_len, NULL, &source, &profile, &profile_len,
	    &logon_id, &token, &quotas, &substatus);
	printf("LsaLogonUser package=%s status=0x%08lx substatus=0x%08lx "
	    "win32=%lu token=%p\n", package, (unsigned long)status,
	    (unsigned long)substatus, LsaNtStatusToWinError(status), token);
	if (status != STATUS_SUCCESS)
		goto done;

	print_token_user(token);
	print_token_details(token);
	if (spawn_options.cmd != NULL && spawn_as_token(token,
	    &spawn_options) != 0)
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
