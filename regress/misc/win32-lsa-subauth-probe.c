/*
 * Diagnostic client for the Windows XP MSV1_0 subauthentication package.
 *
 * Build from the parent build directory:
 *   i686-w64-mingw32-gcc -Wall -Wextra -O0 -g \
 *       -o win32-lsa-subauth-probe.exe \
 *       ../openssh-portable/regress/misc/win32-lsa-subauth-probe.c \
 *       -ladvapi32 -lsecur32
 *
 * Example on XP after installing win32-lsa-subauth-package.dll as Auth255:
 *   win32-lsa-subauth-probe.exe --user xpuser --domain . --subauth-id 255 \
 *       --cmd "cmd /c echo TOKEN_OK && echo %USERNAME%"
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

#define OPENSSH_XP_SUBAUTH_MAGIC "openssh-xp-subauth-probe-v1"

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
	if (needed == 0) {
		printf("GetTokenInformation(TokenUser) size failed: %lu\n",
		    GetLastError());
		goto done;
	}
	tu = (TOKEN_USER *)calloc(1, needed);
	if (tu == NULL)
		goto done;
	if (!GetTokenInformation(token, TokenUser, tu, needed, &needed)) {
		printf("GetTokenInformation(TokenUser) failed: %lu\n",
		    GetLastError());
		goto done;
	}

	name_len = sizeof(name) / sizeof(name[0]);
	domain_len = sizeof(domain) / sizeof(domain[0]);
	if (!LookupAccountSidW(NULL, tu->User.Sid, name, &name_len, domain,
	    &domain_len, &use)) {
		printf("LookupAccountSidW(TokenUser) failed: %lu\n",
		    GetLastError());
		goto done;
	}
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
	DWORD wait_result, exit_code = 0;
	int ret = -1;

	if (!DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL,
	    SecurityImpersonation, TokenPrimary, &primary)) {
		printf("DuplicateTokenEx failed: %lu\n", GetLastError());
		goto done;
	}
	cmd_w = utf8_to_utf16(cmd);
	if (cmd_w == NULL) {
		printf("utf8_to_utf16 command failed: %lu\n", GetLastError());
		goto done;
	}

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

	wait_result = WaitForSingleObject(pi.hProcess, INFINITE);
	if (wait_result != WAIT_OBJECT_0) {
		printf("WaitForSingleObject failed: %lu\n", GetLastError());
		goto done;
	}
	if (!GetExitCodeProcess(pi.hProcess, &exit_code)) {
		printf("GetExitCodeProcess failed: %lu\n", GetLastError());
		goto done;
	}
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
	    "usage: %s --user USER [--domain DOMAIN] [--subauth-id N]"
	    " [--cmd COMMAND]\n", prog);
}

int
main(int argc, char **argv)
{
	const char *user = NULL, *domain = ".", *cmd = NULL;
	ULONG subauth_id = 255;
	wchar_t *user_w = NULL, *domain_w = NULL, workstation_w[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD workstation_len = MAX_COMPUTERNAME_LENGTH + 1;
	MSV1_0_SUBAUTH_LOGON *logon = NULL;
	size_t logon_size, off;
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
		else if (strcmp(argv[i], "--subauth-id") == 0 && i + 1 < argc)
			subauth_id = strtoul(argv[++i], NULL, 0);
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

	user_w = utf8_to_utf16(user);
	domain_w = utf8_to_utf16(domain);
	if (user_w == NULL || domain_w == NULL) {
		printf("utf8_to_utf16 failed: %lu\n", GetLastError());
		goto done;
	}
	if (!GetComputerNameW(workstation_w, &workstation_len))
		wcscpy(workstation_w, L".");

	logon_size = sizeof(*logon) +
	    (wcslen(user_w) + 1) * sizeof(wchar_t) +
	    (wcslen(domain_w) + 1) * sizeof(wchar_t) +
	    (wcslen(workstation_w) + 1) * sizeof(wchar_t) +
	    sizeof(OPENSSH_XP_SUBAUTH_MAGIC);
	logon = (MSV1_0_SUBAUTH_LOGON *)calloc(1, logon_size);
	if (logon == NULL)
		goto done;

	logon->MessageType = MsV1_0SubAuthLogon;
	off = sizeof(*logon);
	logon->UserName.Buffer = (PWSTR)((PBYTE)logon + off);
	logon->UserName.Length = (USHORT)(wcslen(user_w) * sizeof(wchar_t));
	logon->UserName.MaximumLength = logon->UserName.Length + sizeof(wchar_t);
	memcpy(logon->UserName.Buffer, user_w, logon->UserName.Length);
	off += (size_t)logon->UserName.MaximumLength;

	logon->LogonDomainName.Buffer = (PWSTR)((PBYTE)logon + off);
	logon->LogonDomainName.Length = (USHORT)(wcslen(domain_w) * sizeof(wchar_t));
	logon->LogonDomainName.MaximumLength = logon->LogonDomainName.Length + sizeof(wchar_t);
	memcpy(logon->LogonDomainName.Buffer, domain_w, logon->LogonDomainName.Length);
	off += (size_t)logon->LogonDomainName.MaximumLength;

	logon->Workstation.Buffer = (PWSTR)((PBYTE)logon + off);
	logon->Workstation.Length = (USHORT)(wcslen(workstation_w) * sizeof(wchar_t));
	logon->Workstation.MaximumLength = logon->Workstation.Length + sizeof(wchar_t);
	memcpy(logon->Workstation.Buffer, workstation_w, logon->Workstation.Length);
	off += (size_t)logon->Workstation.MaximumLength;

	logon->AuthenticationInfo1.Buffer = (PCHAR)((PBYTE)logon + off);
	logon->AuthenticationInfo1.Length = sizeof(OPENSSH_XP_SUBAUTH_MAGIC) - 1;
	logon->AuthenticationInfo1.MaximumLength = logon->AuthenticationInfo1.Length;
	memcpy(logon->AuthenticationInfo1.Buffer, OPENSSH_XP_SUBAUTH_MAGIC,
	    logon->AuthenticationInfo1.Length);
	logon->AuthenticationInfo2 = logon->AuthenticationInfo1;
	logon->ParameterControl = 0;
	logon->SubAuthPackageId = subauth_id;

	enable_privilege("SeTcbPrivilege");
	init_lsa_string(&process_name, "openssh-subauth-probe");
	status = LsaRegisterLogonProcess(&process_name, &lsa, &mode);
	if (status != STATUS_SUCCESS) {
		printf("LsaRegisterLogonProcess failed: 0x%08lx win32=%lu\n",
		    (unsigned long)status, LsaNtStatusToWinError(status));
		goto done;
	}
	init_lsa_string(&package_name, MSV1_0_PACKAGE_NAME);
	status = LsaLookupAuthenticationPackage(lsa, &package_name,
	    &auth_package);
	if (status != STATUS_SUCCESS) {
		printf("LsaLookupAuthenticationPackage failed: 0x%08lx win32=%lu\n",
		    (unsigned long)status, LsaNtStatusToWinError(status));
		goto done;
	}

	memset(&source, 0, sizeof(source));
	memcpy(source.SourceName, "sshsub", 6);
	if (!AllocateLocallyUniqueId(&source.SourceIdentifier)) {
		printf("AllocateLocallyUniqueId failed: %lu\n", GetLastError());
		goto done;
	}
	init_lsa_string(&origin_name, "openssh-subauth-probe");

	status = LsaLogonUser(lsa, &origin_name, Network, auth_package,
	    logon, (ULONG)logon_size, NULL, &source, &profile, &profile_len,
	    &logon_id, &token, &quotas, &substatus);
	printf("LsaLogonUser status=0x%08lx substatus=0x%08lx win32=%lu token=%p\n",
	    (unsigned long)status, (unsigned long)substatus,
	    LsaNtStatusToWinError(status), token);
	if (status != STATUS_SUCCESS)
		goto done;

	print_token_user(token);

	if (cmd != NULL) {
		if (spawn_as_token(token, cmd) != 0)
			goto done;
	}
	ret = 0;

done:
	if (token != NULL)
		CloseHandle(token);
	if (profile != NULL)
		LsaFreeReturnBuffer(profile);
	if (lsa != NULL)
		LsaDeregisterLogonProcess(lsa);
	free(logon);
	free(user_w);
	free(domain_w);
	return ret;
}
