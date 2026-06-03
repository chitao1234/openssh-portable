/*
 * Diagnostic full LSA authentication package for the Windows XP
 * public-key-token bring-up path.
 *
 * Build from the parent build directory:
 *   i686-w64-mingw32-gcc -Wall -Wextra -O0 -g -shared \
 *       -o win32-lsa-auth-package-probe.dll \
 *       ../openssh-portable/regress/misc/win32-lsa-auth-package-probe.c \
 *       ../openssh-portable/regress/misc/win32-lsa-auth-package-probe.def
 *
 * This package deliberately fails all logons. Its purpose is only to prove
 * that XP can load a custom authentication package, call LsaApLogonUser, and
 * copy a submit buffer into LSASS. Do not wire this into sshd or leave it
 * installed outside a controlled probe.
 */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#define SECURITY_WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ntsecapi.h>
#include <sspi.h>
#include <ntsecpkg.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif
#ifndef STATUS_LOGON_FAILURE
#define STATUS_LOGON_FAILURE ((NTSTATUS)0xC000006DL)
#endif
#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)
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

static PLSA_DISPATCH_TABLE lsa_dispatch;
static ULONG lsa_package_id;

static void
tracef(const char *fmt, ...)
{
	HANDLE h;
	char buf[512];
	DWORD len, written;
	va_list ap;

	h = CreateFileA("C:\\chi\\win32-lsa-auth-package-probe.log",
	    FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
	    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return;
	va_start(ap, fmt);
	len = (DWORD)vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (len >= sizeof(buf))
		len = sizeof(buf) - 1;
	buf[len++] = '\r';
	if (len < sizeof(buf))
		buf[len++] = '\n';
	WriteFile(h, buf, len, &written, NULL);
	CloseHandle(h);
}

static NTSTATUS
alloc_lsa_string(const char *s, PLSA_STRING *out)
{
	PLSA_STRING ret;
	size_t len;

	if (lsa_dispatch == NULL || lsa_dispatch->AllocateLsaHeap == NULL ||
	    s == NULL || out == NULL)
		return STATUS_INVALID_PARAMETER;
	len = strlen(s);
	if (len > USHRT_MAX)
		return STATUS_INVALID_PARAMETER;
	ret = lsa_dispatch->AllocateLsaHeap((ULONG)(sizeof(*ret) + len + 1));
	if (ret == NULL)
		return STATUS_INVALID_PARAMETER;
	memset(ret, 0, sizeof(*ret) + len + 1);
	ret->Length = (USHORT)len;
	ret->MaximumLength = (USHORT)(len + 1);
	ret->Buffer = (PCHAR)(ret + 1);
	memcpy(ret->Buffer, s, len + 1);
	*out = ret;
	return STATUS_SUCCESS;
}

BOOL WINAPI
DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
	(void)instance;
	(void)reason;
	(void)reserved;
	return TRUE;
}

NTSTATUS NTAPI
LsaApInitializePackage(ULONG authentication_package_id,
    PLSA_DISPATCH_TABLE dispatch_table, PLSA_STRING database,
    PLSA_STRING confidentiality, PLSA_STRING *authentication_package_name)
{
	(void)database;
	(void)confidentiality;

	tracef("InitializePackage id=%lu dispatch=%p",
	    authentication_package_id, dispatch_table);
	if (dispatch_table == NULL || authentication_package_name == NULL)
		return STATUS_INVALID_PARAMETER;
	lsa_dispatch = dispatch_table;
	lsa_package_id = authentication_package_id;
	return alloc_lsa_string(OPENSSH_LSA_AUTH_PROBE_PACKAGE,
	    authentication_package_name);
}

NTSTATUS NTAPI
LsaApLogonUser(PLSA_CLIENT_REQUEST client_request,
    SECURITY_LOGON_TYPE logon_type, PVOID authentication_information,
    PVOID client_authentication_base, ULONG authentication_information_length,
    PVOID *profile_buffer, PULONG profile_buffer_length, PLUID logon_id,
    PNTSTATUS sub_status, PLSA_TOKEN_INFORMATION_TYPE token_information_type,
    PVOID *token_information, PLSA_UNICODE_STRING *account_name,
    PLSA_UNICODE_STRING *authenticating_authority)
{
	OPENSSH_LSA_AUTH_PROBE_REQUEST *request = NULL;
	NTSTATUS copy_status = STATUS_NOT_IMPLEMENTED;
	ULONG request_len = authentication_information_length;

	(void)client_authentication_base;

	tracef("LogonUser package_id=%lu type=%lu auth=%p len=%lu",
	    lsa_package_id, (ULONG)logon_type, authentication_information,
	    authentication_information_length);

	if (profile_buffer != NULL)
		*profile_buffer = NULL;
	if (profile_buffer_length != NULL)
		*profile_buffer_length = 0;
	if (logon_id != NULL) {
		logon_id->LowPart = 0;
		logon_id->HighPart = 0;
	}
	if (token_information_type != NULL)
		*token_information_type = LsaTokenInformationNull;
	if (token_information != NULL)
		*token_information = NULL;
	if (account_name != NULL)
		*account_name = NULL;
	if (authenticating_authority != NULL)
		*authenticating_authority = NULL;

	if (sub_status != NULL)
		*sub_status = STATUS_LOGON_FAILURE;

	if (lsa_dispatch != NULL && lsa_dispatch->AllocateLsaHeap != NULL &&
	    lsa_dispatch->FreeLsaHeap != NULL &&
	    lsa_dispatch->CopyFromClientBuffer != NULL &&
	    authentication_information != NULL &&
	    request_len >= sizeof(*request) && request_len <= 4096) {
		request = lsa_dispatch->AllocateLsaHeap(request_len);
		if (request != NULL) {
			copy_status = lsa_dispatch->CopyFromClientBuffer(
			    client_request, request_len, request,
			    authentication_information);
			tracef("CopyFromClientBuffer status=0x%08lx",
			    (unsigned long)copy_status);
			if (copy_status == STATUS_SUCCESS) {
				tracef("request magic=0x%08lx version=%lu "
				    "user_bytes=%lu domain_bytes=%lu",
				    (unsigned long)request->magic,
				    request->version, request->user_bytes,
				    request->domain_bytes);
			}
			lsa_dispatch->FreeLsaHeap(request);
		}
	}

	tracef("LogonUser returning STATUS_LOGON_FAILURE");
	return STATUS_LOGON_FAILURE;
}

NTSTATUS NTAPI
LsaApCallPackage(PLSA_CLIENT_REQUEST client_request,
    PVOID protocol_submit_buffer, PVOID client_buffer_base,
    ULONG submit_buffer_length, PVOID *protocol_return_buffer,
    PULONG return_buffer_length, PNTSTATUS protocol_status)
{
	(void)client_request;
	(void)protocol_submit_buffer;
	(void)client_buffer_base;
	(void)submit_buffer_length;
	if (protocol_return_buffer != NULL)
		*protocol_return_buffer = NULL;
	if (return_buffer_length != NULL)
		*return_buffer_length = 0;
	if (protocol_status != NULL)
		*protocol_status = STATUS_NOT_IMPLEMENTED;
	tracef("CallPackage returning STATUS_NOT_IMPLEMENTED");
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI
LsaApCallPackageUntrusted(PLSA_CLIENT_REQUEST client_request,
    PVOID protocol_submit_buffer, PVOID client_buffer_base,
    ULONG submit_buffer_length, PVOID *protocol_return_buffer,
    PULONG return_buffer_length, PNTSTATUS protocol_status)
{
	return LsaApCallPackage(client_request, protocol_submit_buffer,
	    client_buffer_base, submit_buffer_length, protocol_return_buffer,
	    return_buffer_length, protocol_status);
}

NTSTATUS NTAPI
LsaApCallPackagePassthrough(PLSA_CLIENT_REQUEST client_request,
    PVOID protocol_submit_buffer, PVOID client_buffer_base,
    ULONG submit_buffer_length, PVOID *protocol_return_buffer,
    PULONG return_buffer_length, PNTSTATUS protocol_status)
{
	return LsaApCallPackage(client_request, protocol_submit_buffer,
	    client_buffer_base, submit_buffer_length, protocol_return_buffer,
	    return_buffer_length, protocol_status);
}

VOID NTAPI
LsaApLogonTerminated(PLUID logon_id)
{
	tracef("LogonTerminated %lu:%ld",
	    logon_id == NULL ? 0 : logon_id->LowPart,
	    logon_id == NULL ? 0 : logon_id->HighPart);
}
