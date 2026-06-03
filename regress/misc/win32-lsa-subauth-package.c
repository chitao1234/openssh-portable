/*
 * Diagnostic MSV1_0 subauthentication package for the Windows XP
 * public-key-token bring-up path.
 *
 * Build from the parent build directory:
 *   i686-w64-mingw32-gcc -Wall -Wextra -O0 -g -shared \
 *       -o win32-lsa-subauth-package.dll \
 *       ../openssh-portable/regress/misc/win32-lsa-subauth-package.c \
 *       ../openssh-portable/regress/misc/win32-lsa-subauth-package.def
 *
 * This is intentionally permissive and must not be used as an sshd
 * authentication implementation. Its only purpose is to prove that XP can
 * route MsV1_0SubAuthLogon through an installed DLL and return a usable token.
 * Do not leave it registered on any machine outside this probe. Remove it with:
 *   reg delete HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 /v Auth255 /f
 *   del C:\WINDOWS\system32\win32-lsa-subauth-package.dll
 */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ntsecapi.h>
#include <subauth.h>
#include <stdio.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_WRONG_PASSWORD
#define STATUS_WRONG_PASSWORD ((NTSTATUS)0xC000006AL)
#endif

#ifndef STATUS_ACCOUNT_RESTRICTION
#define STATUS_ACCOUNT_RESTRICTION ((NTSTATUS)0xC000006EL)
#endif

static void
trace_line(const char *msg, ULONG value)
{
	HANDLE h;
	char buf[256];
	DWORD len, written;

	h = CreateFileA("C:\\chi\\win32-lsa-subauth-package.log",
	    FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
	    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return;
	len = (DWORD)snprintf(buf, sizeof(buf), "%s: %lu\r\n", msg, value);
	if (len > sizeof(buf))
		len = sizeof(buf);
	WriteFile(h, buf, len, &written, NULL);
	CloseHandle(h);
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
Msv1_0SubAuthenticationRoutine(NETLOGON_LOGON_INFO_CLASS logon_level,
    PVOID logon_information, ULONG flags, PUSER_ALL_INFORMATION user_all,
    PULONG which_fields, PULONG user_flags, PBOOLEAN authoritative,
    PLARGE_INTEGER logoff_time, PLARGE_INTEGER kickoff_time)
{
	(void)flags;
	(void)which_fields;
	(void)user_all;

	trace_line("entry logon_level", (ULONG)logon_level);
	trace_line("entry logon_information", (ULONG)(ULONG_PTR)logon_information);

	if (authoritative != NULL)
		*authoritative = TRUE;
	if (user_flags != NULL)
		*user_flags = 0;

	if (logoff_time != NULL)
		logoff_time->QuadPart = 0x7fffffffffffffffLL;
	if (kickoff_time != NULL)
		kickoff_time->QuadPart = 0x7fffffffffffffffLL;

	if ((logon_level != NetlogonInteractiveInformation &&
	    logon_level != NetlogonNetworkInformation &&
	    logon_level != NetlogonServiceInformation) ||
	    logon_information == NULL) {
		trace_line("reject unsupported logon_level", (ULONG)logon_level);
		return STATUS_ACCOUNT_RESTRICTION;
	}

	trace_line("accept", 0);
	return STATUS_SUCCESS;
}
