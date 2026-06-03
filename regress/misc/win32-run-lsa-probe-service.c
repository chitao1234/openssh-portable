/*
 * One-shot service wrapper for running LSA probes as LocalSystem on XP.
 *
 * Build from the parent build directory:
 *   i686-w64-mingw32-gcc -Wall -Wextra -O0 -g \
 *       -o win32-run-lsa-probe-service.exe \
 *       ../openssh-portable/regress/misc/win32-run-lsa-probe-service.c
 *
 * Usage as a temporary service:
 *   sc create openssh-lsa-probe binPath= C:\chi\win32-run-lsa-probe-service.exe
 *   sc start openssh-lsa-probe subauth
 *   sc start openssh-lsa-probe authpkg
 *   sc start openssh-lsa-probe authpkg-cmd
 *   sc start openssh-lsa-probe authpkg-cmd-batch
 *   sc start openssh-lsa-probe authpkg-cmd-detached
 *   sc start openssh-lsa-probe authpkg-cmd-stdio-file
 *   sc start openssh-lsa-probe authpkg-cmd-stdio-env
 *   sc start openssh-lsa-probe authpkg-call
 *   sc start openssh-lsa-probe authpkg-call-untrusted
 *   sc start openssh-lsa-probe openssh-lsa-auth
 *   sc start openssh-lsa-probe openssh-lsa-auth-untrusted
 */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

static SERVICE_STATUS_HANDLE service_handle;
static SERVICE_STATUS service_status;

static void
trace_line(const char *msg)
{
	HANDLE h;
	DWORD written;

	h = CreateFileA("C:\\chi\\lsa-probe-service.log", GENERIC_WRITE,
	    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS,
	    FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return;
	SetFilePointer(h, 0, NULL, FILE_END);
	WriteFile(h, msg, (DWORD)strlen(msg), &written, NULL);
	WriteFile(h, "\r\n", 2, &written, NULL);
	CloseHandle(h);
}

static void
set_state(DWORD state, DWORD exit_code)
{
	service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	service_status.dwCurrentState = state;
	service_status.dwControlsAccepted = 0;
	service_status.dwWin32ExitCode = exit_code;
	service_status.dwServiceSpecificExitCode = 0;
	service_status.dwCheckPoint = 0;
	service_status.dwWaitHint = 0;
	if (service_handle != NULL)
		SetServiceStatus(service_handle, &service_status);
}

static void WINAPI
control_handler(DWORD control)
{
	if (control == SERVICE_CONTROL_INTERROGATE)
		set_state(service_status.dwCurrentState,
		    service_status.dwWin32ExitCode);
}

static DWORD
run_child(const char *mode)
{
	const char *cmd;
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	SECURITY_ATTRIBUTES sa;
	HANDLE out = INVALID_HANDLE_VALUE;
	DWORD exit_code = 1;

	if (mode != NULL && strcmp(mode, "authpkg-cmd-batch") == 0)
		cmd = "C:\\chi\\win32-lsa-auth-probe.exe --user xpuser "
		    "--domain . --logon-type batch --env --cwd C:\\chi "
		    "--create-flags no-window --cmd \"cmd /c echo TOKEN_OK && "
		    "set USERNAME\"";
	else if (mode != NULL && strcmp(mode, "openssh-lsa-auth") == 0)
		cmd = "C:\\chi\\win32-lsa-auth-probe.exe --openssh-lsa-auth "
		    "--user xpuser --domain . --cwd C:\\chi "
		    "--create-flags no-window --stdio-file "
		    "C:\\chi\\lsa-token-child.out --cmd "
		    "\"cmd /c echo TOKEN_OK && set USERNAME\"";
	else if (mode != NULL && strcmp(mode, "openssh-lsa-auth-untrusted") == 0)
		cmd = "C:\\chi\\win32-lsa-auth-probe.exe --openssh-lsa-auth "
		    "--user xpuser --domain . --untrusted";
	else if (mode != NULL && strcmp(mode, "authpkg-call") == 0)
		cmd = "C:\\chi\\win32-lsa-auth-probe.exe --user xpuser "
		    "--domain . --call-package";
	else if (mode != NULL && strcmp(mode, "authpkg-call-untrusted") == 0)
		cmd = "C:\\chi\\win32-lsa-auth-probe.exe --user xpuser "
		    "--domain . --call-package --untrusted";
	else if (mode != NULL && strcmp(mode, "authpkg-cmd-stdio-file") == 0)
		cmd = "C:\\chi\\win32-lsa-auth-probe.exe --user xpuser "
		    "--domain . --cwd C:\\chi --create-flags no-window "
		    "--stdio-file C:\\chi\\lsa-token-child.out "
		    "--cmd \"cmd /c echo TOKEN_OK && set USERNAME\"";
	else if (mode != NULL && strcmp(mode, "authpkg-cmd-stdio-env") == 0)
		cmd = "C:\\chi\\win32-lsa-auth-probe.exe --user xpuser "
		    "--domain . --cwd C:\\chi --env --create-flags no-window "
		    "--stdio-file C:\\chi\\lsa-token-child.out "
		    "--cmd \"cmd /c echo TOKEN_OK && set USERNAME\"";
	else if (mode != NULL && strcmp(mode, "authpkg-cmd-interactive") == 0)
		cmd = "C:\\chi\\win32-lsa-auth-probe.exe --user xpuser "
		    "--domain . --logon-type interactive --env --cwd C:\\chi "
		    "--create-flags no-window --cmd \"cmd /c echo TOKEN_OK && "
		    "set USERNAME\"";
	else if (mode != NULL && strcmp(mode, "authpkg-cmd-detached") == 0)
		cmd = "C:\\chi\\win32-lsa-auth-probe.exe --user xpuser "
		    "--domain . --cwd C:\\chi --create-flags detached "
		    "--no-stdio --cmd \"cmd /c echo TOKEN_OK > "
		    "C:\\chi\\lsa-token-child.out\"";
	else if (mode != NULL && strcmp(mode, "authpkg-cmd-no-stdio") == 0)
		cmd = "C:\\chi\\win32-lsa-auth-probe.exe --user xpuser "
		    "--domain . --cwd C:\\chi --create-flags no-window "
		    "--no-stdio --cmd \"cmd /c echo TOKEN_OK > "
		    "C:\\chi\\lsa-token-child.out\"";
	else if (mode != NULL && strcmp(mode, "authpkg-cmd") == 0)
		cmd = "C:\\chi\\win32-lsa-auth-probe.exe --user xpuser "
		    "--domain . --cmd \"cmd /c echo TOKEN_OK && set USERNAME\"";
	else if (mode != NULL && strcmp(mode, "authpkg") == 0)
		cmd = "C:\\chi\\win32-lsa-auth-probe.exe --user xpuser --domain .";
	else
		cmd = "C:\\chi\\win32-lsa-subauth-probe.exe --user xpuser --domain . --subauth-id 255";
	trace_line(cmd);

	memset(&sa, 0, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;
	out = CreateFileA("C:\\chi\\lsa-probe.out", GENERIC_WRITE,
	    FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, CREATE_ALWAYS,
	    FILE_ATTRIBUTE_NORMAL, NULL);
	if (out == INVALID_HANDLE_VALUE)
		return GetLastError();

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	si.hStdOutput = out;
	si.hStdError = out;

	if (!CreateProcessA(NULL, (LPSTR)cmd, NULL, NULL, TRUE, 0, NULL,
	    "C:\\chi", &si, &pi)) {
		exit_code = GetLastError();
		goto done;
	}
	WaitForSingleObject(pi.hProcess, INFINITE);
	if (!GetExitCodeProcess(pi.hProcess, &exit_code))
		exit_code = GetLastError();
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

done:
	CloseHandle(out);
	return exit_code;
}

static void WINAPI
service_main(DWORD argc, LPTSTR *argv)
{
	DWORD exit_code;
	const char *mode = argc > 1 ? argv[1] : "subauth";

	trace_line("service_main entry");
	service_handle = RegisterServiceCtrlHandlerA("openssh-lsa-probe",
	    control_handler);
	if (service_handle == NULL)
		return;
	set_state(SERVICE_RUNNING, NO_ERROR);
	trace_line("service running");
	exit_code = run_child(mode);
	trace_line("child returned");
	set_state(SERVICE_STOPPED, exit_code == 0 ? NO_ERROR : exit_code);
}

int
main(int argc, char **argv)
{
	SERVICE_TABLE_ENTRYA table[] = {
		{ "openssh-lsa-probe", service_main },
		{ NULL, NULL }
	};

	trace_line("main entry");
	if (StartServiceCtrlDispatcherA(table))
		return 0;
	if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
		return (int)run_child(argc > 1 ? argv[1] : "subauth");
	return (int)GetLastError();
}
