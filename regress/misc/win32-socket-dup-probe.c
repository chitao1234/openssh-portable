/*
 * Diagnostic probe for the Windows sshd-session socket handoff path.
 *
 * Build with:
 *   i686-w64-mingw32-gcc -Wall -Wextra -O0 -g -o win32-socket-dup-probe.exe \
 *       win32-socket-dup-probe.c -lws2_32
 *
 * The parent accepts a loopback TCP connection, duplicates the accepted socket
 * using the same WSADuplicateSocket/WSASocket shape used by win32compat
 * posix_spawn, passes it as the child's standard input handle, and waits for
 * the child to send a banner using APC-style WSASend.  Child modes exercise the
 * raw inherited handle plus the two same-process dup strategies that matter for
 * sshd-session's dup(STDIN_FILENO) path.
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#include <winsock2.h>
#include <mswsock.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WSA_FLAG_OVERLAPPED
#define WSA_FLAG_OVERLAPPED 0x01
#endif

enum dup_mode {
	MODE_RAW,
	MODE_DUPHANDLE,
	MODE_WSADUP,
	MODE_WSADUP_OVERLAPPED
};

enum accept_mode {
	ACCEPT_NORMAL,
	ACCEPT_EX
};

enum send_mode {
	SEND_APC_NULL,
	SEND_APC_COUNT,
	SEND_EVENT,
	SEND_SYNC
};

static const char *
dup_mode_name(enum dup_mode mode)
{
	switch (mode) {
	case MODE_RAW:
		return "raw";
	case MODE_DUPHANDLE:
		return "duphandle";
	case MODE_WSADUP:
		return "wsadup";
	case MODE_WSADUP_OVERLAPPED:
		return "wsadup-overlapped";
	}
	return "unknown";
}

static int
parse_dup_mode(const char *s, enum dup_mode *mode)
{
	if (strcmp(s, "raw") == 0)
		*mode = MODE_RAW;
	else if (strcmp(s, "duphandle") == 0)
		*mode = MODE_DUPHANDLE;
	else if (strcmp(s, "wsadup") == 0)
		*mode = MODE_WSADUP;
	else if (strcmp(s, "wsadup-overlapped") == 0)
		*mode = MODE_WSADUP_OVERLAPPED;
	else
		return -1;
	return 0;
}

static const char *
accept_mode_name(enum accept_mode mode)
{
	return mode == ACCEPT_EX ? "acceptex" : "accept";
}

static int
parse_accept_mode(const char *s, enum accept_mode *mode)
{
	if (strcmp(s, "accept") == 0)
		*mode = ACCEPT_NORMAL;
	else if (strcmp(s, "acceptex") == 0)
		*mode = ACCEPT_EX;
	else
		return -1;
	return 0;
}

static const char *
send_mode_name(enum send_mode mode)
{
	switch (mode) {
	case SEND_APC_NULL:
		return "apc-null";
	case SEND_APC_COUNT:
		return "apc-count";
	case SEND_EVENT:
		return "event";
	case SEND_SYNC:
		return "sync";
	}
	return "unknown";
}

static int
parse_send_mode(const char *s, enum send_mode *mode)
{
	if (strcmp(s, "apc-null") == 0)
		*mode = SEND_APC_NULL;
	else if (strcmp(s, "apc-count") == 0)
		*mode = SEND_APC_COUNT;
	else if (strcmp(s, "event") == 0)
		*mode = SEND_EVENT;
	else if (strcmp(s, "sync") == 0)
		*mode = SEND_SYNC;
	else
		return -1;
	return 0;
}

static int
start_winsock(void)
{
	WSADATA wsadata;

	if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0) {
		fprintf(stderr, "WSAStartup failed: %d\n", WSAGetLastError());
		return -1;
	}
	return 0;
}

static void
describe_socket(const char *label, SOCKET s)
{
	int so_type = 0, so_len = sizeof(so_type);
	struct sockaddr_storage ss;
	int ss_len = sizeof(ss);

	fprintf(stderr, "%s: socket=%p\n", label, (void *)(UINT_PTR)s);
	if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char *)&so_type, &so_len) ==
	    SOCKET_ERROR) {
		fprintf(stderr, "%s: getsockopt(SO_TYPE) failed: %d\n",
		    label, WSAGetLastError());
	} else {
		fprintf(stderr, "%s: SO_TYPE=%d\n", label, so_type);
	}
	ss_len = sizeof(ss);
	if (getsockname(s, (struct sockaddr *)&ss, &ss_len) == SOCKET_ERROR) {
		fprintf(stderr, "%s: getsockname failed: %d\n", label,
		    WSAGetLastError());
	}
	ss_len = sizeof(ss);
	if (getpeername(s, (struct sockaddr *)&ss, &ss_len) == SOCKET_ERROR) {
		fprintf(stderr, "%s: getpeername failed: %d\n", label,
		    WSAGetLastError());
	}
}

static SOCKET
dup_socket_wsadup(SOCKET s, DWORD flags)
{
	WSAPROTOCOL_INFOW info;
	SOCKET dup_sock;

	memset(&info, 0, sizeof(info));
	if (WSADuplicateSocketW(s, GetCurrentProcessId(), &info) != 0) {
		fprintf(stderr, "WSADuplicateSocketW failed: %d\n",
		    WSAGetLastError());
		return INVALID_SOCKET;
	}
	dup_sock = WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO,
	    FROM_PROTOCOL_INFO, &info, 0, flags);
	if (dup_sock == INVALID_SOCKET) {
		fprintf(stderr, "WSASocketW(FROM_PROTOCOL_INFO, flags=0x%lx) "
		    "failed: %d\n", (unsigned long)flags, WSAGetLastError());
	}
	return dup_sock;
}

static SOCKET
dup_socket_handle(SOCKET s, BOOL inherit)
{
	HANDLE h = NULL;

	if (!DuplicateHandle(GetCurrentProcess(), (HANDLE)(UINT_PTR)s,
	    GetCurrentProcess(), &h, 0, inherit, DUPLICATE_SAME_ACCESS)) {
		fprintf(stderr, "DuplicateHandle(socket) failed: %lu\n",
		    GetLastError());
		return INVALID_SOCKET;
	}
	return (SOCKET)(UINT_PTR)h;
}

static SOCKET
dup_socket_by_mode(SOCKET s, enum dup_mode mode, BOOL inherit)
{
	SOCKET dup_sock = INVALID_SOCKET;

	switch (mode) {
	case MODE_RAW:
		dup_sock = s;
		if (inherit &&
		    !SetHandleInformation((HANDLE)(UINT_PTR)dup_sock,
		    HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
			fprintf(stderr, "SetHandleInformation(raw) failed: %lu\n",
			    GetLastError());
			return INVALID_SOCKET;
		}
		break;
	case MODE_DUPHANDLE:
		dup_sock = dup_socket_handle(s, inherit);
		break;
	case MODE_WSADUP:
		dup_sock = dup_socket_wsadup(s, 0);
		break;
	case MODE_WSADUP_OVERLAPPED:
		dup_sock = dup_socket_wsadup(s, WSA_FLAG_OVERLAPPED);
		break;
	}

	if (dup_sock != INVALID_SOCKET && mode != MODE_RAW && inherit &&
	    !SetHandleInformation((HANDLE)(UINT_PTR)dup_sock,
	    HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
		fprintf(stderr, "SetHandleInformation(dup) failed: %lu\n",
		    GetLastError());
		closesocket(dup_sock);
		return INVALID_SOCKET;
	}
	return dup_sock;
}

static int
make_listener(unsigned short port, SOCKET *listen_sock)
{
	SOCKET s;
	struct sockaddr_in addr;
	int on = 1;

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		fprintf(stderr, "socket(listener) failed: %d\n", WSAGetLastError());
		return -1;
	}
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(port);
	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
		fprintf(stderr, "bind(%u) failed: %d\n", port, WSAGetLastError());
		closesocket(s);
		return -1;
	}
	if (listen(s, 1) == SOCKET_ERROR) {
		fprintf(stderr, "listen failed: %d\n", WSAGetLastError());
		closesocket(s);
		return -1;
	}
	*listen_sock = s;
	return 0;
}

static SOCKET
connect_loopback(unsigned short port)
{
	SOCKET s;
	struct sockaddr_in addr;

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		fprintf(stderr, "socket(client) failed: %d\n", WSAGetLastError());
		return INVALID_SOCKET;
	}
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(port);
	if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
		fprintf(stderr, "connect(%u) failed: %d\n", port, WSAGetLastError());
		closesocket(s);
		return INVALID_SOCKET;
	}
	return s;
}

static SOCKET
accept_normal(SOCKET listen_sock)
{
	SOCKET s;

	s = accept(listen_sock, NULL, NULL);
	if (s == INVALID_SOCKET)
		fprintf(stderr, "accept failed: %d\n", WSAGetLastError());
	return s;
}

static SOCKET
accept_ex(SOCKET listen_sock)
{
	GUID guid_acceptex = WSAID_ACCEPTEX;
	LPFN_ACCEPTEX acceptex_fn = NULL;
	DWORD bytes = 0, received = 0, flags = 0;
	char addr_buf[(sizeof(struct sockaddr_storage) + 16) * 2];
	OVERLAPPED ov;
	SOCKET accept_sock = INVALID_SOCKET;
	HANDLE event_handle = NULL;
	BOOL ok;

	if (WSAIoctl(listen_sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
	    &guid_acceptex, sizeof(guid_acceptex), &acceptex_fn,
	    sizeof(acceptex_fn), &bytes, NULL, NULL) == SOCKET_ERROR) {
		fprintf(stderr, "WSAIoctl(AcceptEx) failed: %d\n",
		    WSAGetLastError());
		return INVALID_SOCKET;
	}

	accept_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (accept_sock == INVALID_SOCKET) {
		fprintf(stderr, "socket(acceptEx target) failed: %d\n",
		    WSAGetLastError());
		return INVALID_SOCKET;
	}

	event_handle = CreateEventA(NULL, TRUE, FALSE, NULL);
	if (event_handle == NULL) {
		fprintf(stderr, "CreateEvent failed: %lu\n", GetLastError());
		closesocket(accept_sock);
		return INVALID_SOCKET;
	}

	memset(&ov, 0, sizeof(ov));
	ov.hEvent = event_handle;
	memset(addr_buf, 0, sizeof(addr_buf));
	ok = acceptex_fn(listen_sock, accept_sock, addr_buf, 0,
	    sizeof(struct sockaddr_storage) + 16,
	    sizeof(struct sockaddr_storage) + 16, &received, &ov);
	if (!ok && WSAGetLastError() != ERROR_IO_PENDING) {
		fprintf(stderr, "AcceptEx failed: %d\n", WSAGetLastError());
		closesocket(accept_sock);
		CloseHandle(event_handle);
		return INVALID_SOCKET;
	}
	if (!WSAGetOverlappedResult(listen_sock, &ov, &bytes, TRUE, &flags)) {
		fprintf(stderr, "WSAGetOverlappedResult(AcceptEx) failed: %d\n",
		    WSAGetLastError());
		closesocket(accept_sock);
		CloseHandle(event_handle);
		return INVALID_SOCKET;
	}
	if (setsockopt(accept_sock, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
	    (const char *)&listen_sock, sizeof(listen_sock)) == SOCKET_ERROR) {
		fprintf(stderr, "SO_UPDATE_ACCEPT_CONTEXT failed: %d\n",
		    WSAGetLastError());
		closesocket(accept_sock);
		CloseHandle(event_handle);
		return INVALID_SOCKET;
	}

	CloseHandle(event_handle);
	return accept_sock;
}

static void
wait_for_debugger(DWORD wait_ms)
{
	DWORD waited = 0;

	if (wait_ms == 0)
		return;
	fprintf(stderr, "child: pid %lu waiting up to %lu ms for debugger\n",
	    GetCurrentProcessId(), (unsigned long)wait_ms);
	while (waited < wait_ms) {
		if (IsDebuggerPresent()) {
			fprintf(stderr, "child: debugger attached, continuing\n");
			return;
		}
		Sleep(100);
		waited += 100;
	}
	fprintf(stderr, "child: debugger wait timed out, continuing\n");
}

static int
spawn_child(const char *child_mode, const char *send_mode, DWORD wait_ms,
    SOCKET child_stdin, PROCESS_INFORMATION *pi)
{
	char exe[MAX_PATH];
	char cmdline[MAX_PATH + 128];
	STARTUPINFOA si;

	if (GetModuleFileNameA(NULL, exe, sizeof(exe)) == 0) {
		fprintf(stderr, "GetModuleFileNameA failed: %lu\n", GetLastError());
		return -1;
	}
	if (wait_ms != 0) {
		snprintf(cmdline, sizeof(cmdline), "\"%s\" --child %s "
		    "--send-mode %s --wait-ms %lu", exe, child_mode, send_mode,
		    (unsigned long)wait_ms);
	} else {
		snprintf(cmdline, sizeof(cmdline), "\"%s\" --child %s "
		    "--send-mode %s", exe, child_mode, send_mode);
	}
	memset(&si, 0, sizeof(si));
	memset(pi, 0, sizeof(*pi));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = (HANDLE)(UINT_PTR)child_stdin;
	si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

	fprintf(stderr, "parent: spawning %s\n", cmdline);
	if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, 0, NULL, NULL,
	    &si, pi)) {
		fprintf(stderr, "CreateProcessA failed: %lu\n", GetLastError());
		return -1;
	}
	return 0;
}

static volatile LONG send_done;
static volatile LONG send_error;
static volatile LONG send_bytes;

static void CALLBACK
send_completion(DWORD error, DWORD bytes, LPWSAOVERLAPPED overlapped,
    DWORD flags)
{
	(void)overlapped;
	(void)flags;
	send_error = (LONG)error;
	send_bytes = (LONG)bytes;
	InterlockedExchange(&send_done, 1);
}

static int
send_with_apc_wsasend(SOCKET s, const char *payload, int count_arg)
{
	OVERLAPPED ov;
	WSABUF buf;
	DWORD immediate_bytes = 0;
	LPDWORD immediate_bytes_ptr;
	int ret, i;

	memset(&ov, 0, sizeof(ov));
	send_done = 0;
	send_error = 0;
	send_bytes = 0;
	buf.buf = (char *)payload;
	buf.len = (ULONG)strlen(payload);
	immediate_bytes_ptr = count_arg ? &immediate_bytes : NULL;

	fprintf(stderr, "child: calling APC WSASend socket=%p len=%lu "
	    "count_arg=%s\n", (void *)(UINT_PTR)s, (unsigned long)buf.len,
	    count_arg ? "ptr" : "null");
	ret = WSASend(s, &buf, 1, immediate_bytes_ptr, 0, &ov,
	    send_completion);
	if (ret == SOCKET_ERROR) {
		int err = WSAGetLastError();
		fprintf(stderr, "child: WSASend returned SOCKET_ERROR: %d\n", err);
		if (err != WSA_IO_PENDING)
			return -1;
	} else {
		fprintf(stderr, "child: WSASend returned 0 immediate_bytes=%lu\n",
		    (unsigned long)immediate_bytes);
	}

	for (i = 0; i < 50 && !send_done; i++)
		SleepEx(100, TRUE);
	if (!send_done) {
		fprintf(stderr, "child: WSASend completion timed out\n");
		return -1;
	}
	fprintf(stderr, "child: WSASend completion error=%ld bytes=%ld\n",
	    send_error, send_bytes);
	return send_error == 0 && send_bytes == (LONG)buf.len ? 0 : -1;
}

static int
send_with_event_wsasend(SOCKET s, const char *payload)
{
	OVERLAPPED ov;
	WSABUF buf;
	DWORD transferred = 0, flags = 0;
	HANDLE event_handle;
	int ret;

	memset(&ov, 0, sizeof(ov));
	event_handle = CreateEventA(NULL, TRUE, FALSE, NULL);
	if (event_handle == NULL) {
		fprintf(stderr, "child: CreateEvent failed: %lu\n", GetLastError());
		return -1;
	}
	ov.hEvent = event_handle;
	buf.buf = (char *)payload;
	buf.len = (ULONG)strlen(payload);

	fprintf(stderr, "child: calling event WSASend socket=%p len=%lu\n",
	    (void *)(UINT_PTR)s, (unsigned long)buf.len);
	ret = WSASend(s, &buf, 1, NULL, 0, &ov, NULL);
	if (ret == SOCKET_ERROR) {
		int err = WSAGetLastError();
		fprintf(stderr, "child: WSASend returned SOCKET_ERROR: %d\n", err);
		if (err != WSA_IO_PENDING) {
			CloseHandle(event_handle);
			return -1;
		}
	} else {
		fprintf(stderr, "child: WSASend returned 0\n");
	}
	if (!WSAGetOverlappedResult(s, &ov, &transferred, TRUE, &flags)) {
		fprintf(stderr, "child: WSAGetOverlappedResult failed: %d\n",
		    WSAGetLastError());
		CloseHandle(event_handle);
		return -1;
	}
	fprintf(stderr, "child: event WSASend transferred=%lu flags=0x%lx\n",
	    (unsigned long)transferred, (unsigned long)flags);
	CloseHandle(event_handle);
	return transferred == buf.len ? 0 : -1;
}

static int
send_with_sync_wsasend(SOCKET s, const char *payload)
{
	WSABUF buf;
	DWORD transferred = 0;

	buf.buf = (char *)payload;
	buf.len = (ULONG)strlen(payload);
	fprintf(stderr, "child: calling sync WSASend socket=%p len=%lu\n",
	    (void *)(UINT_PTR)s, (unsigned long)buf.len);
	if (WSASend(s, &buf, 1, &transferred, 0, NULL, NULL) == SOCKET_ERROR) {
		fprintf(stderr, "child: sync WSASend failed: %d\n",
		    WSAGetLastError());
		return -1;
	}
	fprintf(stderr, "child: sync WSASend transferred=%lu\n",
	    (unsigned long)transferred);
	return transferred == buf.len ? 0 : -1;
}

static int
send_payload(SOCKET s, const char *payload, enum send_mode send_mode)
{
	switch (send_mode) {
	case SEND_APC_NULL:
		return send_with_apc_wsasend(s, payload, 0);
	case SEND_APC_COUNT:
		return send_with_apc_wsasend(s, payload, 1);
	case SEND_EVENT:
		return send_with_event_wsasend(s, payload);
	case SEND_SYNC:
		return send_with_sync_wsasend(s, payload);
	}
	return -1;
}

static int
child_main(enum dup_mode mode, enum send_mode send_mode, DWORD wait_ms)
{
	SOCKET inherited, target;
	char payload[128];
	int ret;

	if (start_winsock() != 0)
		return 2;
	wait_for_debugger(wait_ms);
	inherited = (SOCKET)(UINT_PTR)GetStdHandle(STD_INPUT_HANDLE);
	describe_socket("child inherited", inherited);

	target = dup_socket_by_mode(inherited, mode, FALSE);
	if (target == INVALID_SOCKET) {
		WSACleanup();
		return 3;
	}
	describe_socket("child target", target);
	snprintf(payload, sizeof(payload), "probe mode=%s send=%s\r\n",
	    dup_mode_name(mode), send_mode_name(send_mode));
	ret = send_payload(target, payload, send_mode);
	if (target != inherited)
		closesocket(target);
	WSACleanup();
	return ret == 0 ? 0 : 4;
}

static int
run_one(enum accept_mode accept_mode, enum dup_mode handoff_mode,
    enum dup_mode child_mode, enum send_mode send_mode, unsigned short port,
    DWORD child_wait_ms, int recv_timeout_ms)
{
	SOCKET listen_sock = INVALID_SOCKET;
	SOCKET client_sock = INVALID_SOCKET;
	SOCKET accepted_sock = INVALID_SOCKET;
	SOCKET child_stdin = INVALID_SOCKET;
	PROCESS_INFORMATION pi;
	char recvbuf[256];
	int n, result = 1;
	DWORD exit_code = 0;

	fprintf(stderr, "\n=== accept=%s handoff=%s child=%s send=%s port=%u ===\n",
	    accept_mode_name(accept_mode), dup_mode_name(handoff_mode),
	    dup_mode_name(child_mode), send_mode_name(send_mode), port);

	if (make_listener(port, &listen_sock) != 0)
		goto out;
	if (accept_mode == ACCEPT_EX) {
		client_sock = connect_loopback(port);
		if (client_sock == INVALID_SOCKET)
			goto out;
		accepted_sock = accept_ex(listen_sock);
	} else {
		client_sock = connect_loopback(port);
		if (client_sock == INVALID_SOCKET)
			goto out;
		accepted_sock = accept_normal(listen_sock);
	}
	if (accepted_sock == INVALID_SOCKET)
		goto out;
	setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO,
	    (const char *)&recv_timeout_ms, sizeof(recv_timeout_ms));
	describe_socket("parent accepted", accepted_sock);

	child_stdin = dup_socket_by_mode(accepted_sock, handoff_mode, TRUE);
	if (child_stdin == INVALID_SOCKET)
		goto out;
	describe_socket("parent child-stdin", child_stdin);

	if (spawn_child(dup_mode_name(child_mode), send_mode_name(send_mode),
	    child_wait_ms, child_stdin, &pi) != 0)
		goto out;
	closesocket(child_stdin);
	child_stdin = INVALID_SOCKET;
	closesocket(accepted_sock);
	accepted_sock = INVALID_SOCKET;

	n = recv(client_sock, recvbuf, sizeof(recvbuf) - 1, 0);
	if (n == SOCKET_ERROR) {
		fprintf(stderr, "parent: recv failed: %d\n", WSAGetLastError());
	} else {
		recvbuf[n] = '\0';
		fprintf(stderr, "parent: received %d bytes: %s", n, recvbuf);
	}

	WaitForSingleObject(pi.hProcess, INFINITE);
	GetExitCodeProcess(pi.hProcess, &exit_code);
	fprintf(stderr, "parent: child exit code %lu\n", exit_code);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	result = (n > 0 && exit_code == 0) ? 0 : 1;

out:
	if (child_stdin != INVALID_SOCKET)
		closesocket(child_stdin);
	if (accepted_sock != INVALID_SOCKET)
		closesocket(accepted_sock);
	if (client_sock != INVALID_SOCKET)
		closesocket(client_sock);
	if (listen_sock != INVALID_SOCKET)
		closesocket(listen_sock);
	fprintf(stderr, "=== result: %s ===\n", result == 0 ? "PASS" : "FAIL");
	return result;
}

static void
usage(const char *prog)
{
	fprintf(stderr,
	    "usage:\n"
	    "  %s [--accept accept|acceptex] [--handoff raw|duphandle|wsadup|wsadup-overlapped]\n"
	    "     [--mode raw|duphandle|wsadup|wsadup-overlapped] [--port N]\n"
	    "     [--send-mode apc-null|apc-count|event|sync]\n"
	    "     [--child-wait-ms N] [--recv-timeout-ms N]\n"
	    "  %s --child raw|duphandle|wsadup|wsadup-overlapped\n"
	    "     [--send-mode apc-null|apc-count|event|sync] [--wait-ms N]\n",
	    prog, prog);
}

int
main(int argc, char **argv)
{
	enum accept_mode accept_mode = ACCEPT_EX;
	enum dup_mode handoff_mode = MODE_WSADUP_OVERLAPPED;
	enum dup_mode child_mode = MODE_RAW;
	enum send_mode send_mode = SEND_APC_NULL;
	unsigned short port = 22331;
	DWORD child_wait_ms = 0;
	DWORD wait_ms = 0;
	int recv_timeout_ms = 60000;
	int single_mode = 0, child = 0;
	int i, failures = 0;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--child") == 0 && i + 1 < argc) {
			if (parse_dup_mode(argv[++i], &child_mode) != 0) {
				usage(argv[0]);
				return 2;
			}
			child = 1;
		} else if (strcmp(argv[i], "--accept") == 0 && i + 1 < argc) {
			if (parse_accept_mode(argv[++i], &accept_mode) != 0) {
				usage(argv[0]);
				return 2;
			}
		} else if (strcmp(argv[i], "--handoff") == 0 && i + 1 < argc) {
			if (parse_dup_mode(argv[++i], &handoff_mode) != 0) {
				usage(argv[0]);
				return 2;
			}
		} else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
			if (parse_dup_mode(argv[++i], &child_mode) != 0) {
				usage(argv[0]);
				return 2;
			}
			single_mode = 1;
		} else if (strcmp(argv[i], "--send-mode") == 0 && i + 1 < argc) {
			if (parse_send_mode(argv[++i], &send_mode) != 0) {
				usage(argv[0]);
				return 2;
			}
		} else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
			long p = strtol(argv[++i], NULL, 10);
			if (p <= 1024 || p > 65535) {
				fprintf(stderr, "port must be >1024 and <=65535\n");
				return 2;
			}
			port = (unsigned short)p;
		} else if (strcmp(argv[i], "--child-wait-ms") == 0 &&
		    i + 1 < argc) {
			child_wait_ms = (DWORD)strtoul(argv[++i], NULL, 10);
		} else if (strcmp(argv[i], "--wait-ms") == 0 && i + 1 < argc) {
			wait_ms = (DWORD)strtoul(argv[++i], NULL, 10);
		} else if (strcmp(argv[i], "--recv-timeout-ms") == 0 &&
		    i + 1 < argc) {
			long t = strtol(argv[++i], NULL, 10);
			if (t <= 0 || t > 3600000) {
				fprintf(stderr, "receive timeout must be between "
				    "1 and 3600000 ms\n");
				return 2;
			}
			recv_timeout_ms = (int)t;
		} else {
			usage(argv[0]);
			return 2;
		}
	}

	if (child)
		return child_main(child_mode, send_mode, wait_ms);

	if (start_winsock() != 0)
		return 2;
	if (single_mode) {
		failures += run_one(accept_mode, handoff_mode, child_mode,
		    send_mode, port, child_wait_ms, recv_timeout_ms);
	} else {
		failures += run_one(accept_mode, handoff_mode, MODE_RAW,
		    send_mode, port++, child_wait_ms, recv_timeout_ms);
		failures += run_one(accept_mode, handoff_mode, MODE_DUPHANDLE,
		    send_mode, port++, child_wait_ms, recv_timeout_ms);
		failures += run_one(accept_mode, handoff_mode, MODE_WSADUP,
		    send_mode, port++, child_wait_ms, recv_timeout_ms);
		failures += run_one(accept_mode, handoff_mode,
		    MODE_WSADUP_OVERLAPPED, send_mode, port++, child_wait_ms,
		    recv_timeout_ms);
	}
	WSACleanup();

	fprintf(stderr, "\nsummary: failures=%d\n", failures);
	return failures == 0 ? 0 : 1;
}
