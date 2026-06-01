/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* Copyright (c) 2015 Microsoft Corp.
* All rights reserved
*
* Microsoft openssh win32 port
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
*
* 1. Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in the
* documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
* IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <errno.h>
#include <stddef.h>
#include "w32fd.h"
#include "utf.h"
#include "misc_internal.h"
#include "Debug.h"

#define INTERNAL_SEND_BUFFER_SIZE 70*1024 //70KB
#define INTERNAL_RECV_BUFFER_SIZE 70*1024 //70KB
#define errno_from_WSALastError() errno_from_WSAError(WSAGetLastError())

#ifndef EAI_BADFLAGS
#define EAI_BADFLAGS EAI_FAIL
#endif
#ifndef EAI_SERVICE
#define EAI_SERVICE EAI_NONAME
#endif
#ifndef EAI_SOCKTYPE
#define EAI_SOCKTYPE EAI_FAIL
#endif

/* state info that needs to be persisted for an inprocess acceptEx call*/
struct acceptEx_context {
	char lpOutputBuf[1024];
	SOCKET accept_socket;
	LPFN_ACCEPTEX lpfnAcceptEx;
	LPFN_GETACCEPTEXSOCKADDRS lpfnGuidGetAcceptExSockaddrs;
	DWORD bytes_received;
};

/* maps WSAError to errno */
static int
errno_from_WSAError(int wsaerrno)
{
	/* TODO - create a mapping table - more efficient */
	switch (wsaerrno) {
	case WSAEWOULDBLOCK:
		return EAGAIN;
	case WSAEFAULT:
		return EFAULT;
	case WSAEINVAL:
		return EINVAL;
	case WSAECONNABORTED:
		return ECONNABORTED;
	case WSAETIMEDOUT:
		return ETIMEDOUT;
	case WSAECONNREFUSED:
		return ECONNREFUSED;
	case WSAEINPROGRESS:
		return EINPROGRESS;
	case WSAESHUTDOWN:
		return ECONNRESET;
	case WSAENOTCONN:
		return ENOTCONN;
	case WSAECONNRESET:
		return ECONNRESET;
	default:
		return wsaerrno - 10000;
	}
}

/* called before any other calls to socketio_ functions */
int
socketio_initialize()
{
	WSADATA wsaData = { 0 };
	return WSAStartup(MAKEWORD(2, 2), &wsaData);
}

/* cleanup */
int
socketio_done()
{
	WSACleanup();
	return 0;
}

/* initiate async acceptEx*/
/* TODO - always return 0, set error in context, accept() will pick it up*/
int
socketio_acceptEx(struct w32_io* pio)
{
	struct acceptEx_context *context;
	struct sockaddr_storage addr; int addrlen = sizeof addr;
	
	debug5("acceptEx - io:%p", pio);
	context = (struct acceptEx_context *)pio->internal.context;
	ResetEvent(pio->read_overlapped.hEvent);

	if (getsockname(pio->sock, (struct sockaddr*)&addr, &addrlen) == SOCKET_ERROR) {
		errno = errno_from_WSALastError();
		debug("acceptEx - getsockname() ERROR:%d, io:%p", WSAGetLastError(), pio);
		return -1;		
	}

	/* create accepting socket */
	context->accept_socket = socket(addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (context->accept_socket == INVALID_SOCKET) {
		errno = errno_from_WSALastError();
		debug3("acceptEx - socket() ERROR:%d, io:%p", WSAGetLastError(), pio);
		return -1;
	}

	if (TRUE == context->lpfnAcceptEx(pio->sock,
					context->accept_socket,
					context->lpOutputBuf,
					0,
					sizeof(SOCKADDR_STORAGE) + 16,
					sizeof(SOCKADDR_STORAGE) + 16,
					&context->bytes_received,
					&pio->read_overlapped))
	{
		/* we are already connected. Set event so subsequent select will catch */
		SetEvent(pio->read_overlapped.hEvent);
	} else {
		/* if overlapped io is in progress, we are good */
		if (WSAGetLastError() != ERROR_IO_PENDING) {
			errno = errno_from_WSALastError();
			debug3("acceptEx - AcceptEx() ERROR:%d, io:%p", WSAGetLastError(), pio);
			return -1;
		}
	}

	pio->read_details.pending = TRUE;
	return 0;
}

void
CALLBACK WSARecvCompletionRoutine(IN DWORD dwError,
				IN DWORD cbTransferred,
				IN LPWSAOVERLAPPED lpOverlapped,
				IN DWORD dwFlags)
{
	struct w32_io* pio =
		(struct w32_io*)((char*)lpOverlapped - offsetof(struct w32_io, read_overlapped));
	debug4("WSARecvCompletionCB - io:%p, pending_state:%d, flags:%d, error:%d, received:%d",
		pio, pio->read_details.pending, dwFlags, dwError, cbTransferred);
	if (!dwError && !cbTransferred)
		dwError = ERROR_GRACEFUL_DISCONNECT;
	pio->read_details.error = dwError;
	pio->read_details.remaining = cbTransferred;
	pio->read_details.completed = 0;
	pio->read_details.pending = FALSE;
}

/* initiates async receive operation*/
/* TODO - always return 0, or make this a void func. any error should be put in context*/
static int
socketio_WSARecv(struct w32_io* pio, BOOL* completed, int len)
{
	int ret = 0;
	WSABUF wsabuf;
	DWORD recv_flags = 0;

	debug5("WSARecv - pio: %p", pio);
	if (completed)
		*completed = FALSE;

	/* initialize recv buffers if needed */
	wsabuf.len = INTERNAL_RECV_BUFFER_SIZE;
	if (pio->read_details.buf == NULL) {
		wsabuf.buf = malloc(wsabuf.len);
		if (!wsabuf.buf) {
			errno = ENOMEM;
			debug3("WSARecv - ERROR:%d, io:%p", errno, pio);
			return -1;
		}

		pio->read_details.buf = wsabuf.buf;
		pio->read_details.buf_size = wsabuf.len;
	} else
		wsabuf.buf = pio->read_details.buf;

	if (len)
		wsabuf.len = min((ULONG)len, wsabuf.len);

	ret = WSARecv(pio->sock, &wsabuf, 1, NULL, &recv_flags, &pio->read_overlapped, &WSARecvCompletionRoutine);
	if (ret == 0) {
		pio->read_details.pending = TRUE;
		/* receive has completed but APC is pending to be scheduled */
		debug4("WSARecv - WSARecv() returned 0, io:%p", pio);
		if (completed)
			*completed = TRUE;
	} else { /* (ret == SOCKET_ERROR) */
		if (WSAGetLastError() == WSA_IO_PENDING) {
			/* io is initiated and pending */
			debug4("WSARecv - reported IO pending");
			pio->read_details.pending = TRUE;
		} else {
			errno = errno_from_WSALastError();
			debug3("WSARecv - WSARecv() ERROR: io:%p %d", pio, WSAGetLastError());
			return -1;
		}
	}

	return 0;
}

/* implements socket() */
struct w32_io*
socketio_socket(int domain, int type, int protocol)
{
	struct w32_io *pio = (struct w32_io*)malloc(sizeof(struct w32_io));
	if (!pio) {
		errno = ENOMEM;
		debug3("socket - ERROR:%d, io:%p", errno, pio);
		return NULL;
	}

	memset(pio, 0, sizeof(struct w32_io));
	pio->sock = socket(domain, type, protocol);
	if (pio->sock == INVALID_SOCKET) {
		errno = errno_from_WSALastError();
		debug3("socket - socket() ERROR:%d, io:%p", WSAGetLastError(), pio);
		free(pio);
		return NULL;
	}

	pio->internal.state = SOCK_INITIALIZED;
	return pio;
}

#define SET_ERRNO_ON_ERROR(expr) do {					\
    int ret = (expr);							\
    if (ret == SOCKET_ERROR) {						\
        errno = errno_from_WSALastError();				\
        debug3("%s - ERROR:%d", __FUNCTION__, WSAGetLastError());	\
    }									\
    return ret;								\
} while (0) 

/* implements setsockopt() */
int
socketio_setsockopt(struct w32_io* pio, int level, int optname, const char* optval, int optlen)
{
	if ((optname == SO_KEEPALIVE) || (optname == SO_REUSEADDR) ||
	    (optname == TCP_NODELAY) || (optname == IPV6_V6ONLY))
		SET_ERRNO_ON_ERROR(setsockopt(pio->sock, level, optname, optval, optlen));
	else {
		debug3("setsockop - ERROR: unsupported optname:%d io:%p", optname, pio);
		errno = ENOTSUP;
		return -1;
	}
}

/* implements getsockopt() */
int
socketio_getsockopt(struct w32_io* pio, int level, int optname, char* optval, int* optlen)
{
	SET_ERRNO_ON_ERROR(getsockopt(pio->sock, level, optname, optval, optlen));
}

/* implements getsockname() */
int
socketio_getsockname(struct w32_io* pio, struct sockaddr* name, int* namelen)
{
	SET_ERRNO_ON_ERROR(getsockname(pio->sock, name, namelen));
}

/* implements getpeername */
int
socketio_getpeername(struct w32_io* pio, struct sockaddr* name, int* namelen)
{
	SET_ERRNO_ON_ERROR(getpeername(pio->sock, name, namelen));
}

/* implements listen() */
int
socketio_listen(struct w32_io* pio, int backlog)
{
	struct acceptEx_context* context;

	if (SOCKET_ERROR == listen(pio->sock, backlog)) {
		errno = errno_from_WSALastError();
		debug3("listen - listen() ERROR:%d io:%p", WSAGetLastError(), pio);
		return -1;
	}

	/* prep for accept*/
	{
		GUID GuidAcceptEx = WSAID_ACCEPTEX;
		GUID GuidGetAcceptExSockaddrs = WSAID_GETACCEPTEXSOCKADDRS;
		DWORD dwBytes;

		context = (struct acceptEx_context*)malloc(sizeof(struct acceptEx_context));
		if (context == NULL) {
			errno = ENOMEM;
			debug3("listen - ERROR:%d, io:%p", errno, pio);
			return -1;
		}
		memset(context, 0, sizeof(struct acceptEx_context));
		if (SOCKET_ERROR == WSAIoctl(pio->sock,
			SIO_GET_EXTENSION_FUNCTION_POINTER,
			&GuidAcceptEx, sizeof(GuidAcceptEx),
			&context->lpfnAcceptEx, sizeof(context->lpfnAcceptEx),
			&dwBytes, NULL, NULL)) {
			free(context);
			errno = errno_from_WSALastError();
			debug3("listen - Ioctl1 ERROR:%d, io:%p", WSAGetLastError(), pio);
			return -1;
		}

		if (SOCKET_ERROR == WSAIoctl(pio->sock,
			SIO_GET_EXTENSION_FUNCTION_POINTER,
			&GuidGetAcceptExSockaddrs, sizeof(GuidGetAcceptExSockaddrs),
			&context->lpfnGuidGetAcceptExSockaddrs, sizeof(context->lpfnGuidGetAcceptExSockaddrs),
			&dwBytes, NULL, NULL)) {
			free(context);
			errno = errno_from_WSALastError();
			debug3("listen - Ioctl2 ERROR:%d, io:%p", WSAGetLastError(), pio);
			return -1;
		}

		pio->read_overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		if ((pio->read_overlapped.hEvent) == NULL) {
			free(context);
			errno = ENOMEM;
			debug3("listen - CreateEvent() ERROR:%d, io:%p", errno, pio);
			return -1;
		}

		context->accept_socket = INVALID_SOCKET;
		pio->internal.context = context;
	}

	pio->internal.state = SOCK_LISTENING;
	return 0;
}

/* implements bind() */
int
socketio_bind(struct w32_io* pio, const struct sockaddr *name, int namelen)
{
	SET_ERRNO_ON_ERROR(bind(pio->sock, name, namelen));
}

/* implements recv() */
int
socketio_recv(struct w32_io* pio, void *buf, size_t len, int flags)
{
	BOOL completed = FALSE;
	errno_t r = 0;
	debug5("recv - io:%p state:%d", pio, pio->internal.state);

	if ((buf == NULL) || (len == 0)) {
		errno = EINVAL;
		debug3("recv - ERROR: invalid arguments, buf:%p, len:%d, io:%p", buf, len, pio);
		return -1;
	}

	if (flags != 0) {
		errno = ENOTSUP;
		debug3("recv - ERROR: flags are not currently supported, io:%p", pio);
		return -1;
	}

	/* TODO - ensure socket is in accepted or connected state */
	/* /io is initiated and pending */
	if (pio->read_details.pending) {
		/* if recv is now in blocking mode, wait for data to be available */
		if (w32_io_is_blocking(pio)) {
			debug4("recv - io is pending, call is blocking, io:%p", pio);
			while (socketio_is_io_available(pio, TRUE) == FALSE) {
				if (0 != wait_for_any_event(NULL, 0, INFINITE))
					return -1;
			}
		} else {
			errno = EAGAIN;
			debug4("recv - io is already pending, io:%p", pio);
			return -1;
		}
	}	

	/* if we have some buffer copy it and return #bytes copied */
	if (pio->read_details.remaining) {
		int num_bytes_copied = min((int)len, pio->read_details.remaining);
		if ((r = memcpy_s(buf, len, pio->read_details.buf + pio->read_details.completed,
			num_bytes_copied)) != 0) {
			debug4("memcpy_s failed with error: %d.", r);
			return -1;
		}
		pio->read_details.remaining -= num_bytes_copied;
		pio->read_details.completed += num_bytes_copied;
		debug5("recv - returning %d bytes from prior completed IO, remaining:%d, io:%p",
			num_bytes_copied, pio->read_details.remaining, pio);
		return num_bytes_copied;
	}

	/* if there was an error on async call, return */
	if (pio->read_details.error) {
		if (pio->read_details.error == ERROR_GRACEFUL_DISCONNECT) {
			debug4("recv - connection closed, io:%p", pio);
			/* connection is closed */
			return 0;
		} else {
			errno = errno_from_WSAError(pio->read_details.error);
			debug3("recv - from CB ERROR:%d, io:%p", pio->read_details.error, pio);
			pio->read_details.error = 0;
			return -1;
		}
	}

	if (0 != socketio_WSARecv(pio, &completed, (int)len))
		return -1;

	if (completed) {
		/* Let APC be scheduled */
		debug4("recv - Letting APC to execute, io:%p", pio);
		SleepEx(0, TRUE);
		if (pio->read_details.pending) {
			/* this shouldn't be happening */
			errno = EOTHER;
			debug3("recv - ERROR: Unexpected IO state, io:%p", pio);
			return -1;
		}
	}

	if (w32_io_is_blocking(pio)) {
		/* wait until io is done */
		debug5("recv - socket in blocking mode, io:%p", pio);
		while (socketio_is_io_available(pio, TRUE) == FALSE) {
			if (0 != wait_for_any_event(NULL, 0, INFINITE))
				return -1;
		}
	} else {
		if (socketio_is_io_available(pio, TRUE) == FALSE) {
			errno = EAGAIN;
			debug4("recv - IO is pending, io:%p", pio);
			return -1;
		}
	}

	/*
	 * by this time we should have some bytes in internal buffer
	 * or an error from callback
	 */
	if (pio->read_details.error) {
		if (pio->read_details.error == ERROR_GRACEFUL_DISCONNECT) {
			/* connection is closed */
			debug4("recv - connection closed(2), io:%p", pio);
			return 0;
		} else {
			errno = errno_from_WSAError(pio->read_details.error);
			pio->read_details.error = 0;
			debug3("recv - from CB(2) ERROR:%d, io:%p", errno, pio);
			return -1;
		}
	}

	if (pio->read_details.remaining) {
		int num_bytes_copied = min((int)len, pio->read_details.remaining);
		if ((r = memcpy_s(buf, len, pio->read_details.buf, num_bytes_copied)) != 0) {
			debug3("memcpy_s failed with error: %d.", r);
			return -1;
		}
		pio->read_details.remaining -= num_bytes_copied;
		pio->read_details.completed = num_bytes_copied;
		debug4("recv - (2) returning %d bytes from completed IO, remaining:%d, io:%p",
			num_bytes_copied, pio->read_details.remaining, pio);
		return num_bytes_copied;
	} else {
		/* this should not happen */
		errno = EOTHER;
		debug3("recv - (2) ERROR:Unexpected IO state, io:%p", pio);
		return -1;
	}
}

void
CALLBACK WSASendCompletionRoutine(IN DWORD dwError,
				IN DWORD cbTransferred,
				IN LPWSAOVERLAPPED lpOverlapped,
				IN DWORD dwFlags)
{
	struct w32_io* pio = (struct w32_io*)((char*)lpOverlapped - offsetof(struct w32_io, write_overlapped));
	debug4("WSASendCB - io:%p, pending_state:%d, error:%d, sent:%d of remaining:%d",
		pio, pio->write_details.pending, dwError, cbTransferred,
		pio->write_details.remaining);
	pio->write_details.error = dwError;
	/* TODO - assert that remaining == cbTransferred */
	if ((dwError == 0) && (pio->write_details.remaining != cbTransferred)) {
		error("WSASendCB - ERROR: broken assumption, io:%p, sent:%d, remaining:%d", pio,
			cbTransferred, pio->write_details.remaining);
		debug_assert_internal();
	}
	pio->write_details.remaining -= cbTransferred;
	pio->write_details.pending = FALSE;
}

/* implementation of send() */
int
socketio_send(struct w32_io* pio, const void *buf, size_t len, int flags)
{
	int ret = 0;
	WSABUF wsabuf;
	errno_t r = 0;
		
	debug5("send - io:%p state:%d", pio, pio->internal.state);

	if ((buf == NULL) || (len == 0)) {
		errno = EINVAL;
		debug3("send - ERROR invalid arguments, buf:%p, len:%d, io:%p", buf, len, pio);
		return -1;
	}

	if (flags != 0) {
		errno = ENOTSUP;
		debug3("send - ERROR: flags are not currently supported, io:%p", pio);
		return -1;
	}

	/* TODO - ensure socket is in accepted or connected state */
	/* if io is already pending */
	if (pio->write_details.pending) {
		if (w32_io_is_blocking(pio)) {
			debug4("send - io is pending, call is blocking, io:%p", pio);
			while (pio->write_details.pending)
				if (wait_for_any_event(NULL, 0, INFINITE) == -1)
					return -1;
		} else {
			errno = EAGAIN;
			debug4("send - IO currently pending, EAGAIN, io:%p", pio);
			return -1;
		}
	}

	if (pio->write_details.error) {
		errno = errno_from_WSAError(pio->write_details.error);
		debug3("ERROR:%d, io:%p", pio->write_details.error, pio);
		return -1;
	}

	/* initialize buffers if needed */
	wsabuf.len = INTERNAL_SEND_BUFFER_SIZE;
	if (pio->write_details.buf == NULL) {
		wsabuf.buf = malloc(wsabuf.len);
		if (!wsabuf.buf) {
			errno = ENOMEM;
			debug3("send - ERROR:%d, io:%p", errno, pio);
			return -1;
		}

		pio->write_details.buf = wsabuf.buf;
		pio->write_details.buf_size = wsabuf.len;
	} else
		wsabuf.buf = pio->write_details.buf;

	wsabuf.len = min(wsabuf.len, (int)len);
	if ((r = memcpy_s(wsabuf.buf, wsabuf.len, buf, wsabuf.len)) != 0) {
		debug3("memcpy_s failed with error: %d.", r);
		return -1;
	}

	/* TODO - implement flags support if needed */
	ret = WSASend(pio->sock, &wsabuf, 1, NULL, 0, &pio->write_overlapped, &WSASendCompletionRoutine);

	if (ret == 0) {
		/* send has completed and APC is scheduled, let it run */
		pio->write_details.pending = TRUE;
		pio->write_details.remaining = wsabuf.len;
		SleepEx(0, TRUE);
		if ((pio->write_details.pending) || (pio->write_details.remaining != 0)) {
			errno = EOTHER;
			debug3("send - ERROR: Unexpected IO state, io:%p", pio);
			return -1;
		}

		/* return num of bytes written */
		return wsabuf.len;
	} else {
		if (WSAGetLastError() == WSA_IO_PENDING) {
			/* io is initiated and pending */
			debug4("send - WSASend reported IO pending, io:%p", pio);
			pio->write_details.pending = TRUE;
			pio->write_details.remaining = wsabuf.len;
			if (w32_io_is_blocking(pio)) {
				/* wait until io is done */
				debug5("send - waiting as socket is in blocking mode, io:%p", pio);
				while (pio->write_details.pending)
					if (wait_for_any_event(NULL, 0, INFINITE) == -1) {
						/* if interrupted but send has completed, we are good*/
						if ((errno != EINTR) || (pio->write_details.pending))
							return -1;
						errno = 0;
					}
			}

			debug5("send - returning %d, io:%p", wsabuf.len, pio);
			return wsabuf.len;
		} else {
			errno = errno_from_WSALastError();
			debug3("send - WSASend() ERROR:%d, io:%p", WSAGetLastError(), pio);
			return -1;
		}
	}
}

/* shutdown() implementation */
int
socketio_shutdown(struct w32_io* pio, int how)
{
	SET_ERRNO_ON_ERROR(shutdown(pio->sock, how));
}

/* socket close() implementation */
int
socketio_close(struct w32_io* pio)
{
	debug4("close - io:%p", pio);
	closesocket(pio->sock);
	/* wait for pending io to abort */
	SleepEx(0, TRUE);
	if ((pio->internal.state == SOCK_READY) &&
	    (pio->read_details.pending || pio->write_details.pending)) {
		error("close - IO is still pending on closed socket. read:%d, write:%d, io:%p",
			pio->read_details.pending, pio->write_details.pending, pio);
		debug_assert_internal();
	}
	if (pio->internal.state == SOCK_LISTENING) {
		if (pio->read_overlapped.hEvent)
			CloseHandle(pio->read_overlapped.hEvent);
		if (pio->internal.context) {
			struct acceptEx_context *ctx = (struct acceptEx_context*)pio->internal.context;
			if (ctx->accept_socket != INVALID_SOCKET)
				closesocket(ctx->accept_socket);
			free(pio->internal.context);
		}
	} else if (pio->internal.state == SOCK_CONNECTING) {
		if (pio->write_overlapped.hEvent)
			CloseHandle(pio->write_overlapped.hEvent);
	} else {
		if (pio->read_details.buf)
			free(pio->read_details.buf);

		if (pio->write_details.buf)
			free(pio->write_details.buf);
	}

	free(pio);
	return 0;
}

/* accept() implementation */
struct w32_io*
socketio_accept(struct w32_io* pio, struct sockaddr* addr, int* addrlen)
{
	struct w32_io *accept_io = NULL;
	int iResult = 0;
	struct acceptEx_context* context;
	struct sockaddr *local_address, *remote_address;
	int local_address_len, remote_address_len;
	errno_t r = 0;

	debug5("accept - io:%p", pio);
	/* start io if not already started */
	if (pio->read_details.pending == FALSE) {
		if (socketio_acceptEx(pio) != 0)
			return NULL;
	}

	if (w32_io_is_blocking(pio)) {
		/* block until accept io is complete */
		while (FALSE == socketio_is_io_available(pio, TRUE))
			if (-1 == wait_for_any_event(&pio->read_overlapped.hEvent,
				1, INFINITE))
				return NULL;
	} else {
		/* if i/o is not ready */
		if (FALSE == socketio_is_io_available(pio, TRUE)) {
			errno = EAGAIN;
			debug4("accept is pending, io:%p", pio);
			return NULL;
		}
	}

	context = (struct acceptEx_context*)pio->internal.context;
	pio->read_details.pending = FALSE;
	ResetEvent(pio->read_overlapped.hEvent);

	if (pio->read_details.error) {
		errno = errno_from_WSAError(pio->read_details.error);
		debug3("accept - ERROR: async io completed with error: %d, io:%p", pio->read_details.error, pio);
		pio->read_details.error = 0;
		goto on_error;
	}

	if (0 != setsockopt(context->accept_socket, SOL_SOCKET,
		SO_UPDATE_ACCEPT_CONTEXT, (char*)&pio->sock, sizeof(pio->sock))) {
		errno = errno_from_WSALastError();
		debug3("accept - ERROR: setsockopt failed:%d, io:%p", WSAGetLastError(), pio);
		goto on_error;
	}

	accept_io = (struct w32_io*)malloc(sizeof(struct w32_io));
	if (!accept_io) {
		errno = ENOMEM;
		debug3("accept - ERROR:%d, io:%p", errno, pio);
		goto on_error;
	}
	memset(accept_io, 0, sizeof(struct w32_io));

	accept_io->sock = context->accept_socket;
	accept_io->internal.state = SOCK_READY;
	context->accept_socket = INVALID_SOCKET;
	debug4("accept io:%p", accept_io);

	if ((addr != NULL) && (addrlen != NULL)) {
		context->lpfnGuidGetAcceptExSockaddrs(context->lpOutputBuf, 0,
			sizeof(SOCKADDR_STORAGE) + 16,
			sizeof(SOCKADDR_STORAGE) + 16, &local_address,
			&local_address_len, &remote_address, &remote_address_len);
		if (remote_address_len) {
			if((r = memcpy_s(addr, remote_address_len, remote_address, remote_address_len)) != 0) {
				debug3("memcpy_s failed with error: %d.", r);
				goto on_error;
			}
			*addrlen = remote_address_len;
		}
	}
	return accept_io;

on_error:
	if (context->accept_socket != INVALID_SOCKET) {
		closesocket(context->accept_socket);
		context->accept_socket = INVALID_SOCKET;
	}

	return NULL;
}

/* initiates an async connect*/
int
socketio_connectex(struct w32_io* pio, const struct sockaddr* name, int namelen)
{

	struct sockaddr_in tmp_addr4;
	struct sockaddr_in6 tmp_addr6;
	SOCKADDR* tmp_addr;
	size_t tmp_addr_len;
	DWORD tmp_bytes;
	GUID connectex_guid = WSAID_CONNECTEX;
	LPFN_CONNECTEX ConnectEx;

	debug5("connectex - io:%p", pio);
	if (name->sa_family == AF_INET6) {
		ZeroMemory(&tmp_addr6, sizeof(tmp_addr6));
		tmp_addr6.sin6_family = AF_INET6;
		tmp_addr6.sin6_port = 0;
		tmp_addr = (SOCKADDR*)&tmp_addr6;
		tmp_addr_len = sizeof(tmp_addr6);
	} else if (name->sa_family == AF_INET) {
		ZeroMemory(&tmp_addr4, sizeof(tmp_addr4));
		tmp_addr4.sin_family = AF_INET;
		tmp_addr4.sin_port = 0;
		tmp_addr = (SOCKADDR*)&tmp_addr4;
		tmp_addr_len = sizeof(tmp_addr4);
	} else {
		errno = ENOTSUP;
		debug3("connectex - ERROR: unsuppored address family:%d, io:%p", name->sa_family, pio);
		return -1;
	}

	if (SOCKET_ERROR == bind(pio->sock, tmp_addr, (int)tmp_addr_len)) {
		errno = errno_from_WSALastError();
		/* 
		 * When use bind_address or bind_interface, this bind will return WSAEINVAL. But it doesn't matter.
		 * https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-bind
		 */
		if (errno != EINVAL) {
			debug3("connectex - ERROR: bind failed :%d, io:%p", WSAGetLastError(), pio);
			return -1;
		}
	}

	if (SOCKET_ERROR == WSAIoctl(pio->sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
		&connectex_guid, sizeof(connectex_guid),
		&ConnectEx, sizeof(ConnectEx),
		&tmp_bytes, NULL, NULL)) {
		errno = errno_from_WSALastError();
		debug3("connectex - ioctl ERROR:%d, io:%p", WSAGetLastError(), pio);
		return -1;
	}

	if ((!pio->write_overlapped.hEvent)
		&& ((pio->write_overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL)) == NULL)) {
		errno = ENOMEM;
		debug3("connectex - ERROR CreateEvent failed:%d, io:%p", errno, pio);
		return -1;
	}

	ResetEvent(pio->write_overlapped.hEvent);
	if (TRUE == ConnectEx(pio->sock, name, namelen, NULL, 0, NULL,
		&pio->write_overlapped)) {
		/* set completion event to indicates that async connect has completed */
		SetEvent(pio->write_overlapped.hEvent);
	} else {
		if (WSAGetLastError() != ERROR_IO_PENDING) {
			CloseHandle(pio->write_overlapped.hEvent);
			pio->write_overlapped.hEvent = 0;
			errno = errno_from_WSALastError();
			debug3("connectex - ERROR ConnectEx() :%d, io:%p", WSAGetLastError(), pio);
			return -1;
		}
	}

	pio->write_details.pending = TRUE;
	pio->internal.state = SOCK_CONNECTING;
	return 0;
}

/* connect implementation */
int
socketio_connect(struct w32_io* pio, const struct sockaddr* name, int namelen)
{

	debug5("connect - io:%p", pio);
	if (pio->write_details.pending == FALSE) {
		if (-1 == socketio_connectex(pio, name, namelen))
			return -1;
	}

	if (w32_io_is_blocking(pio)) {
		/*  block until connect io is complete */
		while (FALSE == socketio_is_io_available(pio, TRUE)) {
			if (-1 == wait_for_any_event(&pio->write_overlapped.hEvent, 1, INFINITE))
				return -1;
		}
	} else {
		/* if i/o is not ready */
		if (FALSE == socketio_is_io_available(pio, TRUE)) {
			errno = EINPROGRESS;
			debug4("connect - in progress, io:%p", pio);
			return -1;
		}
	}

	return socketio_finish_connect(pio);
}

int
socketio_finish_connect(struct w32_io* pio)
{
	DWORD wsa_error = 0;
	debug5("finish_connect, io:%p", pio);

	if (pio->write_details.error) {
		wsa_error = pio->write_details.error;
		debug3("finish_connect - ERROR: async io completed with error: %d, io:%p", wsa_error, pio);
		goto done;
	}

	if (0 != setsockopt(pio->sock, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0)) {
		wsa_error = WSAGetLastError();
		debug3("finish_connect - ERROR: setsockopt failed:%d, io:%p", wsa_error, pio);
		goto done;
	}

done:
	CloseHandle(pio->write_overlapped.hEvent);
	pio->write_overlapped.hEvent = 0;
	pio->write_details.pending = FALSE;

	if (wsa_error) {
		pio->read_details.error = wsa_error;
		pio->write_details.error = wsa_error;
		errno = errno_from_WSAError(wsa_error);
	} else /* reset write_detail that were previously used for async connect */
		ZeroMemory(&pio->write_details, sizeof(pio->write_details));

	pio->internal.state = SOCK_READY;
	return (wsa_error? -1 : 0);
}

/* checks if a given io is ready/available */
BOOL
socketio_is_io_available(struct w32_io* pio, BOOL rd)
{
	if ((pio->internal.state == SOCK_LISTENING) ||
	    (pio->internal.state == SOCK_CONNECTING)) {
		DWORD numBytes = 0;
		DWORD flags;
		BOOL sock_listening = (pio->internal.state == SOCK_LISTENING);
		OVERLAPPED *overlapped = sock_listening ? &pio->read_overlapped : &pio->write_overlapped;
		BOOL pending = sock_listening ? pio->read_details.pending : pio->write_details.pending;

		if (pending) {
			/* if there is an error to be picked up */
			if (sock_listening) {
				if (pio->read_details.error)
					return TRUE;
			} else {
				if (pio->write_details.error)
					return TRUE;
			}
		}

		if (WSAGetOverlappedResult(pio->sock, overlapped, &numBytes, FALSE, &flags))
			return TRUE;
		else if (WSAGetLastError() != WSA_IO_INCOMPLETE) {
			if (sock_listening)
				pio->read_details.error = WSAGetLastError();
			else
				pio->write_details.error = WSAGetLastError();
			return TRUE;
		}

		return FALSE;
	} else if (rd) {
		if (pio->read_details.remaining || pio->read_details.error)
			return TRUE;
		else
			return FALSE;
	} else
		return (pio->write_details.pending == FALSE) ? TRUE : FALSE;
}

/*start async io (if needed) for accept and recv*/
void
socketio_on_select(struct w32_io* pio, BOOL rd)
{
	enum w32_io_sock_state sock_state = pio->internal.state;
	debug4("on_select - io:%p type:%d rd:%d", pio, pio->type, rd);

	/* nothing to do for writes (that includes connect) */
	if (!rd)
		return;

	/* listening socket - acceptEx if needed */
	if (sock_state == SOCK_LISTENING) {
		if (pio->read_details.pending == FALSE)
			if (socketio_acceptEx(pio) != 0) {
				/* set error, accept will pick it*/
				pio->read_details.error = errno;
				errno = 0;
				pio->read_details.pending = TRUE;
				SetEvent(pio->read_overlapped.hEvent);
				return;
			}
	} else if(sock_state == SOCK_READY) {
		/* connected socket - WSARecv if needed */
		if ((!pio->read_details.pending) && (!socketio_is_io_available(pio, rd)) && (socketio_WSARecv(pio, NULL, 0) != 0))
		{
			/* set error, recv() will pick it */
			pio->read_details.error = errno;
			errno = 0;
			return;
		}
	}
}

int
w32_gethostname(char *name_utf8, size_t len)
{
	char* tmp_name_utf8 = NULL;

	if (pIsWindows8OrGreater()) {
		/* TODO - GetHostNameW not present in Win7, do GetProcAddr on Win8+*/
	        /*
		wchar_t name_utf16[256];
		if (GetHostNameW(name_utf16, 256) == SOCKET_ERROR) {
	                errno = errno_from_WSALastError();
	                return -1;
	        }

	        if ((tmp_name_utf8 = utf16_to_utf8(name_utf16)) == NULL ||
	                strlen(tmp_name_utf8) >= len) {
	                errno = EFAULT; //??
	                return -1;
	        }

	        memcpy(name_utf8, tmp_name_utf8, strlen(tmp_name_utf8) + 1);
	        free(tmp_name_utf8);
	        return 0; */
		return gethostname(name_utf8, (int)len);
	} else
		return gethostname(name_utf8, (int)len);
}

void
w32_freeaddrinfo(struct addrinfo *ai)
{
	struct addrinfo *cur;
	while (ai) {
		cur = ai;
		ai = ai->ai_next;
		if (cur->ai_addr)
			free(cur->ai_addr);
		if (cur->ai_canonname)
			free(cur->ai_canonname);
		free(cur);
	}
}

static int
copy_sockaddr_string(char *dst, size_t dstlen, const char *src)
{
	size_t srclen;

	if (dst == NULL)
		return 0;
	srclen = strlen(src);
	if (dstlen == 0 || srclen >= dstlen)
		return EAI_MEMORY;
	memcpy(dst, src, srclen + 1);
	return 0;
}

const char *
w32_inet_ntop(int af, const void *src, char *dst, socklen_t size)
{
	struct in_addr in;
	struct sockaddr_in6 sin6;
	DWORD len;
	const char *addr;

	if (dst == NULL || size <= 0) {
		errno = ENOSPC;
		return NULL;
	}

	switch (af) {
	case AF_INET:
		memcpy(&in, src, sizeof(in));
		addr = inet_ntoa(in);
		if (addr == NULL)
			return NULL;
		if (strlen(addr) >= (size_t)size) {
			errno = ENOSPC;
			return NULL;
		}
		strcpy_s(dst, (size_t)size, addr);
		return dst;
	case AF_INET6:
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET6;
		memcpy(&sin6.sin6_addr, src, sizeof(sin6.sin6_addr));
		len = (DWORD)size;
		if (WSAAddressToStringA((LPSOCKADDR)&sin6, sizeof(sin6), NULL, dst, &len) == 0)
			return dst;
		errno = errno_from_WSAError(WSAGetLastError());
		return NULL;
	default:
		errno = EAFNOSUPPORT;
		return NULL;
	}
}

static int
w32_getnameinfo_numeric_host(const struct sockaddr *sa, size_t salen, char *host, size_t hostlen)
{
	const struct sockaddr_in *sin;
	const struct sockaddr_in6 *sin6;

	if (host == NULL)
		return 0;

	switch (sa->sa_family) {
	case AF_INET:
		if (salen < sizeof(*sin))
			return EAI_FAMILY;
		sin = (const struct sockaddr_in *)sa;
		return w32_inet_ntop(AF_INET, &sin->sin_addr, host, (socklen_t)hostlen) == NULL ? EAI_MEMORY : 0;
	case AF_INET6:
		if (salen < sizeof(*sin6))
			return EAI_FAMILY;
		sin6 = (const struct sockaddr_in6 *)sa;
		return w32_inet_ntop(AF_INET6, &sin6->sin6_addr, host, (socklen_t)hostlen) == NULL ? EAI_MEMORY : 0;
	default:
		return EAI_FAMILY;
	}
}

int
w32_getnameinfo(const struct sockaddr *sa, size_t salen, char *host, size_t hostlen,
	char *serv, size_t servlen, int flags)
{
	typedef int (WSAAPI *GetNameInfoType)(const struct sockaddr *, socklen_t,
	    char *, DWORD, char *, DWORD, int);
	static GetNameInfoType s_pGetNameInfo = NULL;
	static int s_init = 0;
	HMODULE hm;
	const struct sockaddr_in *sin;
	struct servent *se;
	char servbuf[16];
	int ret;

	if (!s_init) {
		s_init = 1;
		if ((hm = LoadLibraryW(L"ws2_32.dll")) != NULL)
			s_pGetNameInfo = (GetNameInfoType)GetProcAddress(hm, "getnameinfo");
	}
	if (s_pGetNameInfo != NULL)
		return s_pGetNameInfo(sa, (socklen_t)salen, host, (DWORD)hostlen,
		    serv, (DWORD)servlen, flags);

	if (sa == NULL)
		return EAI_FAIL;

	if (serv != NULL) {
		if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6)
			return EAI_FAMILY;
		if (salen < (sa->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)))
			return EAI_FAMILY;
		if ((flags & NI_NUMERICSERV) == 0) {
			u_short port = sa->sa_family == AF_INET ?
			    ((const struct sockaddr_in *)sa)->sin_port :
			    ((const struct sockaddr_in6 *)sa)->sin6_port;
			se = getservbyport(port, (flags & NI_DGRAM) ? "udp" : "tcp");
			if (se != NULL) {
				ret = copy_sockaddr_string(serv, servlen, se->s_name);
				if (ret != 0)
					return ret;
				goto host_lookup;
			}
		}
		snprintf(servbuf, sizeof(servbuf), "%u", sa->sa_family == AF_INET ?
		    ntohs(((const struct sockaddr_in *)sa)->sin_port) :
		    ntohs(((const struct sockaddr_in6 *)sa)->sin6_port));
		ret = copy_sockaddr_string(serv, servlen, servbuf);
		if (ret != 0)
			return ret;
	}

host_lookup:
	if (host == NULL)
		return 0;
	if ((flags & NI_NUMERICHOST) != 0)
		return w32_getnameinfo_numeric_host(sa, salen, host, hostlen);
	if (sa->sa_family == AF_INET) {
		struct hostent *hp;
		if (salen < sizeof(*sin))
			return EAI_FAMILY;
		sin = (const struct sockaddr_in *)sa;
		hp = gethostbyaddr((const char *)&sin->sin_addr, sizeof(sin->sin_addr), AF_INET);
		if (hp != NULL)
			return copy_sockaddr_string(host, hostlen, hp->h_name);
		if ((flags & NI_NAMEREQD) != 0)
			return EAI_NONAME;
	}
	return w32_getnameinfo_numeric_host(sa, salen, host, hostlen);
}

typedef INT (WSAAPI *GetAddrInfoWType)(PCWSTR, PCWSTR, const ADDRINFOW *,
    PADDRINFOW *);
typedef VOID (WSAAPI *FreeAddrInfoWType)(PADDRINFOW);

static int
w32_load_getaddrinfoW(GetAddrInfoWType *getaddrinfoW,
    FreeAddrInfoWType *freeaddrinfoW)
{
	static GetAddrInfoWType s_pGetAddrInfoW = NULL;
	static FreeAddrInfoWType s_pFreeAddrInfoW = NULL;
	static int s_init = 0;
	HMODULE hm;

	if (!s_init) {
		s_init = 1;
		if ((hm = LoadLibraryW(L"ws2_32.dll")) != NULL) {
			s_pGetAddrInfoW = (GetAddrInfoWType)GetProcAddress(hm,
			    "GetAddrInfoW");
			s_pFreeAddrInfoW = (FreeAddrInfoWType)GetProcAddress(hm,
			    "FreeAddrInfoW");
		}
	}

	*getaddrinfoW = s_pGetAddrInfoW;
	*freeaddrinfoW = s_pFreeAddrInfoW;
	return s_pGetAddrInfoW != NULL && s_pFreeAddrInfoW != NULL;
}

static int
w32_copy_addrinfoW(struct addrinfoW *info_w, struct addrinfo **res)
{
	struct addrinfoW **cur_w = &info_w;
	struct addrinfo **cur = res;
	struct addrinfo *dst;
	int ret = 0;

	while (*cur_w) {
		if ((*cur = calloc(1, sizeof(struct addrinfo))) == NULL)
			return EAI_MEMORY;
		dst = *cur;
		dst->ai_flags = (*cur_w)->ai_flags;
		dst->ai_family = (*cur_w)->ai_family;
		dst->ai_socktype = (*cur_w)->ai_socktype;
		dst->ai_protocol = (*cur_w)->ai_protocol;
		dst->ai_addrlen = (*cur_w)->ai_addrlen;
		if ((*cur_w)->ai_canonname != NULL &&
		    (dst->ai_canonname =
		    utf16_to_utf8((*cur_w)->ai_canonname)) == NULL)
			return EAI_MEMORY;
		if ((*cur_w)->ai_addrlen &&
		    (dst->ai_addr = malloc((*cur_w)->ai_addrlen)) == NULL)
			return EAI_MEMORY;
		if ((*cur_w)->ai_addrlen &&
		    memcpy_s(dst->ai_addr, (*cur_w)->ai_addrlen,
		    (*cur_w)->ai_addr, (*cur_w)->ai_addrlen))
			return EAI_MEMORY;
		cur_w = &(*cur_w)->ai_next;
		cur = &dst->ai_next;
	}

	return ret;
}

static int
w32_getaddrinfo_modern(const char *node_utf8, const char *service_utf8,
    const struct addrinfo *hints, struct addrinfo **res,
    GetAddrInfoWType getaddrinfoW, FreeAddrInfoWType freeaddrinfoW)
{
	int ret = 0;
	wchar_t *node_utf16 = NULL, *service_utf16 = NULL;
	struct addrinfoW *info_w = NULL;

	if ((node_utf8 && (node_utf16 = utf8_to_utf16(node_utf8)) == NULL) ||
	    (service_utf8 && (service_utf16 = utf8_to_utf16(service_utf8)) == NULL)) {
		ret = EAI_MEMORY;
		goto done;
	}

	if ((ret = getaddrinfoW(node_utf16, service_utf16, (ADDRINFOW*)hints,
	    &info_w)) != 0)
		goto done;

	ret = w32_copy_addrinfoW(info_w, res);

done:
	if (node_utf16)
		free(node_utf16);
	if (service_utf16)
		free(service_utf16);
	if (info_w)
		freeaddrinfoW(info_w);
	if (ret != 0 && *res) {
		w32_freeaddrinfo(*res);
		*res = NULL;
	}
	return ret;
}

static int
w32_addrinfo_flags_supported(int flags)
{
	int supported_flags = AI_PASSIVE | AI_CANONNAME | AI_NUMERICHOST;

#ifdef AI_NUMERICSERV
	supported_flags |= AI_NUMERICSERV;
#endif
#ifdef AI_ADDRCONFIG
	supported_flags |= AI_ADDRCONFIG;
#endif

	return (flags & ~supported_flags) == 0;
}

static int
w32_addrinfo_socktype_protocol(const struct addrinfo *hints, int *socktype,
    int *protocol)
{
	*socktype = hints != NULL ? hints->ai_socktype : 0;
	*protocol = hints != NULL ? hints->ai_protocol : 0;

	if (*socktype == 0) {
		if (*protocol == IPPROTO_UDP)
			*socktype = SOCK_DGRAM;
		else
			*socktype = SOCK_STREAM;
	}
	if (*socktype != SOCK_STREAM && *socktype != SOCK_DGRAM)
		return EAI_SOCKTYPE;
	if (*protocol == 0)
		*protocol = *socktype == SOCK_DGRAM ? IPPROTO_UDP : IPPROTO_TCP;
	if ((*socktype == SOCK_STREAM && *protocol != IPPROTO_TCP) ||
	    (*socktype == SOCK_DGRAM && *protocol != IPPROTO_UDP))
		return EAI_SERVICE;
	return 0;
}

static int
w32_addrinfo_parse_service(const char *service, int flags, int socktype,
    int protocol, u_short *port)
{
	struct servent *se;
	const char *proto = NULL;
	char *end;
	unsigned long n;

	*port = 0;
	if (service == NULL)
		return 0;

	errno = 0;
	n = strtoul(service, &end, 10);
	if (service[0] != '\0' && *end == '\0' && errno != ERANGE &&
	    n <= 65535) {
		*port = htons((u_short)n);
		return 0;
	}
#ifdef AI_NUMERICSERV
	if ((flags & AI_NUMERICSERV) != 0)
		return EAI_NONAME;
#endif

	if (socktype == SOCK_DGRAM || protocol == IPPROTO_UDP)
		proto = "udp";
	else if (socktype == SOCK_STREAM || protocol == IPPROTO_TCP)
		proto = "tcp";
	if ((se = getservbyname(service, proto)) == NULL)
		return EAI_SERVICE;
	*port = se->s_port;
	return 0;
}

static struct addrinfo *
w32_addrinfo_alloc_ipv4(u_long addr, u_short port, int flags, int socktype,
    int protocol, const char *canonname)
{
	struct addrinfo *ai;
	struct sockaddr_in *sin;

	if ((ai = calloc(1, sizeof(*ai))) == NULL)
		return NULL;
	if ((sin = calloc(1, sizeof(*sin))) == NULL) {
		free(ai);
		return NULL;
	}

	sin->sin_family = AF_INET;
	sin->sin_port = port;
	sin->sin_addr.s_addr = addr;
	ai->ai_flags = flags;
	ai->ai_family = AF_INET;
	ai->ai_socktype = socktype;
	ai->ai_protocol = protocol;
	ai->ai_addrlen = sizeof(*sin);
	ai->ai_addr = (struct sockaddr *)sin;
	if (canonname != NULL && (ai->ai_canonname = _strdup(canonname)) == NULL) {
		w32_freeaddrinfo(ai);
		return NULL;
	}
	return ai;
}

static int
w32_getaddrinfo_legacy(const char *node, const char *service,
    const struct addrinfo *hints, struct addrinfo **res)
{
	struct hostent *hp;
	struct in_addr in;
	struct addrinfo *cur, *prev;
	u_short port;
	u_long addr;
	int flags, family, socktype, protocol, ret, i, numeric_host;

	flags = hints != NULL ? hints->ai_flags : 0;
	family = hints != NULL ? hints->ai_family : AF_UNSPEC;
	if (family != AF_UNSPEC && family != AF_INET)
		return EAI_FAMILY;
	if (!w32_addrinfo_flags_supported(flags))
		return EAI_BADFLAGS;
	if ((ret = w32_addrinfo_socktype_protocol(hints, &socktype,
	    &protocol)) != 0)
		return ret;
	if ((ret = w32_addrinfo_parse_service(service, flags, socktype,
	    protocol, &port)) != 0)
		return ret;

	if (node == NULL) {
		addr = (flags & AI_PASSIVE) ? htonl(INADDR_ANY) :
		    htonl(INADDR_LOOPBACK);
		*res = w32_addrinfo_alloc_ipv4(addr, port, flags, socktype,
		    protocol, NULL);
		return *res == NULL ? EAI_MEMORY : 0;
	}

	numeric_host = 0;
	addr = inet_addr(node);
	if (addr != INADDR_NONE || strcmp(node, "255.255.255.255") == 0)
		numeric_host = 1;
	if (numeric_host) {
		*res = w32_addrinfo_alloc_ipv4(addr, port, flags, socktype,
		    protocol, (flags & AI_CANONNAME) ? node : NULL);
		return *res == NULL ? EAI_MEMORY : 0;
	}
	if ((flags & AI_NUMERICHOST) != 0)
		return EAI_NONAME;

	if ((hp = gethostbyname(node)) == NULL || hp->h_addrtype != AF_INET ||
	    hp->h_length != sizeof(in) || hp->h_addr_list == NULL ||
	    hp->h_addr_list[0] == NULL)
		return EAI_NONAME;

	prev = *res = NULL;
	for (i = 0; hp->h_addr_list[i] != NULL; i++) {
		memcpy(&in, hp->h_addr_list[i], sizeof(in));
		cur = w32_addrinfo_alloc_ipv4(in.s_addr, port, flags, socktype,
		    protocol, (i == 0 && (flags & AI_CANONNAME)) ?
		    hp->h_name : NULL);
		if (cur == NULL) {
			w32_freeaddrinfo(*res);
			*res = NULL;
			return EAI_MEMORY;
		}
		if (prev == NULL)
			*res = cur;
		else
			prev->ai_next = cur;
		prev = cur;
	}
	return 0;
}

int
w32_getaddrinfo(const char *node_utf8, const char *service_utf8,
		const struct addrinfo *hints, struct addrinfo **res)
{
	GetAddrInfoWType getaddrinfoW;
	FreeAddrInfoWType freeaddrinfoW;
	*res = NULL;

	if (w32_load_getaddrinfoW(&getaddrinfoW, &freeaddrinfoW))
		return w32_getaddrinfo_modern(node_utf8, service_utf8, hints,
		    res, getaddrinfoW, freeaddrinfoW);
	return w32_getaddrinfo_legacy(node_utf8, service_utf8, hints, res);
}
