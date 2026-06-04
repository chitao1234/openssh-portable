/*
 * Author: Manoj Ampalam <manojamp@microsoft.com>
 *  read() and write() on tty using worker threads to handle 
 *  synchronous Windows Console IO
 * 
 * Author: Ray Hayes <ray.hayes@microsoft.com>
 *  TTY/PTY support added by capturing all terminal input events
 *
 * Author: Balu <bagajjal@microsoft.com>
 *  Misc fixes and code cleanup
 *
 * Author: Manoj Ampalam <manojamp@microsoft.com>
 *  Extended support to other Windows IO that does not support 
 *  overlapped IO. Ex. pipe handles returned by CreatePipe()
 * 
 * Copyright (c) 2017 Microsoft Corp.
 * All rights reserved
 *
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
#include <windows.h>
#include <process.h>
#include <stdlib.h>
#include <string.h>
#include "w32fd.h"
#include "tncon.h"
#include "utf.h"
#include "Debug.h"
#include "tnnet.h"
#include "misc_internal.h"
#include "w32api_proxies.h"

extern int in_raw_mode;
BOOL isFirstTime = TRUE;

static BOOL
syncio_valid_handle(HANDLE handle)
{
	return handle != NULL && handle != INVALID_HANDLE_VALUE;
}

static DWORD
syncio_file_type(struct w32_io *pio)
{
	if (!syncio_valid_handle(WINHANDLE(pio)))
		return FILE_TYPE_UNKNOWN;
	return FILETYPE(pio);
}

static void
syncio_close_handle(struct w32_io *pio, DWORD file_type)
{
	if (file_type != FILE_TYPE_CHAR && syncio_valid_handle(WINHANDLE(pio))) {
		CloseHandle(WINHANDLE(pio));
		WINHANDLE(pio) = INVALID_HANDLE_VALUE;
	}
}

static void
syncio_free(struct w32_io *pio, DWORD file_type)
{
	syncio_close_handle(pio, file_type);
	if (pio->read_details.buf)
		free(pio->read_details.buf);
	if (pio->write_details.buf)
		free(pio->write_details.buf);
	free(pio);
}

static BOOL
syncio_reap_signaled_read_thread(struct w32_io *pio)
{
	HANDLE read_thread = pio->read_overlapped.hEvent;

	if (read_thread == NULL)
		return TRUE;
	if (WaitForSingleObject(read_thread, 0) != WAIT_OBJECT_0)
		return FALSE;

	/*
	 * Prefer the normal completion APC. If the worker exited through the
	 * interrupt APC, no read APC will arrive, so reap the thread here.
	 */
	SleepEx(0, TRUE);
	if (!pio->read_details.pending)
		return TRUE;

	CloseHandle(read_thread);
	pio->read_overlapped.hEvent = NULL;
	pio->read_details.pending = FALSE;
	return TRUE;
}

static BOOL
syncio_terminate_read_thread(struct w32_io *pio)
{
	HANDLE read_thread = pio->read_overlapped.hEvent;

	if (syncio_reap_signaled_read_thread(pio))
		return TRUE;

	debug4("terminating sync read worker thread, io:%p", pio);
	if (!TerminateThread(read_thread, 0)) {
		debug4("TerminateThread failed, error:%d, io:%p", GetLastError(), pio);
		return FALSE;
	}
	if (WaitForSingleObject(read_thread, 1000) != WAIT_OBJECT_0) {
		debug4("terminated sync read worker did not exit, io:%p", pio);
		return FALSE;
	}

	CloseHandle(read_thread);
	pio->read_overlapped.hEvent = NULL;
	pio->read_details.pending = FALSE;
	return TRUE;
}

/* APC that gets queued on main thread when a sync Read completes on worker thread */
static VOID CALLBACK
ReadAPCProc(_In_ ULONG_PTR dwParam)
{
	struct w32_io* pio = (struct w32_io*)dwParam;

	if (pio->read_overlapped.hEvent == NULL)
		return;

	debug5("TermRead CB - io:%p, bytes: %d, pending: %d, error: %d", pio, pio->read_details.completed,
		pio->read_details.pending, pio->sync_read_status.error);
	pio->read_details.error = pio->sync_read_status.error;
	pio->read_details.remaining = pio->sync_read_status.transferred;
	pio->read_details.completed = 0;
	pio->read_details.pending = FALSE;
	WaitForSingleObject(pio->read_overlapped.hEvent, INFINITE);
	CloseHandle(pio->read_overlapped.hEvent);
	pio->read_overlapped.hEvent = 0;
	if (pio->close_after_read) {
		syncio_free(pio, syncio_file_type(pio));
	}
}

/* Read worker thread */
static unsigned __stdcall
ReadThread(_In_ LPVOID lpParameter)
{
	int nBytesReturned = 0;
	struct w32_io* pio = (struct w32_io*)lpParameter;

	debug5("TermRead thread, io:%p", pio);
	memset(&pio->sync_read_status, 0, sizeof(pio->sync_read_status));
	if (FILETYPE(pio) == FILE_TYPE_CHAR) {
		if (in_raw_mode) {
			while (nBytesReturned == 0) {
				nBytesReturned = ReadConsoleForTermEmul(WINHANDLE(pio),
					pio->read_details.buf, pio->read_details.buf_size);
			}
			pio->sync_read_status.transferred = nBytesReturned;
		}  else {
			if (isFirstTime) {
				isFirstTime = false;

				DWORD dwAttributes;
				/* open(dev/null) is showing up as FILE_TYPE_CHAR but is not a valid console handle */
				if (GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &dwAttributes)) {
					dwAttributes |= (ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
					if (!SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), dwAttributes))
						debug2("SetConsoleMode on STD_INPUT_HANDLE failed with %d", GetLastError());
				} else if (GetLastError() != ERROR_INVALID_HANDLE)
					debug2("GetConsoleMode on STD_INPUT_HANDLE failed with %d", GetLastError());

			}

			if (!ReadFile(WINHANDLE(pio), pio->read_details.buf,
				pio->read_details.buf_size, &(pio->sync_read_status.transferred), NULL)) {
				debug4("ReadThread - ReadFile failed, error:%d, io:%p", GetLastError(), pio); 
				pio->sync_read_status.error = GetLastError();
				goto done;
			}

			if (pio->sync_read_status.transferred) {
				char *p = NULL;
				if (p = strstr(pio->read_details.buf, "\r\n"))
					*p++ = '\n';
				else if (p = strstr(pio->read_details.buf, "\r"))
					*p++ = '\n';

				if (p) {
					*p = '\0';
					pio->sync_read_status.transferred = (DWORD)strlen(pio->read_details.buf);
				}
			}
		}
	} else {
		if (!ReadFile(WINHANDLE(pio), pio->read_details.buf,
		    pio->read_details.buf_size, &(pio->sync_read_status.transferred), NULL)) {
			debug4("ReadThread - ReadFile failed, error:%d, io:%p", GetLastError(), pio); 
			pio->sync_read_status.error = GetLastError();
			goto done;
		}

		/* If there is no data to be read then set the error to ERROR_HANDLE_EOF */
		if (!pio->sync_read_status.transferred) {
			pio->sync_read_status.error = ERROR_HANDLE_EOF;
		}
	}

done:
	if (0 == QueueUserAPC(ReadAPCProc, main_thread, (ULONG_PTR)pio)) {		
		pio->read_details.pending = FALSE;
		pio->read_details.error = GetLastError();
		debug_assert_internal();
	}

	return 0;
}

/* Initiates read on tty */
int
syncio_initiate_read(struct w32_io* pio)
{
	HANDLE read_thread;

	debug5("syncio_initiate_read io:%p", pio);
	if (pio->read_details.buf_size == 0) {
		pio->read_details.buf = malloc(TERM_IO_BUF_SIZE);
		if (pio->read_details.buf == NULL) {
			errno = ENOMEM;
			return -1;
		}
		pio->read_details.buf_size = TERM_IO_BUF_SIZE;
	}

	read_thread = (HANDLE) _beginthreadex(NULL, 0, ReadThread, pio, 0, NULL);
	if (read_thread == NULL) {
		errno = errno_from_Win32LastError();
		debug3("TermRead initiate - ERROR _beginthreadex %d, io:%p", GetLastError(), pio);
		return -1;
	}

	pio->read_overlapped.hEvent = read_thread;
	pio->read_details.pending = TRUE;
	return 0;
}

/* APC that gets queued on main thread when a sync Write completes on worker thread */
static VOID CALLBACK 
WriteAPCProc(_In_ ULONG_PTR dwParam)
{
	struct w32_io* pio = (struct w32_io*)dwParam;

	if (pio->write_overlapped.hEvent == NULL)
		return;

	debug5("TermWrite CB - io:%p, bytes: %d, pending: %d, error: %d", pio, pio->write_details.completed,
		pio->write_details.pending, pio->sync_write_status.error);
	pio->write_details.error = pio->sync_write_status.error;
	pio->write_details.remaining -= pio->sync_write_status.transferred;
	/* TODO- assert that reamining is 0 by now */
	pio->write_details.completed = 0;
	pio->write_details.pending = FALSE;
	WaitForSingleObject(pio->write_overlapped.hEvent, INFINITE);
	CloseHandle(pio->write_overlapped.hEvent);
	pio->write_overlapped.hEvent = 0;

	/* Inject any TTY query response (e.g. cursor position report) into the read buffer */
	if (pio->tty_resp_buf != NULL && pio->tty_resp_len > 0 &&
	    !pio->read_details.pending) {
		if (pio->read_details.buf_size == 0) {
			pio->read_details.buf = malloc(pio->tty_resp_len);
			pio->read_details.buf_size = (DWORD)pio->tty_resp_len;
		}
		if (pio->read_details.buf != NULL) {
			DWORD n = (DWORD)min(pio->tty_resp_len, pio->read_details.buf_size);
			memcpy(pio->read_details.buf, pio->tty_resp_buf, n);
			pio->read_details.remaining = n;
			pio->read_details.completed = 0;
		}
		pio->tty_resp_buf = NULL;
		pio->tty_resp_len = 0;
	}
}


/* Write worker thread */
static unsigned __stdcall
WriteThread(_In_ LPVOID lpParameter)
{
	struct w32_io* pio = (struct w32_io*)lpParameter;
	unsigned char *respbuf = NULL;
	size_t resplen = 0;	
	debug5("WriteThread thread, io:%p", pio);

	if (FILETYPE(pio) == FILE_TYPE_CHAR) {
		if (0 == in_raw_mode) {
			char *utf8 = pio->write_details.buf, *alloc = NULL;
			wchar_t *t;
			DWORD written;

			if (pio->sync_write_status.to_transfer <
			    pio->write_details.buf_size) {
				utf8[pio->sync_write_status.to_transfer] = '\0';
			} else if ((alloc = malloc(
			    pio->sync_write_status.to_transfer + 1)) == NULL) {
				pio->sync_write_status.error = ERROR_OUTOFMEMORY;
				goto done;
			} else {
				memcpy(alloc, pio->write_details.buf,
				    pio->sync_write_status.to_transfer);
				alloc[pio->sync_write_status.to_transfer] = '\0';
				utf8 = alloc;
			}

			t = utf8_to_utf16(utf8);
			if (t != NULL) {
				if (!WriteConsoleW(WINHANDLE(pio), t,
				    (DWORD)wcslen(t), &written, NULL))
					pio->sync_write_status.error = GetLastError();
				free(t);
			} else
				pio->sync_write_status.error = ERROR_OUTOFMEMORY;
			free(alloc);
		} else {
			processBuffer(WINHANDLE(pio), pio->write_details.buf, pio->sync_write_status.to_transfer, &respbuf, &resplen);
			if (respbuf != NULL && resplen > 0) {
				pio->tty_resp_buf = respbuf;
				pio->tty_resp_len = resplen;
			}
		}
		if (pio->sync_write_status.error == 0)
			pio->sync_write_status.transferred = pio->sync_write_status.to_transfer;
	} else {
		if (!WriteFile(WINHANDLE(pio), pio->write_details.buf, pio->sync_write_status.to_transfer,
		    &(pio->sync_write_status.transferred), NULL)) {
			pio->sync_write_status.error = GetLastError();
			debug4("WriteThread - WriteFile %d, io:%p", GetLastError(), pio);
		}
	}

done:
	if (0 == QueueUserAPC(WriteAPCProc, main_thread, (ULONG_PTR)pio)) {
		error("WriteThread thread - ERROR QueueUserAPC failed %d, io:%p", GetLastError(), pio);
		pio->write_details.pending = FALSE;
		pio->write_details.error = GetLastError();
		debug_assert_internal();
	}

	return 0;
}

/* Initiates write on tty */
int
syncio_initiate_write(struct w32_io* pio, DWORD num_bytes)
{
	HANDLE write_thread;
	debug5("syncio_initiate_write initiate io:%p", pio);
	memset(&(pio->sync_write_status), 0, sizeof(pio->sync_write_status));
	pio->sync_write_status.to_transfer = num_bytes;
	write_thread = (HANDLE)_beginthreadex(NULL, 0, WriteThread, pio, 0, NULL);
	if (write_thread == NULL) {
		errno = errno_from_Win32LastError();
		debug3("syncio_initiate_write initiate - ERROR _beginthreadex %d, io:%p", GetLastError(), pio);
		return -1;
	}

	pio->write_overlapped.hEvent = write_thread;
	pio->write_details.pending = TRUE;
	return 0;
}

static VOID CALLBACK
InterruptThread(_In_ ULONG_PTR dwParam)
{
	_endthreadex(0);
}

/* close */
int 
syncio_close(struct w32_io* pio)
{
	int should_defer_free = 0;
	DWORD file_type = FILE_TYPE_UNKNOWN;
	BOOL can_cancel_cross_thread;

	debug4("syncio_close - pio:%p", pio);
	can_cancel_cross_thread = pIsWindowsVistaOrGreater();

	/*
	* Wait for io write operation that is called by worker thread to terminate
	* to avoid the write operation being terminated prematurely by CancelIoEx.
	* If you see any process waiting here indefinitely - its because no one
	* is draining from other end of the pipe. This is an unfortunate
	* consequence that should otherwise have very little impact on practical
	* scenarios.
	*/
	if (pio->write_details.pending) {
		WaitForSingleObject(pio->write_overlapped.hEvent, INFINITE);

		/* drain queued APCs */
		SleepEx(0, TRUE);
	}

	if (can_cancel_cross_thread)
		pCancelIoEx(WINHANDLE(pio), NULL);

	/* If io is pending, let worker threads exit. */
	if (pio->read_details.pending) {
		/*
		* CancelIoEx/CancelSynchronousIo handle Vista+ cross-thread
		* cancellation. XP has neither; even GetFileType/CloseHandle can
		* block behind the pending synchronous read, so terminate this
		* dedicated worker before touching the underlying handle.
		*/
		if (can_cancel_cross_thread) {
			QueueUserAPC(InterruptThread, pio->read_overlapped.hEvent, (ULONG_PTR)NULL);
			pCancelSynchronousIo(pio->read_overlapped.hEvent);
		} else if (!syncio_terminate_read_thread(pio))
			should_defer_free = 1;

		// give the read thread some time to wind down, but don't block syncio_close
		if (!should_defer_free && pio->read_details.pending &&
		    WAIT_TIMEOUT == WaitForSingleObject(pio->read_overlapped.hEvent, 1000)) {
			debug4("read_overlapped thread timed out");
			if (!can_cancel_cross_thread &&
			    syncio_terminate_read_thread(pio))
				should_defer_free = 0;
			else
				should_defer_free = 1;
		}
	}

	if (should_defer_free) {
		pio->close_after_read = TRUE;
		/* drain queued APCs after transferring cleanup ownership */
		SleepEx(0, TRUE);
		return 0;
	}

	/* drain queued APCs */
	SleepEx(0, TRUE);

	if (pio->read_details.pending)
		syncio_reap_signaled_read_thread(pio);

	/* TODO - fix this, closing Console handles is interfering with TTY/PTY rendering */
	file_type = syncio_file_type(pio);
	syncio_free(pio, file_type);
	return 0;
}
