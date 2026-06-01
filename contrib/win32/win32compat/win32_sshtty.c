/* 
 * Windows version of sshtty* routines implemented in sshtty.c 
 */

#include "includes.h"

#include <winsock2.h>
#include <windows.h>
#include <errno.h>
#include <string.h>
#include <pwd.h>

#include "console.h"
#include "w32fd.h"
#include "../../../sshpty.h"

static struct termios _saved_tio;
static int _in_raw_mode = 0;

/* 
 * TTY raw mode routines for Windows 
 */

static struct termios term_settings;
static const speed_t default_tty_speed = B9600;

static void
sync_saved_tio(void)
{
	_saved_tio = term_settings;
}

static int
fd_termios_state(int fd, struct termios *tio)
{
	DWORD mode;
	HANDLE handle;

	if (tio == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (!isatty(fd)) {
		errno = ENOTTY;
		return -1;
	}

	memset(tio, 0, sizeof(*tio));
	tio->c_iflag = BRKINT | ICRNL | IXON;
	tio->c_oflag = OPOST;
	tio->c_cflag = CLOCAL | CREAD | CS8;
	tio->c_lflag = ISIG | ICANON | ECHO | ECHOE | ECHOK | IEXTEN;
	tio->c_cc[VMIN] = 1;
	tio->c_cc[VTIME] = 0;
	tio->c_ispeed = default_tty_speed;
	tio->c_ospeed = default_tty_speed;

	handle = (HANDLE)w32_fd_to_handle(fd);
	if (handle == NULL || handle == INVALID_HANDLE_VALUE)
		return 0;
	if (!GetConsoleMode(handle, &mode))
		return 0;

	if ((mode & ENABLE_LINE_INPUT) == 0)
		tio->c_lflag &= ~ICANON;
	if ((mode & ENABLE_ECHO_INPUT) == 0)
		tio->c_lflag &= ~(ECHO | ECHOE | ECHOK);
	if ((mode & ENABLE_PROCESSED_INPUT) == 0)
		tio->c_lflag &= ~ISIG;

	return 0;
}

static int
apply_termios_state(int fd, const struct termios *tio)
{
	DWORD mode;
	HANDLE handle;

	if (tio == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (!isatty(fd)) {
		errno = ENOTTY;
		return -1;
	}

	handle = (HANDLE)w32_fd_to_handle(fd);
	if (handle == NULL || handle == INVALID_HANDLE_VALUE)
		return 0;
	if (!GetConsoleMode(handle, &mode))
		return 0;

	if (tio->c_lflag & ICANON)
		mode |= ENABLE_LINE_INPUT;
	else
		mode &= ~ENABLE_LINE_INPUT;

	if (tio->c_lflag & ECHO)
		mode |= ENABLE_ECHO_INPUT;
	else
		mode &= ~ENABLE_ECHO_INPUT;

	if (tio->c_lflag & ISIG)
		mode |= ENABLE_PROCESSED_INPUT;
	else
		mode &= ~ENABLE_PROCESSED_INPUT;

	if (!SetConsoleMode(handle, mode)) {
		errno = EINVAL;
		return -1;
	}

	return 0;
}

struct termios *
get_saved_tio(void)
{
	return _in_raw_mode ? &_saved_tio : &term_settings;
}

void
leave_raw_mode(int quiet)
{
	if (!_in_raw_mode)
		return;

	ConExitRawMode();
	(void)quiet;
	_in_raw_mode = 0;
	sync_saved_tio();
}

void
enter_raw_mode(int quiet)
{
	(void)quiet;
	if (fd_termios_state(STDIN_FILENO, &term_settings) == -1)
		memset(&term_settings, 0, sizeof(term_settings));

	_saved_tio = term_settings;
	ConEnterRawMode();
	_in_raw_mode = 1;

	if (fd_termios_state(STDIN_FILENO, &term_settings) == -1)
		term_settings = _saved_tio;
}

int
tcgetattr(int fd, struct termios *tio)
{
	return fd_termios_state(fd, tio);
}

int
tcsetattr(int fd, int opt, const struct termios *tio)
{
	switch (opt & ~TCSASOFT) {
	case TCSANOW:
	case TCSADRAIN:
	case TCSAFLUSH:
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	return apply_termios_state(fd, tio);
}

speed_t
cfgetospeed(const struct termios *tio)
{
	return tio->c_ospeed;
}

speed_t
cfgetispeed(const struct termios *tio)
{
	return tio->c_ispeed;
}

int
cfsetospeed(struct termios *tio, speed_t speed)
{
	tio->c_ospeed = speed;
	return 0;
}

int
cfsetispeed(struct termios *tio, speed_t speed)
{
	tio->c_ispeed = speed;
	return 0;
}
