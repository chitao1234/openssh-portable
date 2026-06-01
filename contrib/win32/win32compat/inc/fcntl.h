#if defined(__GNUC__)
# include_next <fcntl.h>
#else
# include "crtheaders.h"
# include FCNTL_H
#endif

/*fcntl commands*/
#define F_GETFL 0x1
#define F_SETFL 0x2
#define F_GETFD 0x4
#define F_SETFD 0x8
#define F_DUPFD 0x10

/*fd flags*/
#define FD_CLOEXEC 0x1

#define F_OK 0


int w32_fcntl(int fd, int cmd, ... /* arg */);
#define fcntl(a,b,...)		w32_fcntl((a), (b), ##__VA_ARGS__)

#define open(a,b,...) w32_open((a), (b), ##__VA_ARGS__)
int w32_open(const char *pathname, int flags, ... /* arg */);

void* w32_fd_to_handle(int fd);

#define O_RDONLY     _O_RDONLY
#define O_WRONLY     _O_WRONLY
#define O_RDWR       _O_RDWR
#define O_APPEND     _O_APPEND
#define O_CREAT      _O_CREAT
#define O_TRUNC      _O_TRUNC
#define O_EXCL       _O_EXCL
#define O_TEXT       _O_TEXT
#define O_BINARY     _O_BINARY
#define O_RAW        _O_BINARY
#define O_TEMPORARY  _O_TEMPORARY
#define O_NOINHERIT  _O_NOINHERIT
#define O_SEQUENTIAL _O_SEQUENTIAL
#define O_RANDOM     _O_RANDOM
#define O_U16TEXT     _O_U16TEXT

/*
* open() POSIX specific modes and flags.
* Caution while making changes
* - cross check conflict with common macros in Windows headers
* - Ex. #define O_APPEND    0x8
*/
#ifndef O_ACCMODE
#define O_ACCMODE			0x0003
#endif
#ifndef O_NONBLOCK
# define O_NONBLOCK			0x0004  /*io operations wont block*/
#endif
#ifndef S_IXUSR
# define S_IXUSR			0000100	/* execute/search permission, */
#endif
#ifndef S_IXGRP
# define S_IXGRP			0000010	/* execute/search permission, */
#endif
#ifndef S_IXOTH
# define S_IXOTH			0000001	/* execute/search permission, */
#endif
#ifndef _S_IWUSR
# define _S_IWUSR			0000200	/* write permission, */
#endif
#ifndef S_IWUSR
# define S_IWUSR			_S_IWUSR	/* write permission, owner */
#endif
#ifndef S_IWGRP
# define S_IWGRP			0000020	/* write permission, group */
#endif
#ifndef S_IWOTH
# define S_IWOTH			0000002	/* write permission, other */
#endif
#ifndef S_IRUSR
# define S_IRUSR			0000400	/* read permission, owner */
#endif
#ifndef S_IRGRP
# define S_IRGRP			0000040	/* read permission, group */
#endif
#ifndef S_IROTH
# define S_IROTH			0000004	/* read permission, other */
#endif
#ifndef S_IRWXU
# define S_IRWXU			0000700	/* read, write, execute */
#endif
#ifndef S_IRWXG
# define S_IRWXG			0000070	/* read, write, execute */
#endif
#ifndef S_IRWXO
# define S_IRWXO			0000007	/* read, write, execute */
#endif

/* 
 * File types. Note that the values are different from similar variants 
 * defined in stat.h. These are based on similar definition values on Linux
 */
#define __S_IFDIR       0040000 /* Directory.  */
#define __S_IFREG       0100000 /* Regular file.  */
