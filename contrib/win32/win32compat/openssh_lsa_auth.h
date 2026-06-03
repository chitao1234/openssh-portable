/*
 * Protocol shared between sshd and the OpenSSH XP LSA authentication
 * package.
 *
 * The package is intentionally grant based: only trusted LSA callers may
 * create a one-time grant with LsaCallAuthenticationPackage, and
 * LsaLogonUser only mints a token when that grant is redeemed.
 */
#ifndef OPENSSH_LSA_AUTH_H
#define OPENSSH_LSA_AUTH_H

#include <windows.h>

#define OPENSSH_LSA_AUTH_PACKAGE "OpenSSHLsaAuth"
#define OPENSSH_LSA_AUTH_DLL "openssh-lsa-auth"
#define OPENSSH_LSA_AUTH_MAGIC 0x4f534c41UL /* "OSLA" */
#define OPENSSH_LSA_AUTH_VERSION 1
#define OPENSSH_LSA_AUTH_GRANT_BYTES 16

#define OPENSSH_LSA_AUTH_OP_CREATE_GRANT 1
#define OPENSSH_LSA_AUTH_OP_REDEEM_GRANT 2

typedef struct _OPENSSH_LSA_AUTH_REQUEST {
	ULONG magic;
	ULONG version;
	ULONG opcode;
	ULONG flags;
	ULONG user_bytes;
	ULONG domain_bytes;
	UCHAR grant[OPENSSH_LSA_AUTH_GRANT_BYTES];
	/* WCHAR user[], domain[] follow, including terminating NULs. */
} OPENSSH_LSA_AUTH_REQUEST;

typedef struct _OPENSSH_LSA_AUTH_GRANT_REPLY {
	ULONG magic;
	ULONG version;
	ULONG status;
	UCHAR grant[OPENSSH_LSA_AUTH_GRANT_BYTES];
} OPENSSH_LSA_AUTH_GRANT_REPLY;

#endif /* OPENSSH_LSA_AUTH_H */
