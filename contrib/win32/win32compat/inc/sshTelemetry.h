/*
 * Minimal telemetry stub for autotools/MinGW builds.
 *
 * The Visual Studio build uses contrib/win32/openssh/sshTelemetry.*
 * with TraceLogging. For MinGW and XP-oriented bring-up we use no-op
 * declarations here so Windows-specific telemetry does not block the build.
 */

#pragma once

static inline void
send_auth_telemetry(const int status, const char *auth_type)
{
	(void)status;
	(void)auth_type;
}

static inline void
send_auth_method_telemetry(const char *auth_methods)
{
	(void)auth_methods;
}

static inline void
send_encryption_telemetry(const char *direction, const char *cipher,
    const char *kex, const char *mac, const char *comp,
    const char *host_key, char *const *cproposal, char *const *sproposal)
{
	(void)direction;
	(void)cipher;
	(void)kex;
	(void)mac;
	(void)comp;
	(void)host_key;
	(void)cproposal;
	(void)sproposal;
}

static inline void
send_kex_exch_exit_code_telemetry(const int exit_code)
{
	(void)exit_code;
}

static inline void
send_pubkey_telemetry(const char *pubkey_status)
{
	(void)pubkey_status;
}

static inline void
send_shell_telemetry(const int pty, const int shell_type)
{
	(void)pty;
	(void)shell_type;
}

static inline void
send_pubkey_sign_telemetry(const char *pubkey_sign_status)
{
	(void)pubkey_sign_status;
}

static inline void
send_ssh_connection_telemetry(const char *conn, const char *port)
{
	(void)conn;
	(void)port;
}

static inline void
send_sshd_connection_telemetry(const char *conn)
{
	(void)conn;
}

static inline void
send_ssh_version_telemetry(const char *ssh_version, const char *peer_version,
    const char *remote_protocol_error)
{
	(void)ssh_version;
	(void)peer_version;
	(void)remote_protocol_error;
}
