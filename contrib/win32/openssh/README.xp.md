# Windows XP Port Status

This branch is an XP bring-up of Microsoft's Win32 OpenSSH port. The current
working target is 32-bit MinGW on Windows XP; it is not a production-ready XP
release and does not imply feature parity with Windows 7+.

The sibling `../openssh-5.9p1-win32` tree remains useful as historical Win32
reference material, but it is not treated as authoritative code for this port.

## Current Build Shape

- The active XP path is the MinGW/autotools build. It builds the Win32
  compatibility layer and the server-side Windows helpers instead of using a
  separate POSIX-only path.
- The current XP-tested build is OpenSSL-less and does not require `bcrypt` or
  `libcrypto` at runtime. This reduces the available algorithm surface; XP
  validation has focused on Ed25519 host/user keys and the algorithms offered
  by that build.
- The Visual Studio projects are still useful for comparing intended Windows
  wiring, but the XP work is currently validated through the 32-bit MinGW path.
- ConPTY is not available on XP. Interactive sessions use the legacy
  `ssh-shellhost.exe` PTY path.
- Several Vista+ APIs are late-bound through
  `contrib/win32/win32compat/w32api_proxies.*` so XP can use fallbacks or clean
  unsupported results instead of failing at load time.

## XP Runtime Validation

The following paths have been tested on Windows XP with the 32-bit MinGW build:

- `ssh.exe` client connections from XP to a Linux host.
- `sshd.exe` as a Windows service on a non-privileged test port.
- Password authentication for local XP users.
- Public-key authentication for local XP users through the XP LSA package path.
- Non-PTY remote command execution.
- Interactive legacy PTY sessions through `ssh-shellhost.exe`.
- `sftp-server.exe` as the configured server subsystem.
- Default `scp` mode, which uses SFTP.
- Legacy `scp -O` mode.

For SFTP paths, use the Windows absolute form `/C:/path/...`. A plain
`C:/path/...` is parsed as a relative SFTP path by this port.

## ACL And Strict Permission Status

The Windows port has two different ACL layers, and the distinction matters:
runtime `StrictModes` checks for user authentication files, and install/repair
ACL policy for server configuration and application files.

- `StrictModes yes` rejects an insecure user's `authorized_keys` at runtime.
  On XP, adding writable `Everyone` access to
  `C:\Documents and Settings\<user>\.ssh\authorized_keys` caused public-key
  authentication to fail with `Permission denied (publickey)`.
- Host private keys are repaired by service startup code. On XP, adding writable
  `Everyone` access to `ssh_host_ed25519_key` was removed on the next service
  start, restoring the private key to Administrators/System-only access.
- `sshd_config` permissions are installation/repair policy, not a runtime gate.
  The Windows repair function is `Repair-SshdConfigPermission`; current runtime
  tests show `sshd` does not reject a writable custom `-f` config file.
- Application binaries, including `sftp-server.exe`, are also installation
  ACL policy. `Repair-ApplicationFilePermission` allows normal users
  read/execute access and removes write access, but current runtime tests show
  subsystem launch does not reject a writable `sftp-server.exe`.

For production-style XP packaging, the installer or setup tool must apply the
server config, host key, application binary, and user key ACL policies. Runtime
checks alone do not cover every file class.

## Known Remaining Gaps

- The XP installer/setup flow is still not productionized. This includes
  service creation, `%ProgramData%\ssh` setup on XP, default config placement,
  ACL repair, and clear operator-facing scripts.
- LSA package deployment is not automated for production use. The local-user
  public-key path has been validated, but install/reboot/rollback handling still
  needs hardening.
- Domain-user public-key authentication is not solved.
- GSSAPI/Kerberos and domain integration are unvalidated.
- Legacy PTY resize support is disabled or incomplete on XP.
- Modern Windows features such as ConPTY and newer telemetry are outside the XP
  runtime surface.
- The no-OpenSSL build has a reduced crypto/key algorithm surface compared with
  normal modern Windows builds.
- Runtime ACL enforcement does not cover `sshd_config` or external subsystem
  binaries; those remain setup/repair responsibilities unless we deliberately
  choose to change Windows behavior.

## Recommended Next Steps

1. Keep iterating on the 32-bit MinGW build and test on a real XP target.
2. Turn the current manual XP service, ProgramData, ACL, and LSA setup steps
   into repeatable scripts or installer actions.
3. Add automated regression coverage for XP-relevant SFTP/SCP/subsystem and
   ACL behavior where it can be tested without a full XP VM.
4. Decide explicitly whether to preserve upstream Windows ACL semantics for
   config/application files or add stricter runtime checks for this XP port.
5. Validate the remaining authentication surface: domain accounts, GSSAPI, and
   any key algorithms needed beyond the current OpenSSL-less Ed25519 path.
