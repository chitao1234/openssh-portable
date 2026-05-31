# Windows XP Porting Milestone

This repository is the Microsoft Win32 port of portable OpenSSH. The first
milestone for Windows XP support is not "full feature parity"; it is to remove
the most obvious build-time and runtime assumptions that require Windows Vista
or newer, so the Win32 compatibility layer can be brought up on XP and tested.

## What this milestone changes

- Lowers the Win32 target floor in Visual Studio project definitions to
  `_WIN32_WINNT=0x0501` through a central `$(OpenSSHWinNt)` property.
- Keeps non-Win32 project targets at the existing `0x0601` floor.
- Replaces direct calls to several Vista+ APIs in the Win32 compatibility layer
  with late-bound proxy functions and XP-safe fallbacks where practical.
- Makes ConPTY detection avoid newer loader flags so XP simply falls back to the
  legacy `ssh-shellhost.exe` PTY path.

## APIs that now have XP-oriented handling

The current tree used these APIs directly:

- `GetTickCount64`
- `CancelIoEx`
- `CancelSynchronousIo`
- `GetFinalPathNameByHandleW`
- `RegGetValueW`
- `IsWindows8OrGreater` via `VersionHelpers.h`
- `LoadLibraryExW(..., LOAD_LIBRARY_SEARCH_SYSTEM32)` in the ConPTY probe

The XP milestone routes them through `contrib/win32/win32compat/w32api_proxies.*`
so the process can:

- late-bind the real API when present on newer systems
- fall back to older APIs where possible
- return a clean "unsupported" result instead of hard-failing at load time

## Known remaining blockers

This milestone does not mean OpenSSH is ready for Windows XP yet. The biggest
remaining blockers are deeper than a few Win32 wrappers:

1. Toolchain floor

The checked-in Windows build currently assumes modern Visual Studio 2022,
`v143`, recent Windows SDKs, and `/Qspectre`-compatible CRTs. Those are not an
XP-targeting toolchain. You will likely need a separate legacy build path for
the `Win32` platform, potentially using an older MSVC or MinGW-based workflow.

2. Crypto and dependency floor

`paths.targets` still links `bcrypt.lib`, and `win32iocompat.vcxproj` still
defines `USE_MSCNG`. CNG is not available on stock Windows XP. A real XP port
must either:

- replace the CNG-dependent code path with CryptoAPI/OpenSSL-based logic, or
- build a distinct XP profile that disables the MSCNG path entirely

3. ETW / TraceLogging

Parts of the Windows logging stack use ETW and TraceLogging. ETW provider
registration is a Vista+ feature set. For XP, this likely needs to degrade to
Event Log only, debug logging only, or a compile-time-disabled telemetry path.

4. Long-path and handle-to-path behavior

The `GetFinalPathNameByHandleW` fallback is best-effort. It is sufficient for
initial bring-up, but should be tested carefully against:

- local files
- UNC paths
- symlinks / reparse points
- chroot path checks
- `fdopen()` reopen paths

5. Authentication and service behavior

Modern Windows logon, service hardening, and token-management assumptions need
validation on XP, especially around:

- service installation and SCM behavior
- LSA / logon package handling
- user profile loading
- password authentication
- privilege assignment and SID translation

6. Feature scope

Expect some Windows features to remain unavailable on XP even if the port
starts and accepts connections:

- ConPTY
- modern telemetry
- some newer shell-host behavior
- any functionality that depends on newer system DLL exports

## Reference code

The sibling `../openssh-5.9p1-win32` tree is useful as a reference for older
Win32 assumptions and XP-era build targets, but it is much older than the
current Microsoft port. Treat it as a compatibility reference, not as code that
can be copied forward wholesale.

## Recommended next steps

1. Create a dedicated XP build profile for `Win32`.

Keep `x64` and newer ARM targets on the current toolchain assumptions. XP work
should be isolated to `Win32` first.

2. Remove or conditionalize the CNG dependency.

This is likely the next largest technical blocker after the basic Win32 API
surface.

3. Audit ETW / TraceLogging paths.

Decide whether to stub them, disable them, or route them to a legacy logging
backend when `OpenSSHWinNt == 0x0501`.

4. Compare runtime behavior against the NoMachine 5.9 Win32 tree.

Use the older tree to guide service setup, authentication fallbacks, and any
XP-specific shell or console behavior that Microsoft’s newer port no longer
expects.
