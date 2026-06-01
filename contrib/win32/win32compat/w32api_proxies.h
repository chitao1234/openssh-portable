/*
* Author: Yanbing Wang <yawang@microsoft.com>
*
* Support logon user call on Win32 based operating systems.
*
*/

#pragma once

#include <winsock2.h>
#include <windows.h>
#define SECURITY_WIN32
#include <security.h>
#include <ntsecapi.h>

BOOL pLogonUserExExW(wchar_t *, wchar_t *, wchar_t *, DWORD, DWORD, PTOKEN_GROUPS, PHANDLE, PSID *, PVOID *, LPDWORD, PQUOTA_LIMITS);
BOOLEAN pTranslateNameW(LPCWSTR, EXTENDED_NAME_FORMAT, EXTENDED_NAME_FORMAT, LPWSTR, PULONG);
NTSTATUS pLsaOpenPolicy(PLSA_UNICODE_STRING, PLSA_OBJECT_ATTRIBUTES, ACCESS_MASK, PLSA_HANDLE);
NTSTATUS pLsaFreeMemory(PVOID);
NTSTATUS pLsaAddAccountRights(LSA_HANDLE, PSID,	PLSA_UNICODE_STRING, ULONG);
ULONG pRtlNtStatusToDosError(NTSTATUS);
NTSTATUS pLsaClose(LSA_HANDLE);
NTSTATUS pLsaRemoveAccountRights(LSA_HANDLE, PSID, BOOLEAN, PLSA_UNICODE_STRING, ULONG);
BOOL pCancelIoEx(HANDLE, LPOVERLAPPED);
BOOL pCancelSynchronousIo(HANDLE);
BOOLEAN pCreateSymbolicLinkW(LPCWSTR, LPCWSTR, DWORD);
DWORD pGetFinalPathNameByHandleW(HANDLE, LPWSTR, DWORD, DWORD);
BOOL pGetConsoleScreenBufferInfoEx(HANDLE, PCONSOLE_SCREEN_BUFFER_INFOEX);
ULONGLONG pGetTickCount64(void);
BOOL pIsWindowsVistaOrGreater(void);
BOOL pIsWindows8OrGreater(void);
LSTATUS pRegGetValueW(HKEY, LPCWSTR, LPCWSTR, DWORD, LPDWORD, PVOID, LPDWORD);
