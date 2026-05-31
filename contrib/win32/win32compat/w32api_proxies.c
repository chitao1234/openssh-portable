/*
* Author: Yanbing Wang <yawang@microsoft.com>
*	Support logon user call on Win32 based operating systems.
*
* Author: Manoj Ampalam <manojamp@microsoft.com>
*	Added generalized wrappers for run time dll loading
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

#include "w32api_proxies.h"
#include "Debug.h"
#include "misc_internal.h"

#ifndef STATUS_BUFFER_OVERFLOW
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#endif

#ifndef RRF_SUBKEY_WOW6464KEY
#define RRF_SUBKEY_WOW6464KEY 0
#endif

#ifndef RRF_SUBKEY_WOW6432KEY
#define RRF_SUBKEY_WOW6432KEY 0
#endif

typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation = 0,
	ObjectNameInformation = 1
} OBJECT_INFORMATION_CLASS;

typedef NTSTATUS (NTAPI *NtQueryObjectType)(
	HANDLE,
	OBJECT_INFORMATION_CLASS,
	PVOID,
	ULONG,
	PULONG);

static FARPROC get_proc_address(HMODULE hm, const char *fn);

static wchar_t*
system32_dir()
{
	static wchar_t* s_system32_dir = NULL;
	static wchar_t s_system32_path[PATH_MAX + 1] = { 0, };

	if (s_system32_dir)
		return s_system32_dir;

	if (!GetSystemDirectoryW(s_system32_path, _countof(s_system32_path))) {
		debug3("GetSystemDirectory failed with error %d", GetLastError());
		return NULL;
	}
	s_system32_dir = s_system32_path;

	return s_system32_dir;
}

static HMODULE
load_module(wchar_t* name)
{
	HMODULE hm = NULL;

	/*system uses a standard search strategy to find the module */
	if ((hm = LoadLibraryW(name)) == NULL)
		debug3("unable to load module %ls at run time, error: %d", name, GetLastError());

	return hm;
}

static HMODULE
load_sspicli()
{
	static HMODULE s_hm_sspicli = NULL;

	if (!s_hm_sspicli)
		s_hm_sspicli = load_module(L"sspicli.dll");

	return s_hm_sspicli;
}

static HMODULE
load_advapi32()
{
	static HMODULE s_hm_advapi32 = NULL;

	if (!s_hm_advapi32)
		s_hm_advapi32 = load_module(L"advapi32.dll");

	return s_hm_advapi32;
}

static HMODULE
load_api_security_lsapolicy()
{
	static HMODULE s_hm_api_security_lsapolicy = NULL;

	if (!s_hm_api_security_lsapolicy)
		s_hm_api_security_lsapolicy = load_module(L"api-ms-win-security-lsapolicy-l1-1-0.dll");

	return s_hm_api_security_lsapolicy;
}

static HMODULE
load_secur32()
{
	static HMODULE s_hm_secur32 = NULL;

	if (!s_hm_secur32)
		s_hm_secur32 = load_module(L"secur32.dll");

	return s_hm_secur32;
}

static HMODULE
load_ntdll()
{
	static HMODULE s_hm_ntdll = NULL;

	if (!s_hm_ntdll)
		s_hm_ntdll = load_module(L"ntdll.dll");

	return s_hm_ntdll;
}

static HMODULE
load_kernel32()
{
	static HMODULE s_hm_kernel32 = NULL;

	if (!s_hm_kernel32)
		s_hm_kernel32 = load_module(L"kernel32.dll");

	return s_hm_kernel32;
}

static BOOL
get_os_version(OSVERSIONINFOEXW *version_info)
{
	static int cached = 0;
	static OSVERSIONINFOEXW cached_version = { 0 };

	if (!cached) {
		cached_version.dwOSVersionInfoSize = sizeof(cached_version);
		if (!GetVersionExW((LPOSVERSIONINFOW)&cached_version)) {
			debug3("GetVersionExW failed with error %d", GetLastError());
			return FALSE;
		}
		cached = 1;
	}
	*version_info = cached_version;
	return TRUE;
}

static BOOL
resolve_dos_path_from_device_path(const wchar_t *device_path, wchar_t *path_buf, DWORD path_buf_len)
{
	wchar_t drive[3] = L" :";
	wchar_t target[MAX_PATH];
	DWORD i;

	drive[1] = L':';
	for (i = 0; i < 26; i++) {
		drive[0] = (wchar_t)(L'A' + i);
		if (QueryDosDeviceW(drive, target, ARRAYSIZE(target)) == 0)
			continue;
		if (_wcsnicmp(device_path, target, wcslen(target)) != 0)
			continue;
		if (_snwprintf_s(path_buf, path_buf_len, _TRUNCATE, L"%ls%ls", drive, device_path + wcslen(target)) < 0)
			return FALSE;
		return TRUE;
	}

	return FALSE;
}

static DWORD
fallback_final_path_name_by_handle(HANDLE h, LPWSTR path_buf, DWORD path_buf_len)
{
	HMODULE ntdll = NULL;
	DWORD ret = 0;
	DWORD chars_needed = 0;
	PVOID object_info = NULL;
	wchar_t *device_path = NULL;
	wchar_t dos_path[PATH_MAX];
	UNICODE_STRING *object_name = NULL;
	ULONG return_length = 0;
	NTSTATUS status;
	NtQueryObjectType pNtQueryObject = NULL;
	BYTE stack_buf[1024];

	ntdll = load_ntdll();
	if (ntdll == NULL)
		goto done;

	pNtQueryObject = (NtQueryObjectType)get_proc_address(ntdll, "NtQueryObject");
	if (pNtQueryObject == NULL)
		goto done;

	object_info = stack_buf;
	status = pNtQueryObject(h, ObjectNameInformation, object_info, sizeof(stack_buf), &return_length);
	if (status == STATUS_BUFFER_OVERFLOW && return_length != 0) {
		object_info = malloc(return_length);
		if (object_info == NULL) {
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			goto done;
		}
		status = pNtQueryObject(h, ObjectNameInformation, object_info, return_length, &return_length);
	}
	if (status < 0) {
		debug3("NtQueryObject(ObjectNameInformation) failed with 0x%lx", status);
		goto done;
	}

	object_name = (UNICODE_STRING *)object_info;
	if (object_name->Buffer == NULL || object_name->Length == 0) {
		SetLastError(ERROR_INVALID_HANDLE);
		goto done;
	}

	chars_needed = object_name->Length / sizeof(wchar_t);
	device_path = calloc(chars_needed + 1, sizeof(wchar_t));
	if (device_path == NULL) {
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		goto done;
	}
	memcpy(device_path, object_name->Buffer, object_name->Length);
	device_path[chars_needed] = L'\0';

	if (_wcsnicmp(device_path, L"\\Device\\Mup\\", 12) == 0) {
		if (path_buf_len == 0) {
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
			goto done;
		}
		if (_snwprintf_s(path_buf, path_buf_len, _TRUNCATE, L"\\\\?\\UNC\\%ls", device_path + 12) < 0) {
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
			goto done;
		}
		ret = (DWORD)wcslen(path_buf);
		goto done;
	}
	if (_wcsnicmp(device_path, L"\\??\\UNC\\", 8) == 0) {
		if (path_buf_len == 0) {
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
			goto done;
		}
		if (_snwprintf_s(path_buf, path_buf_len, _TRUNCATE, L"\\\\?\\UNC\\%ls", device_path + 8) < 0) {
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
			goto done;
		}
		ret = (DWORD)wcslen(path_buf);
		goto done;
	}
	if (_wcsnicmp(device_path, L"\\??\\", 4) == 0) {
		if (path_buf_len == 0 || _snwprintf_s(path_buf, path_buf_len, _TRUNCATE, L"\\\\?\\%ls", device_path + 4) < 0) {
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
			goto done;
		}
		ret = (DWORD)wcslen(path_buf);
		goto done;
	}
	if (resolve_dos_path_from_device_path(device_path, dos_path, ARRAYSIZE(dos_path))) {
		if (path_buf_len == 0 || _snwprintf_s(path_buf, path_buf_len, _TRUNCATE, L"\\\\?\\%ls", dos_path) < 0) {
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
			goto done;
		}
		ret = (DWORD)wcslen(path_buf);
		goto done;
	}

	if (path_buf_len == 0) {
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		goto done;
	}
	path_buf[0] = L'\0';
	SetLastError(ERROR_CALL_NOT_IMPLEMENTED);

done:
	if (object_info != stack_buf && object_info != NULL)
		free(object_info);
	if (device_path != NULL)
		free(device_path);
	return ret;
}

static FARPROC
get_proc_address(HMODULE hm, const char *fn)
{
	if (hm == NULL) {
		debug3("GetProcAddress of %s failed with error %d.", fn, GetLastError());
	}
	FARPROC ret = GetProcAddress(hm, fn);
	if (!ret)
		debug3("GetProcAddress of %s failed with error %d.", fn, GetLastError());

	return ret;
}

BOOL
pCancelIoEx(HANDLE handle, LPOVERLAPPED overlapped)
{
	typedef BOOL (WINAPI *CancelIoExType)(HANDLE, LPOVERLAPPED);
	static CancelIoExType s_pCancelIoEx = NULL;
	static int s_init = 0;
	HMODULE hm = NULL;

	if (!s_init) {
		s_init = 1;
		if ((hm = load_kernel32()) != NULL)
			s_pCancelIoEx = (CancelIoExType)get_proc_address(hm, "CancelIoEx");
	}

	if (s_pCancelIoEx != NULL)
		return s_pCancelIoEx(handle, overlapped);

	if (overlapped != NULL) {
		SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
		return FALSE;
	}

	return CancelIo(handle);
}

BOOL
pCancelSynchronousIo(HANDLE handle)
{
	typedef BOOL (WINAPI *CancelSynchronousIoType)(HANDLE);
	static CancelSynchronousIoType s_pCancelSynchronousIo = NULL;
	static int s_init = 0;
	HMODULE hm = NULL;

	if (!s_init) {
		s_init = 1;
		if ((hm = load_kernel32()) != NULL)
			s_pCancelSynchronousIo = (CancelSynchronousIoType)get_proc_address(hm, "CancelSynchronousIo");
	}

	if (s_pCancelSynchronousIo != NULL)
		return s_pCancelSynchronousIo(handle);

	SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
	return FALSE;
}

BOOLEAN
pCreateSymbolicLinkW(LPCWSTR symlink_file_name, LPCWSTR target_file_name, DWORD flags)
{
	typedef BOOLEAN (WINAPI *CreateSymbolicLinkWType)(LPCWSTR, LPCWSTR, DWORD);
	static CreateSymbolicLinkWType s_pCreateSymbolicLinkW = NULL;
	static int s_init = 0;
	HMODULE hm = NULL;

	if (!s_init) {
		s_init = 1;
		if ((hm = load_kernel32()) != NULL)
			s_pCreateSymbolicLinkW = (CreateSymbolicLinkWType)get_proc_address(hm, "CreateSymbolicLinkW");
	}

	if (s_pCreateSymbolicLinkW != NULL)
		return s_pCreateSymbolicLinkW(symlink_file_name, target_file_name, flags);

	SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
	return FALSE;
}

DWORD
pGetFinalPathNameByHandleW(HANDLE handle, LPWSTR path_buf, DWORD path_buf_len, DWORD flags)
{
	typedef DWORD (WINAPI *GetFinalPathNameByHandleWType)(HANDLE, LPWSTR, DWORD, DWORD);
	static GetFinalPathNameByHandleWType s_pGetFinalPathNameByHandleW = NULL;
	static int s_init = 0;
	HMODULE hm = NULL;

	(void)flags;

	if (!s_init) {
		s_init = 1;
		if ((hm = load_kernel32()) != NULL)
			s_pGetFinalPathNameByHandleW = (GetFinalPathNameByHandleWType)get_proc_address(hm, "GetFinalPathNameByHandleW");
	}

	if (s_pGetFinalPathNameByHandleW != NULL)
		return s_pGetFinalPathNameByHandleW(handle, path_buf, path_buf_len, flags);

	return fallback_final_path_name_by_handle(handle, path_buf, path_buf_len);
}

ULONGLONG
pGetTickCount64(void)
{
	typedef ULONGLONG (WINAPI *GetTickCount64Type)(void);
	static GetTickCount64Type s_pGetTickCount64 = NULL;
	static int s_init = 0;
	HMODULE hm = NULL;
	static DWORD s_last_tick = 0;
	static ULONGLONG s_tick_base = 0;
	DWORD tick_now;

	if (!s_init) {
		s_init = 1;
		if ((hm = load_kernel32()) != NULL)
			s_pGetTickCount64 = (GetTickCount64Type)get_proc_address(hm, "GetTickCount64");
	}

	if (s_pGetTickCount64 != NULL)
		return s_pGetTickCount64();

	tick_now = GetTickCount();
	if (tick_now < s_last_tick)
		s_tick_base += (1ULL << 32);
	s_last_tick = tick_now;
	return s_tick_base + tick_now;
}

BOOL
pIsWindowsVistaOrGreater(void)
{
	OSVERSIONINFOEXW version_info;

	if (!get_os_version(&version_info))
		return FALSE;

	return version_info.dwMajorVersion >= 6;
}

BOOL
pIsWindows8OrGreater(void)
{
	OSVERSIONINFOEXW version_info;

	if (!get_os_version(&version_info))
		return FALSE;

	if (version_info.dwMajorVersion > 6)
		return TRUE;
	if (version_info.dwMajorVersion < 6)
		return FALSE;
	return version_info.dwMinorVersion >= 2;
}

LSTATUS
pRegGetValueW(HKEY hkey, LPCWSTR subkey, LPCWSTR value, DWORD flags, LPDWORD type, PVOID data, LPDWORD size)
{
	HKEY opened_key = NULL;
	LSTATUS status;
	DWORD reg_type = 0;
	DWORD query_type = 0;
	DWORD query_size = 0;
	wchar_t *tmp = NULL;
	DWORD access = KEY_QUERY_VALUE;

	if (flags & RRF_SUBKEY_WOW6464KEY)
		access |= KEY_WOW64_64KEY;
	if (flags & RRF_SUBKEY_WOW6432KEY)
		access |= KEY_WOW64_32KEY;

	if (subkey != NULL && *subkey != L'\0') {
		status = RegOpenKeyExW(hkey, subkey, 0, access, &opened_key);
		if (status != ERROR_SUCCESS)
			return status;
		hkey = opened_key;
	}

	status = RegQueryValueExW(hkey, value, 0, &reg_type, NULL, &query_size);
	if (status != ERROR_SUCCESS)
		goto done;

	if ((flags & RRF_RT_REG_SZ) != 0 &&
	    reg_type != REG_SZ && reg_type != REG_EXPAND_SZ)
	{
		status = ERROR_UNSUPPORTED_TYPE;
		goto done;
	}

	query_type = reg_type;
	if (type != NULL)
		*type = query_type;

	if (data == NULL) {
		*size = query_size;
		status = ERROR_SUCCESS;
		goto done;
	}

	if (size == NULL || *size < query_size) {
		if (size != NULL)
			*size = query_size;
		status = ERROR_MORE_DATA;
		goto done;
	}

	status = RegQueryValueExW(hkey, value, 0, &query_type, (LPBYTE)data, size);
	if (status != ERROR_SUCCESS)
		goto done;

	if ((flags & RRF_RT_REG_SZ) != 0 && query_type == REG_EXPAND_SZ && (flags & RRF_NOEXPAND) == 0) {
		DWORD expanded_chars = ExpandEnvironmentStringsW((LPCWSTR)data, NULL, 0);
		if (expanded_chars == 0) {
			status = GetLastError();
			goto done;
		}
		if (*size < expanded_chars * sizeof(wchar_t)) {
			*size = expanded_chars * sizeof(wchar_t);
			status = ERROR_MORE_DATA;
			goto done;
		}
		tmp = calloc(expanded_chars, sizeof(wchar_t));
		if (tmp == NULL) {
			status = ERROR_NOT_ENOUGH_MEMORY;
			goto done;
		}
		if (ExpandEnvironmentStringsW((LPCWSTR)data, tmp, expanded_chars) == 0) {
			status = GetLastError();
			goto done;
		}
		memcpy(data, tmp, expanded_chars * sizeof(wchar_t));
		*size = expanded_chars * sizeof(wchar_t);
		query_type = REG_SZ;
	}

	if (type != NULL)
		*type = query_type;

done:
	if (tmp != NULL)
		free(tmp);
	if (opened_key != NULL)
		RegCloseKey(opened_key);
	return status;
}

BOOL
pLogonUserExExW(wchar_t *user_name, wchar_t *domain, wchar_t *password, DWORD logon_type,
	DWORD logon_provider, PTOKEN_GROUPS token_groups, PHANDLE token, PSID *logon_sid,
	PVOID *profile_buffer, LPDWORD profile_length, PQUOTA_LIMITS quota_limits)
{
	HMODULE hm = NULL;

	typedef BOOL(WINAPI *LogonUserExExWType)(wchar_t*, wchar_t*, wchar_t*, DWORD, DWORD, PTOKEN_GROUPS, PHANDLE, PSID, PVOID, LPDWORD, PQUOTA_LIMITS);
	static LogonUserExExWType s_pLogonUserExExW = NULL;

	if (!s_pLogonUserExExW) {
		/* this API is typically found in sspicli, but this dll doesn't exist on some downlevel machines - we fallback to advapi32 then */
		if ((hm = load_sspicli()) == NULL &&
		    (hm = load_advapi32()) == NULL)
			return FALSE;

		if ((s_pLogonUserExExW = (LogonUserExExWType)get_proc_address(hm, "LogonUserExExW")) == NULL)
			return FALSE;
	}

	return s_pLogonUserExExW(user_name, domain, password, logon_type, logon_provider,
			token_groups, token, logon_sid, profile_buffer, profile_length, quota_limits);
}


BOOLEAN pTranslateNameW(LPCWSTR name,
	EXTENDED_NAME_FORMAT account_format,
	EXTENDED_NAME_FORMAT desired_name_format,
	LPWSTR translated_name,
	PULONG psize)
{
	HMODULE hm = NULL;
	typedef BOOLEAN(SEC_ENTRY *TranslateNameWType)(LPCWSTR, EXTENDED_NAME_FORMAT, EXTENDED_NAME_FORMAT, LPWSTR, PULONG);
	static TranslateNameWType s_pTranslateNameW = NULL;

	if (!s_pTranslateNameW) {
		if ((hm = load_secur32()) == NULL)
			return FALSE;

		if ((s_pTranslateNameW = (TranslateNameWType)get_proc_address(hm, "TranslateNameW")) == NULL)
			return FALSE;
	}
	return s_pTranslateNameW(name, account_format, desired_name_format, translated_name, psize);
}

NTSTATUS pLsaOpenPolicy(PLSA_UNICODE_STRING system_name,
	PLSA_OBJECT_ATTRIBUTES attrib,
	ACCESS_MASK access,
	PLSA_HANDLE handle)
{
	HMODULE hm = NULL;
	typedef NTSTATUS(NTAPI *LsaOpenPolicyType)(PLSA_UNICODE_STRING, PLSA_OBJECT_ATTRIBUTES, ACCESS_MASK, PLSA_HANDLE);
	static LsaOpenPolicyType s_pLsaOpenPolicy = NULL;
	if (!s_pLsaOpenPolicy) {
		if ((hm = load_api_security_lsapolicy()) == NULL &&
			((hm = load_advapi32()) == NULL))
			return STATUS_ASSERTION_FAILURE;
		if ((s_pLsaOpenPolicy = (LsaOpenPolicyType)get_proc_address(hm, "LsaOpenPolicy")) == NULL)
			return STATUS_ASSERTION_FAILURE;
	}
	return s_pLsaOpenPolicy(system_name, attrib, access, handle);
}
NTSTATUS pLsaFreeMemory(PVOID buffer)
{
	HMODULE hm = NULL;
	typedef NTSTATUS(NTAPI *LsaFreeMemoryType)(PVOID);
	static LsaFreeMemoryType s_pLsaFreeMemory = NULL;
	if (!s_pLsaFreeMemory) {
		if ((hm = load_api_security_lsapolicy()) == NULL &&
			((hm = load_advapi32()) == NULL))
			return STATUS_ASSERTION_FAILURE;
		if ((s_pLsaFreeMemory = (LsaFreeMemoryType)get_proc_address(hm, "LsaFreeMemory")) == NULL)
			return STATUS_ASSERTION_FAILURE;
	}
	return s_pLsaFreeMemory(buffer);
}
NTSTATUS pLsaAddAccountRights(LSA_HANDLE lsa_h,
	PSID psid,
	PLSA_UNICODE_STRING rights,
	ULONG num_rights)
{
	HMODULE hm = NULL;
	typedef NTSTATUS(NTAPI *LsaAddAccountRightsType)(LSA_HANDLE, PSID, PLSA_UNICODE_STRING, ULONG);
	static LsaAddAccountRightsType s_pLsaAddAccountRights = NULL;
	if (!s_pLsaAddAccountRights) {
		if ((hm = load_api_security_lsapolicy()) == NULL &&
			((hm = load_advapi32()) == NULL))
			return STATUS_ASSERTION_FAILURE;
		if ((s_pLsaAddAccountRights = (LsaAddAccountRightsType)get_proc_address(hm, "LsaAddAccountRights")) == NULL)
			return STATUS_ASSERTION_FAILURE;
	}

	return s_pLsaAddAccountRights(lsa_h, psid, rights, num_rights);
}

NTSTATUS pLsaRemoveAccountRights(LSA_HANDLE lsa_h,
	PSID psid,
	BOOLEAN all_rights,
	PLSA_UNICODE_STRING rights,
	ULONG num_rights)
{
	HMODULE hm = NULL;
	typedef NTSTATUS(NTAPI *LsaRemoveAccountRightsType)(LSA_HANDLE, PSID, BOOLEAN, PLSA_UNICODE_STRING, ULONG);
	static LsaRemoveAccountRightsType s_pLsaRemoveAccountRights = NULL;
	if (!s_pLsaRemoveAccountRights) {
		if ((hm = load_api_security_lsapolicy()) == NULL &&
			((hm = load_advapi32()) == NULL))
			return STATUS_ASSERTION_FAILURE;
		if ((s_pLsaRemoveAccountRights = (LsaRemoveAccountRightsType)get_proc_address(hm, "LsaRemoveAccountRights")) == NULL)
			return STATUS_ASSERTION_FAILURE;
	}

	return s_pLsaRemoveAccountRights(lsa_h, psid, all_rights, rights, num_rights);
}

ULONG pRtlNtStatusToDosError(NTSTATUS status)
{
	HMODULE hm = NULL;
	typedef ULONG(NTAPI *RtlNtStatusToDosErrorType)(NTSTATUS);
	static RtlNtStatusToDosErrorType s_pRtlNtStatusToDosError = NULL;

	if (!s_pRtlNtStatusToDosError) {
		if ((hm = load_ntdll()) == NULL)
			return STATUS_ASSERTION_FAILURE;

		if ((s_pRtlNtStatusToDosError = (RtlNtStatusToDosErrorType)get_proc_address(hm, "RtlNtStatusToDosError")) == NULL)
			return STATUS_ASSERTION_FAILURE;
	}
	return pRtlNtStatusToDosError(status);
}

NTSTATUS pLsaClose(LSA_HANDLE lsa_h)
{
	HMODULE hm = NULL;
	typedef NTSTATUS(NTAPI *LsaCloseType)(LSA_HANDLE);
	static LsaCloseType s_pLsaClose = NULL;

	if (!s_pLsaClose) {
		if ((hm = load_api_security_lsapolicy()) == NULL &&
			((hm = load_advapi32()) == NULL))
			return STATUS_ASSERTION_FAILURE;

		if ((s_pLsaClose = (LsaCloseType)get_proc_address(hm, "LsaClose")) == NULL)
			return STATUS_ASSERTION_FAILURE;
	}

	return s_pLsaClose(lsa_h);
}
