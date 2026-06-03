/*
 * Diagnostic full LSA authentication package for the Windows XP
 * public-key-token bring-up path.
 *
 * Build from the parent build directory:
 *   i686-w64-mingw32-gcc -Wall -Wextra -O0 -g -shared \
 *       -o win32-lsa-auth-package-probe.dll \
 *       ../openssh-portable/regress/misc/win32-lsa-auth-package-probe.c \
 *       ../openssh-portable/regress/misc/win32-lsa-auth-package-probe.def \
 *       -lnetapi32 -ladvapi32
 *
 * This diagnostic package is intentionally permissive once it receives the
 * expected probe magic. Its purpose is only to prove that XP can load a custom
 * authentication package, call LsaApLogonUser, and return a usable local-user
 * token. Do not wire this into sshd or leave it installed outside a controlled
 * probe.
 */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#define SECURITY_WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ntsecapi.h>
#include <sspi.h>
#include <ntsecpkg.h>
#include <lm.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif
#ifndef STATUS_LOGON_FAILURE
#define STATUS_LOGON_FAILURE ((NTSTATUS)0xC000006DL)
#endif
#ifndef STATUS_ACCOUNT_DISABLED
#define STATUS_ACCOUNT_DISABLED ((NTSTATUS)0xC0000072L)
#endif
#ifndef STATUS_ACCOUNT_RESTRICTION
#define STATUS_ACCOUNT_RESTRICTION ((NTSTATUS)0xC000006EL)
#endif
#ifndef STATUS_INSUFFICIENT_RESOURCES
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL)
#endif
#ifndef STATUS_NO_SUCH_USER
#define STATUS_NO_SUCH_USER ((NTSTATUS)0xC0000064L)
#endif
#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)
#endif

#define OPENSSH_LSA_AUTH_PROBE_PACKAGE "OpenSSHLsaProbe"
#define OPENSSH_LSA_AUTH_PROBE_MAGIC 0x4f535841UL /* "OSXA" */
#define OPENSSH_LSA_AUTH_PROBE_VERSION 1
#define OPENSSH_LSA_PROBE_GROUP_ATTRS \
	(SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED)

typedef struct _OPENSSH_LSA_AUTH_PROBE_REQUEST {
	ULONG magic;
	ULONG version;
	ULONG flags;
	ULONG user_bytes;
	ULONG domain_bytes;
	/* WCHAR user[], domain[] follow. */
} OPENSSH_LSA_AUTH_PROBE_REQUEST;

static PLSA_DISPATCH_TABLE lsa_dispatch;
static ULONG lsa_package_id;

typedef struct _LSA_TOKEN_BUILD {
	PLSA_TOKEN_INFORMATION_V1 token;
	PVOID block;
	LPBYTE cursor;
	LPBYTE end;
} LSA_TOKEN_BUILD;

static void
tracef(const char *fmt, ...)
{
	HANDLE h;
	char buf[512];
	DWORD len, written;
	va_list ap;

	h = CreateFileA("C:\\chi\\win32-lsa-auth-package-probe.log",
	    FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
	    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return;
	va_start(ap, fmt);
	len = (DWORD)vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (len >= sizeof(buf))
		len = sizeof(buf) - 1;
	buf[len++] = '\r';
	if (len < sizeof(buf))
		buf[len++] = '\n';
	WriteFile(h, buf, len, &written, NULL);
	CloseHandle(h);
}

static PVOID
lsa_alloc_zero(ULONG len)
{
	PVOID ret;

	if (lsa_dispatch == NULL || lsa_dispatch->AllocateLsaHeap == NULL ||
	    len == 0)
		return NULL;
	ret = lsa_dispatch->AllocateLsaHeap(len);
	if (ret != NULL)
		memset(ret, 0, len);
	return ret;
}

static void
lsa_free(PVOID ptr)
{
	if (ptr != NULL && lsa_dispatch != NULL &&
	    lsa_dispatch->FreeLsaHeap != NULL)
		lsa_dispatch->FreeLsaHeap(ptr);
}

static void *
build_alloc(LSA_TOKEN_BUILD *build, DWORD len, DWORD align)
{
	ULONG_PTR p;

	if (align == 0)
		align = sizeof(void *);
	p = (ULONG_PTR)build->cursor;
	p = (p + align - 1) & ~(ULONG_PTR)(align - 1);
	if (p < (ULONG_PTR)build->cursor || p + len < p ||
	    p + len > (ULONG_PTR)build->end)
		return NULL;
	build->cursor = (LPBYTE)(p + len);
	memset((void *)p, 0, len);
	return (void *)p;
}

static DWORD
sid_length(PSID sid)
{
	return sid == NULL ? 0 : GetLengthSid(sid);
}

static int
copy_sid_to_build(LSA_TOKEN_BUILD *build, PSID src, PSID *dst)
{
	DWORD len = sid_length(src);

	*dst = NULL;
	if (len == 0)
		return 1;
	*dst = build_alloc(build, len, sizeof(DWORD));
	if (*dst == NULL)
		return 1;
	if (!CopySid(len, *dst, src))
		return 1;
	return 0;
}

static int
copy_sid_to_heap(PSID src, PSID *dst)
{
	DWORD len = sid_length(src);

	*dst = NULL;
	if (len == 0)
		return 1;
	*dst = calloc(1, len);
	if (*dst == NULL)
		return 1;
	if (!CopySid(len, *dst, src)) {
		free(*dst);
		*dst = NULL;
		return 1;
	}
	return 0;
}

static int
alloc_sid_from_rids(SID_IDENTIFIER_AUTHORITY authority, BYTE subauth_count,
    const DWORD *rids, PSID *sid)
{
	DWORD rid[8] = { 0 };
	PSID tmp = NULL;
	int ret;
	BYTE i;

	*sid = NULL;
	if (subauth_count == 0 || subauth_count > 8 || rids == NULL)
		return 1;
	for (i = 0; i < subauth_count; i++)
		rid[i] = rids[i];
	if (!AllocateAndInitializeSid(&authority, subauth_count, rid[0],
	    rid[1], rid[2], rid[3], rid[4], rid[5], rid[6], rid[7], &tmp))
		return 1;
	ret = copy_sid_to_heap(tmp, sid);
	FreeSid(tmp);
	return ret;
}

static int
alloc_well_known_sid(SID_IDENTIFIER_AUTHORITY authority, DWORD rid0, PSID *sid)
{
	return alloc_sid_from_rids(authority, 1, &rid0, sid);
}

static int
alloc_well_known_sid2(SID_IDENTIFIER_AUTHORITY authority, DWORD rid0,
    DWORD rid1, PSID *sid)
{
	DWORD rids[2];

	rids[0] = rid0;
	rids[1] = rid1;
	return alloc_sid_from_rids(authority, 2, rids, sid);
}

static int
alloc_domain_rid_sid(PSID user_sid, DWORD rid, PSID *sid)
{
	SID_IDENTIFIER_AUTHORITY authority;
	DWORD subauth_count, i, subauth[8] = { 0 };
	PSID tmp = NULL;
	int ret;

	*sid = NULL;
	if (!IsValidSid(user_sid))
		return 1;
	subauth_count = *GetSidSubAuthorityCount(user_sid);
	if (subauth_count == 0 || subauth_count > 8)
		return 1;
	authority = *GetSidIdentifierAuthority(user_sid);
	for (i = 0; i < subauth_count - 1; i++)
		subauth[i] = *GetSidSubAuthority(user_sid, i);
	subauth[subauth_count - 1] = rid;
	if (!AllocateAndInitializeSid(&authority, (BYTE)subauth_count,
	    subauth[0], subauth[1], subauth[2], subauth[3], subauth[4],
	    subauth[5], subauth[6], subauth[7], &tmp))
		return 1;
	ret = copy_sid_to_heap(tmp, sid);
	FreeSid(tmp);
	return ret;
}

static int
lookup_account_sid_w(const wchar_t *name, PSID *sid)
{
	DWORD sid_len = 0, domain_len = 0;
	SID_NAME_USE use;
	wchar_t *domain = NULL;

	*sid = NULL;
	LookupAccountNameW(NULL, name, NULL, &sid_len, NULL, &domain_len, &use);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || sid_len == 0)
		return 1;
	*sid = calloc(1, sid_len);
	domain = malloc(domain_len * sizeof(wchar_t));
	if (*sid == NULL || domain == NULL)
		goto fail;
	if (!LookupAccountNameW(NULL, name, *sid, &sid_len, domain,
	    &domain_len, &use))
		goto fail;
	free(domain);
	return 0;

fail:
	free(domain);
	free(*sid);
	*sid = NULL;
	return 1;
}

static wchar_t *
dup_request_string(const BYTE *base, ULONG request_len, ULONG offset,
    ULONG bytes)
{
	wchar_t *ret;

	if (bytes == 0 || (bytes % sizeof(wchar_t)) != 0 ||
	    offset > request_len || bytes > request_len - offset)
		return NULL;
	ret = calloc((bytes / sizeof(wchar_t)) + 1, sizeof(wchar_t));
	if (ret == NULL)
		return NULL;
	memcpy(ret, base + offset, bytes);
	ret[bytes / sizeof(wchar_t)] = L'\0';
	return ret;
}

static NTSTATUS
parse_probe_request(OPENSSH_LSA_AUTH_PROBE_REQUEST *request, ULONG request_len,
    wchar_t **user_out, wchar_t **domain_out)
{
	ULONG off;

	*user_out = NULL;
	*domain_out = NULL;
	if (request == NULL || request_len < sizeof(*request) ||
	    request->magic != OPENSSH_LSA_AUTH_PROBE_MAGIC ||
	    request->version != OPENSSH_LSA_AUTH_PROBE_VERSION)
		return STATUS_INVALID_PARAMETER;
	off = sizeof(*request);
	*user_out = dup_request_string((const BYTE *)request, request_len, off,
	    request->user_bytes);
	off += request->user_bytes;
	*domain_out = dup_request_string((const BYTE *)request, request_len, off,
	    request->domain_bytes);
	if (*user_out == NULL || *domain_out == NULL) {
		free(*user_out);
		free(*domain_out);
		*user_out = NULL;
		*domain_out = NULL;
		return STATUS_INVALID_PARAMETER;
	}
	return STATUS_SUCCESS;
}

static int
domain_is_local(const wchar_t *domain)
{
	wchar_t computer[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD len = MAX_COMPUTERNAME_LENGTH + 1;

	if (domain == NULL || domain[0] == L'\0' || wcscmp(domain, L".") == 0)
		return 1;
	if (GetComputerNameW(computer, &len) && _wcsicmp(domain, computer) == 0)
		return 1;
	return 0;
}

static int
append_group_sid(PSID **sids, DWORD *count, DWORD *capacity, PSID sid)
{
	PSID *next;

	if (*count == *capacity) {
		DWORD new_capacity = *capacity == 0 ? 8 : *capacity * 2;
		next = realloc(*sids, new_capacity * sizeof(**sids));
		if (next == NULL)
			return 1;
		*sids = next;
		*capacity = new_capacity;
	}
	(*sids)[(*count)++] = sid;
	return 0;
}

static void
free_group_sid_array(PSID *sids, DWORD count)
{
	DWORD i;

	if (sids == NULL)
		return;
	for (i = 0; i < count; i++)
		free(sids[i]);
	free(sids);
}

static NTSTATUS
collect_group_sids(const wchar_t *user, PSID user_sid, PSID **out_sids,
    DWORD *out_count)
{
	SID_IDENTIFIER_AUTHORITY world = SECURITY_WORLD_SID_AUTHORITY;
	SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
	LOCALGROUP_USERS_INFO_0 *local_groups = NULL;
	GROUP_USERS_INFO_0 *global_groups = NULL;
	DWORD local_count = 0, local_total = 0, global_count = 0;
	DWORD global_total = 0, count = 0, capacity = 0, i;
	PSID *sids = NULL, sid;
	NET_API_STATUS net_status;

	*out_sids = NULL;
	*out_count = 0;

	if (alloc_well_known_sid(world, SECURITY_WORLD_RID, &sid) != 0 ||
	    append_group_sid(&sids, &count, &capacity, sid) != 0)
		goto nomem;
	if (alloc_well_known_sid(nt, SECURITY_AUTHENTICATED_USER_RID,
	    &sid) != 0 ||
	    append_group_sid(&sids, &count, &capacity, sid) != 0)
		goto nomem;
	if (alloc_well_known_sid(nt, SECURITY_LOCAL_RID, &sid) != 0 ||
	    append_group_sid(&sids, &count, &capacity, sid) != 0)
		goto nomem;
	if (alloc_well_known_sid(nt, SECURITY_NETWORK_RID, &sid) != 0 ||
	    append_group_sid(&sids, &count, &capacity, sid) != 0)
		goto nomem;
	if (alloc_domain_rid_sid(user_sid, DOMAIN_GROUP_RID_USERS, &sid) == 0) {
		if (append_group_sid(&sids, &count, &capacity, sid) != 0)
			goto nomem;
	}

	net_status = NetUserGetLocalGroups(NULL, user, 0, LG_INCLUDE_INDIRECT,
	    (LPBYTE *)&local_groups, MAX_PREFERRED_LENGTH, &local_count,
	    &local_total);
	if (net_status == NERR_Success) {
		for (i = 0; i < local_count; i++) {
			if (lookup_account_sid_w(local_groups[i].lgrui0_name,
			    &sid) == 0 &&
			    append_group_sid(&sids, &count, &capacity, sid) != 0)
				goto nomem;
		}
	} else {
		tracef("NetUserGetLocalGroups failed: %lu", net_status);
	}

	net_status = NetUserGetGroups(NULL, user, 0, (LPBYTE *)&global_groups,
	    MAX_PREFERRED_LENGTH, &global_count, &global_total);
	if (net_status == NERR_Success) {
		for (i = 0; i < global_count; i++) {
			if (lookup_account_sid_w(global_groups[i].grui0_name,
			    &sid) == 0 &&
			    append_group_sid(&sids, &count, &capacity, sid) != 0)
				goto nomem;
		}
	} else {
		tracef("NetUserGetGroups failed: %lu", net_status);
	}

	NetApiBufferFree(local_groups);
	NetApiBufferFree(global_groups);
	*out_sids = sids;
	*out_count = count;
	return STATUS_SUCCESS;

nomem:
	NetApiBufferFree(local_groups);
	NetApiBufferFree(global_groups);
	free_group_sid_array(sids, count);
	return STATUS_INSUFFICIENT_RESOURCES;
}

static NTSTATUS
collect_privileges(PSID user_sid, LUID_AND_ATTRIBUTES **out_privs,
    DWORD *out_count)
{
	LSA_OBJECT_ATTRIBUTES oa;
	LSA_HANDLE policy = NULL;
	PLSA_UNICODE_STRING rights = NULL;
	ULONG right_count = 0, i, count = 0;
	LUID_AND_ATTRIBUTES *privs = NULL;
	NTSTATUS status;

	*out_privs = NULL;
	*out_count = 0;
	memset(&oa, 0, sizeof(oa));
	oa.Length = sizeof(oa);
	status = LsaOpenPolicy(NULL, &oa,
	    POLICY_VIEW_LOCAL_INFORMATION | POLICY_LOOKUP_NAMES, &policy);
	if (status != STATUS_SUCCESS) {
		tracef("LsaOpenPolicy failed: 0x%08lx", (unsigned long)status);
		return STATUS_SUCCESS;
	}
	status = LsaEnumerateAccountRights(policy, user_sid, &rights,
	    &right_count);
	if (status == (NTSTATUS)0xC0000034L) /* STATUS_OBJECT_NAME_NOT_FOUND */
		status = STATUS_SUCCESS;
	if (status != STATUS_SUCCESS) {
		tracef("LsaEnumerateAccountRights failed: 0x%08lx",
		    (unsigned long)status);
		goto done;
	}
	if (right_count == 0)
		goto done;
	privs = calloc(right_count, sizeof(*privs));
	if (privs == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}
	for (i = 0; i < right_count; i++) {
		wchar_t name[128];
		ULONG chars = rights[i].Length / sizeof(wchar_t);
		if (chars >= (sizeof(name) / sizeof(name[0])))
			continue;
		memcpy(name, rights[i].Buffer, rights[i].Length);
		name[chars] = L'\0';
		if (LookupPrivilegeValueW(NULL, name, &privs[count].Luid)) {
			privs[count].Attributes = SE_PRIVILEGE_ENABLED;
			count++;
		}
	}
	*out_privs = privs;
	*out_count = count;
	privs = NULL;

done:
	free(privs);
	if (rights != NULL)
		LsaFreeMemory(rights);
	if (policy != NULL)
		LsaClose(policy);
	return status;
}

static int
alloc_lsa_unicode_string(const wchar_t *s, PLSA_UNICODE_STRING *out)
{
	PLSA_UNICODE_STRING ret;
	size_t chars, bytes;

	*out = NULL;
	if (s == NULL)
		s = L"";
	chars = wcslen(s);
	bytes = chars * sizeof(wchar_t);
	if (bytes > USHRT_MAX - sizeof(wchar_t))
		return 1;
	ret = lsa_alloc_zero((ULONG)(sizeof(*ret) + bytes + sizeof(wchar_t)));
	if (ret == NULL)
		return 1;
	ret->Length = (USHORT)bytes;
	ret->MaximumLength = (USHORT)(bytes + sizeof(wchar_t));
	ret->Buffer = (PWSTR)(ret + 1);
	memcpy(ret->Buffer, s, bytes);
	*out = ret;
	return 0;
}

static NTSTATUS
build_token_information(const wchar_t *user, USER_INFO_4 *info,
    PLSA_TOKEN_INFORMATION_TYPE token_type, PVOID *token_info)
{
	LSA_TOKEN_BUILD build;
	PSID *group_sids = NULL;
	DWORD group_count = 0, group_size, i;
	LUID_AND_ATTRIBUTES *privs = NULL;
	DWORD priv_count = 0, priv_size;
	NTSTATUS status;
	PTOKEN_GROUPS groups;
	PTOKEN_PRIVILEGES privileges;
	SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
	PSID primary_group = NULL;
	DWORD total;

	memset(&build, 0, sizeof(build));
	*token_info = NULL;
	*token_type = LsaTokenInformationNull;

	status = collect_group_sids(user, info->usri4_user_sid, &group_sids,
	    &group_count);
	if (status != STATUS_SUCCESS)
		return status;
	status = collect_privileges(info->usri4_user_sid, &privs, &priv_count);
	if (status != STATUS_SUCCESS)
		goto done;
	if (alloc_domain_rid_sid(info->usri4_user_sid,
	    info->usri4_primary_group_id != 0 ? info->usri4_primary_group_id :
	    DOMAIN_GROUP_RID_USERS, &primary_group) != 0 &&
	    alloc_well_known_sid2(nt, SECURITY_BUILTIN_DOMAIN_RID,
	    DOMAIN_ALIAS_RID_USERS, &primary_group) != 0) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}

	group_size = sizeof(DWORD) + group_count * sizeof(SID_AND_ATTRIBUTES);
	priv_size = sizeof(DWORD) + priv_count * sizeof(LUID_AND_ATTRIBUTES);
	total = sizeof(LSA_TOKEN_INFORMATION_V1) + group_size + priv_size +
	    sid_length(info->usri4_user_sid) * 2 + sid_length(primary_group);
	for (i = 0; i < group_count; i++)
		total += sid_length(group_sids[i]);
	total += 4096;

	build.block = lsa_alloc_zero(total);
	if (build.block == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}
	build.cursor = build.block;
	build.end = build.cursor + total;
	build.token = build_alloc(&build, sizeof(*build.token), sizeof(void *));
	if (build.token == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}

	build.token->ExpirationTime.LowPart = 0xffffffffUL;
	build.token->ExpirationTime.HighPart = 0x7fffffffL;
	if (copy_sid_to_build(&build, info->usri4_user_sid,
	    &build.token->User.User.Sid) != 0 ||
	    copy_sid_to_build(&build, info->usri4_user_sid,
	    &build.token->Owner.Owner) != 0 ||
	    copy_sid_to_build(&build, primary_group,
	    &build.token->PrimaryGroup.PrimaryGroup) != 0) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}
	build.token->User.User.Attributes = 0;

	groups = build_alloc(&build, group_size, sizeof(void *));
	if (groups == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}
	groups->GroupCount = group_count;
	for (i = 0; i < group_count; i++) {
		if (copy_sid_to_build(&build, group_sids[i],
		    &groups->Groups[i].Sid) != 0) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto done;
		}
		groups->Groups[i].Attributes = OPENSSH_LSA_PROBE_GROUP_ATTRS;
	}
	build.token->Groups = groups;

	privileges = build_alloc(&build, priv_size, sizeof(void *));
	if (privileges == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}
	privileges->PrivilegeCount = priv_count;
	for (i = 0; i < priv_count; i++)
		privileges->Privileges[i] = privs[i];
	build.token->Privileges = privileges;

	build.token->DefaultDacl.DefaultDacl = NULL;
	*token_type = LsaTokenInformationV1;
	*token_info = build.token;
	build.block = NULL;
	status = STATUS_SUCCESS;

done:
	lsa_free(build.block);
	free_group_sid_array(group_sids, group_count);
	free(privs);
	free(primary_group);
	return status;
}

static NTSTATUS
alloc_lsa_string(const char *s, PLSA_STRING *out)
{
	PLSA_STRING ret;
	size_t len;

	if (lsa_dispatch == NULL || lsa_dispatch->AllocateLsaHeap == NULL ||
	    s == NULL || out == NULL)
		return STATUS_INVALID_PARAMETER;
	len = strlen(s);
	if (len > USHRT_MAX)
		return STATUS_INVALID_PARAMETER;
	ret = lsa_dispatch->AllocateLsaHeap((ULONG)(sizeof(*ret) + len + 1));
	if (ret == NULL)
		return STATUS_INVALID_PARAMETER;
	memset(ret, 0, sizeof(*ret) + len + 1);
	ret->Length = (USHORT)len;
	ret->MaximumLength = (USHORT)(len + 1);
	ret->Buffer = (PCHAR)(ret + 1);
	memcpy(ret->Buffer, s, len + 1);
	*out = ret;
	return STATUS_SUCCESS;
}

BOOL WINAPI
DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
	(void)instance;
	(void)reason;
	(void)reserved;
	return TRUE;
}

NTSTATUS NTAPI
LsaApInitializePackage(ULONG authentication_package_id,
    PLSA_DISPATCH_TABLE dispatch_table, PLSA_STRING database,
    PLSA_STRING confidentiality, PLSA_STRING *authentication_package_name)
{
	(void)database;
	(void)confidentiality;

	tracef("InitializePackage id=%lu dispatch=%p",
	    authentication_package_id, dispatch_table);
	if (dispatch_table == NULL || authentication_package_name == NULL)
		return STATUS_INVALID_PARAMETER;
	lsa_dispatch = dispatch_table;
	lsa_package_id = authentication_package_id;
	return alloc_lsa_string(OPENSSH_LSA_AUTH_PROBE_PACKAGE,
	    authentication_package_name);
}

NTSTATUS NTAPI
LsaApLogonUser(PLSA_CLIENT_REQUEST client_request,
    SECURITY_LOGON_TYPE logon_type, PVOID authentication_information,
    PVOID client_authentication_base, ULONG authentication_information_length,
    PVOID *profile_buffer, PULONG profile_buffer_length, PLUID logon_id,
    PNTSTATUS sub_status, PLSA_TOKEN_INFORMATION_TYPE token_information_type,
    PVOID *token_information, PLSA_UNICODE_STRING *account_name,
    PLSA_UNICODE_STRING *authenticating_authority)
{
	OPENSSH_LSA_AUTH_PROBE_REQUEST *request = NULL;
	ULONG request_len = authentication_information_length;
	wchar_t *user = NULL, *domain = NULL;
	USER_INFO_4 *user_info = NULL;
	NTSTATUS status = STATUS_LOGON_FAILURE;
	NET_API_STATUS net_status;
	int logon_session_created = 0;

	(void)client_request;
	(void)client_authentication_base;

	tracef("LogonUser package_id=%lu type=%lu auth=%p len=%lu",
	    lsa_package_id, (ULONG)logon_type, authentication_information,
	    authentication_information_length);

	if (profile_buffer != NULL)
		*profile_buffer = NULL;
	if (profile_buffer_length != NULL)
		*profile_buffer_length = 0;
	if (logon_id != NULL) {
		logon_id->LowPart = 0;
		logon_id->HighPart = 0;
	}
	if (token_information_type != NULL)
		*token_information_type = LsaTokenInformationNull;
	if (token_information != NULL)
		*token_information = NULL;
	if (account_name != NULL)
		*account_name = NULL;
	if (authenticating_authority != NULL)
		*authenticating_authority = NULL;

	if (sub_status != NULL)
		*sub_status = STATUS_LOGON_FAILURE;

	if (authentication_information != NULL &&
	    request_len >= sizeof(*request) && request_len <= 4096) {
		request = authentication_information;
		tracef("request magic=0x%08lx version=%lu "
		    "user_bytes=%lu domain_bytes=%lu",
		    (unsigned long)request->magic, request->version,
		    request->user_bytes, request->domain_bytes);
	}

	status = parse_probe_request(request, request_len, &user, &domain);
	if (status != STATUS_SUCCESS) {
		tracef("parse request failed: 0x%08lx", (unsigned long)status);
		goto done;
	}
	tracef("request user=%ls domain=%ls", user, domain);
	if (!domain_is_local(domain)) {
		tracef("reject non-local domain");
		status = STATUS_ACCOUNT_RESTRICTION;
		goto done;
	}
	net_status = NetUserGetInfo(NULL, user, 4, (LPBYTE *)&user_info);
	if (net_status != NERR_Success) {
		tracef("NetUserGetInfo failed: %lu", net_status);
		status = STATUS_NO_SUCH_USER;
		goto done;
	}
	if ((user_info->usri4_flags & UF_ACCOUNTDISABLE) != 0) {
		tracef("reject disabled account");
		status = STATUS_ACCOUNT_DISABLED;
		goto done;
	}

	status = build_token_information(user, user_info, token_information_type,
	    token_information);
	if (status != STATUS_SUCCESS) {
		tracef("build token failed: 0x%08lx", (unsigned long)status);
		goto done;
	}
	if (account_name != NULL &&
	    alloc_lsa_unicode_string(user, account_name) != 0) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}
	if (authenticating_authority != NULL &&
	    alloc_lsa_unicode_string(domain_is_local(domain) ? L"." : domain,
	    authenticating_authority) != 0) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}
	if (logon_id == NULL || lsa_dispatch == NULL ||
	    lsa_dispatch->CreateLogonSession == NULL) {
		status = STATUS_INVALID_PARAMETER;
		goto done;
	}
	if (AllocateLocallyUniqueId(logon_id) == FALSE) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}
	status = lsa_dispatch->CreateLogonSession(logon_id);
	if (status != STATUS_SUCCESS) {
		tracef("CreateLogonSession failed: 0x%08lx luid=%lu:%ld",
		    (unsigned long)status, logon_id->LowPart,
		    logon_id->HighPart);
		goto done;
	}
	logon_session_created = 1;
	if (sub_status != NULL)
		*sub_status = STATUS_SUCCESS;
	tracef("LogonUser returning STATUS_SUCCESS");
	status = STATUS_SUCCESS;

done:
	if (status != STATUS_SUCCESS) {
		if (sub_status != NULL)
			*sub_status = status;
		if (token_information_type != NULL)
			*token_information_type = LsaTokenInformationNull;
		if (token_information != NULL) {
			lsa_free(*token_information);
			*token_information = NULL;
		}
		if (account_name != NULL) {
			lsa_free(*account_name);
			*account_name = NULL;
		}
		if (authenticating_authority != NULL) {
			lsa_free(*authenticating_authority);
			*authenticating_authority = NULL;
		}
		if (logon_session_created && lsa_dispatch != NULL &&
		    lsa_dispatch->DeleteLogonSession != NULL)
			lsa_dispatch->DeleteLogonSession(logon_id);
		tracef("LogonUser returning failure: 0x%08lx",
		    (unsigned long)status);
	}
	NetApiBufferFree(user_info);
	free(user);
	free(domain);
	return status;
}

NTSTATUS NTAPI
LsaApCallPackage(PLSA_CLIENT_REQUEST client_request,
    PVOID protocol_submit_buffer, PVOID client_buffer_base,
    ULONG submit_buffer_length, PVOID *protocol_return_buffer,
    PULONG return_buffer_length, PNTSTATUS protocol_status)
{
	(void)client_request;
	(void)protocol_submit_buffer;
	(void)client_buffer_base;
	(void)submit_buffer_length;
	if (protocol_return_buffer != NULL)
		*protocol_return_buffer = NULL;
	if (return_buffer_length != NULL)
		*return_buffer_length = 0;
	if (protocol_status != NULL)
		*protocol_status = STATUS_NOT_IMPLEMENTED;
	tracef("CallPackage returning STATUS_NOT_IMPLEMENTED");
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI
LsaApCallPackageUntrusted(PLSA_CLIENT_REQUEST client_request,
    PVOID protocol_submit_buffer, PVOID client_buffer_base,
    ULONG submit_buffer_length, PVOID *protocol_return_buffer,
    PULONG return_buffer_length, PNTSTATUS protocol_status)
{
	return LsaApCallPackage(client_request, protocol_submit_buffer,
	    client_buffer_base, submit_buffer_length, protocol_return_buffer,
	    return_buffer_length, protocol_status);
}

NTSTATUS NTAPI
LsaApCallPackagePassthrough(PLSA_CLIENT_REQUEST client_request,
    PVOID protocol_submit_buffer, PVOID client_buffer_base,
    ULONG submit_buffer_length, PVOID *protocol_return_buffer,
    PULONG return_buffer_length, PNTSTATUS protocol_status)
{
	return LsaApCallPackage(client_request, protocol_submit_buffer,
	    client_buffer_base, submit_buffer_length, protocol_return_buffer,
	    return_buffer_length, protocol_status);
}

VOID NTAPI
LsaApLogonTerminated(PLUID logon_id)
{
	tracef("LogonTerminated %lu:%ld",
	    logon_id == NULL ? 0 : logon_id->LowPart,
	    logon_id == NULL ? 0 : logon_id->HighPart);
}
