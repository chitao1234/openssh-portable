/*
 * OpenSSH LSA authentication package for Windows XP public-key logon.
 *
 * XP lacks the S4U logon path used by newer Windows releases. This package
 * gives trusted sshd a narrow replacement: sshd first asks LSASS to create a
 * short-lived one-time grant for an existing local account, then immediately
 * redeems that grant via LsaLogonUser to receive a token.
 */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#define SECURITY_WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <ntsecapi.h>
#include <sspi.h>
#include <ntsecpkg.h>
#include <lm.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "openssh_lsa_auth.h"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif
#ifndef STATUS_LOGON_FAILURE
#define STATUS_LOGON_FAILURE ((NTSTATUS)0xC000006DL)
#endif
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
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
#ifndef STATUS_OBJECT_NAME_NOT_FOUND
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)
#endif

#define OPENSSH_LSA_AUTH_GROUP_ATTRS \
	(SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED)
#define OPENSSH_LSA_AUTH_GRANT_TTL_MS 60000UL
#define OPENSSH_LSA_AUTH_MAX_REQUEST 8192UL

typedef struct _OPENSSH_LSA_GRANT {
	struct _OPENSSH_LSA_GRANT *next;
	UCHAR grant[OPENSSH_LSA_AUTH_GRANT_BYTES];
	wchar_t *user;
	wchar_t *domain;
	ULONGLONG expires_ms;
} OPENSSH_LSA_GRANT;

typedef struct _LSA_TOKEN_BUILD {
	PLSA_TOKEN_INFORMATION_V1 token;
	PVOID block;
	LPBYTE cursor;
	LPBYTE end;
} LSA_TOKEN_BUILD;

static PLSA_DISPATCH_TABLE lsa_dispatch;
static CRITICAL_SECTION grant_lock;
static int grant_lock_initialized;
static OPENSSH_LSA_GRANT *grants;

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

static ULONGLONG
now_ms(void)
{
	FILETIME ft;
	ULARGE_INTEGER uli;

	GetSystemTimeAsFileTime(&ft);
	uli.LowPart = ft.dwLowDateTime;
	uli.HighPart = ft.dwHighDateTime;
	return uli.QuadPart / 10000ULL;
}

static void
free_grant(OPENSSH_LSA_GRANT *grant)
{
	if (grant == NULL)
		return;
	free(grant->user);
	free(grant->domain);
	SecureZeroMemory(grant, sizeof(*grant));
	free(grant);
}

static void
purge_expired_grants_locked(ULONGLONG now)
{
	OPENSSH_LSA_GRANT **pp = &grants, *cur;

	while ((cur = *pp) != NULL) {
		if (cur->expires_ms > now) {
			pp = &cur->next;
			continue;
		}
		*pp = cur->next;
		free_grant(cur);
	}
}

static int
grant_exists_locked(const UCHAR grant_id[OPENSSH_LSA_AUTH_GRANT_BYTES])
{
	OPENSSH_LSA_GRANT *cur;

	for (cur = grants; cur != NULL; cur = cur->next) {
		if (memcmp(cur->grant, grant_id,
		    OPENSSH_LSA_AUTH_GRANT_BYTES) == 0)
			return 1;
	}
	return 0;
}

static int
wcsdup_local(const wchar_t *s, wchar_t **out)
{
	size_t chars;

	*out = NULL;
	if (s == NULL)
		return 1;
	chars = wcslen(s) + 1;
	*out = calloc(chars, sizeof(wchar_t));
	if (*out == NULL)
		return 1;
	memcpy(*out, s, chars * sizeof(wchar_t));
	return 0;
}

static int
grant_random(UCHAR grant_id[OPENSSH_LSA_AUTH_GRANT_BYTES])
{
	int i;

	for (i = 0; i < 10; i++) {
		if (!RtlGenRandom(grant_id, OPENSSH_LSA_AUTH_GRANT_BYTES))
			return 1;
		if (!grant_exists_locked(grant_id))
			return 0;
	}
	return 1;
}

static NTSTATUS
insert_grant(const wchar_t *user, const wchar_t *domain,
    UCHAR grant_id[OPENSSH_LSA_AUTH_GRANT_BYTES])
{
	OPENSSH_LSA_GRANT *grant = NULL;
	ULONGLONG now = now_ms();
	NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

	grant = calloc(1, sizeof(*grant));
	if (grant == NULL)
		goto done;
	if (wcsdup_local(user, &grant->user) != 0 ||
	    wcsdup_local(domain, &grant->domain) != 0)
		goto done;

	EnterCriticalSection(&grant_lock);
	purge_expired_grants_locked(now);
	if (grant_random(grant_id) != 0) {
		LeaveCriticalSection(&grant_lock);
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}
	memcpy(grant->grant, grant_id, OPENSSH_LSA_AUTH_GRANT_BYTES);
	grant->expires_ms = now + OPENSSH_LSA_AUTH_GRANT_TTL_MS;
	grant->next = grants;
	grants = grant;
	grant = NULL;
	LeaveCriticalSection(&grant_lock);
	status = STATUS_SUCCESS;

done:
	free_grant(grant);
	return status;
}

static NTSTATUS
consume_grant(const wchar_t *user, const wchar_t *domain,
    const UCHAR grant_id[OPENSSH_LSA_AUTH_GRANT_BYTES])
{
	OPENSSH_LSA_GRANT **pp, *cur;
	ULONGLONG now = now_ms();
	NTSTATUS status = STATUS_LOGON_FAILURE;

	EnterCriticalSection(&grant_lock);
	purge_expired_grants_locked(now);
	for (pp = &grants; (cur = *pp) != NULL; pp = &cur->next) {
		if (memcmp(cur->grant, grant_id,
		    OPENSSH_LSA_AUTH_GRANT_BYTES) != 0)
			continue;
		/* grant_id is a 32-byte random token — matching it is sufficient;
		 * user/domain check prevents one user consuming another's grant */
		if (_wcsicmp(cur->user, user) == 0 &&
		    _wcsicmp(cur->domain, domain) == 0)
			status = STATUS_SUCCESS;
		*pp = cur->next;
		free_grant(cur);
		break;
	}
	LeaveCriticalSection(&grant_lock);
	return status;
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

	if (bytes < sizeof(wchar_t) || (bytes % sizeof(wchar_t)) != 0 ||
	    offset > request_len || bytes > request_len - offset)
		return NULL;
	ret = calloc((bytes / sizeof(wchar_t)) + 1, sizeof(wchar_t));
	if (ret == NULL)
		return NULL;
	memcpy(ret, base + offset, bytes);
	ret[bytes / sizeof(wchar_t)] = L'\0';
	if (ret[(bytes / sizeof(wchar_t)) - 1] != L'\0') {
		free(ret);
		return NULL;
	}
	return ret;
}

static NTSTATUS
parse_auth_request(OPENSSH_LSA_AUTH_REQUEST *request, ULONG request_len,
    ULONG expected_opcode, wchar_t **user_out, wchar_t **domain_out)
{
	ULONG off;

	*user_out = NULL;
	*domain_out = NULL;
	if (request == NULL || request_len < sizeof(*request) ||
	    request_len > OPENSSH_LSA_AUTH_MAX_REQUEST ||
	    request->magic != OPENSSH_LSA_AUTH_MAGIC ||
	    request->version != OPENSSH_LSA_AUTH_VERSION ||
	    request->opcode != expected_opcode)
		return STATUS_INVALID_PARAMETER;
	off = sizeof(*request);
	*user_out = dup_request_string((const BYTE *)request, request_len, off,
	    request->user_bytes);
	off += request->user_bytes;
	*domain_out = dup_request_string((const BYTE *)request, request_len, off,
	    request->domain_bytes);
	if (*user_out == NULL || *domain_out == NULL ||
	    (*user_out)[0] == L'\0' || wcslen(*user_out) > UNLEN ||
	    wcslen(*domain_out) > DNLEN) {
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

static const wchar_t *
normalized_domain(const wchar_t *domain)
{
	return domain_is_local(domain) ? L"." : domain;
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
			    &sid) != 0)
				continue;
			if (append_group_sid(&sids, &count, &capacity,
			    sid) != 0) {
				free(sid);
				goto nomem;
			}
		}
	}

	net_status = NetUserGetGroups(NULL, user, 0, (LPBYTE *)&global_groups,
	    MAX_PREFERRED_LENGTH, &global_count, &global_total);
	if (net_status == NERR_Success) {
		for (i = 0; i < global_count; i++) {
			if (lookup_account_sid_w(global_groups[i].grui0_name,
			    &sid) != 0)
				continue;
			if (append_group_sid(&sids, &count, &capacity,
			    sid) != 0) {
				free(sid);
				goto nomem;
			}
		}
	}

	if (local_groups != NULL)
		NetApiBufferFree(local_groups);
	if (global_groups != NULL)
		NetApiBufferFree(global_groups);
	*out_sids = sids;
	*out_count = count;
	return STATUS_SUCCESS;

nomem:
	if (local_groups != NULL)
		NetApiBufferFree(local_groups);
	if (global_groups != NULL)
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
	if (status != STATUS_SUCCESS)
		return STATUS_SUCCESS;
	status = LsaEnumerateAccountRights(policy, user_sid, &rights,
	    &right_count);
	if (status == STATUS_OBJECT_NAME_NOT_FOUND)
		status = STATUS_SUCCESS;
	if (status != STATUS_SUCCESS)
		goto done;
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
alloc_default_dacl(LSA_TOKEN_BUILD *build, PSID user_sid, PACL *dacl_out)
{
	SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
	PSID system_sid = NULL, admins_sid = NULL;
	PACL dacl;
	DWORD acl_size;
	NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

	*dacl_out = NULL;
	if (alloc_well_known_sid(nt, SECURITY_LOCAL_SYSTEM_RID,
	    &system_sid) != 0 ||
	    alloc_well_known_sid2(nt, SECURITY_BUILTIN_DOMAIN_RID,
	    DOMAIN_ALIAS_RID_ADMINS, &admins_sid) != 0)
		goto done;

	acl_size = sizeof(ACL) +
	    3 * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) +
	    sid_length(user_sid) + sid_length(system_sid) + sid_length(admins_sid);
	dacl = build_alloc(build, acl_size, sizeof(DWORD));
	if (dacl == NULL)
		goto done;
	if (!InitializeAcl(dacl, acl_size, ACL_REVISION) ||
	    !AddAccessAllowedAce(dacl, ACL_REVISION, GENERIC_ALL, user_sid) ||
	    !AddAccessAllowedAce(dacl, ACL_REVISION, GENERIC_ALL, system_sid) ||
	    !AddAccessAllowedAce(dacl, ACL_REVISION, GENERIC_ALL, admins_sid))
		goto done;
	*dacl_out = dacl;
	status = STATUS_SUCCESS;

done:
	free(system_sid);
	free(admins_sid);
	return status;
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
	PACL default_dacl = NULL;
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
	total += sizeof(ACL) +
	    3 * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) +
	    sid_length(info->usri4_user_sid) +
	    2 * SECURITY_MAX_SID_SIZE;
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
		groups->Groups[i].Attributes = OPENSSH_LSA_AUTH_GROUP_ATTRS;
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

	status = alloc_default_dacl(&build, info->usri4_user_sid,
	    &default_dacl);
	if (status != STATUS_SUCCESS)
		goto done;
	build.token->DefaultDacl.DefaultDacl = default_dacl;
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
		return STATUS_INSUFFICIENT_RESOURCES;
	memset(ret, 0, sizeof(*ret) + len + 1);
	ret->Length = (USHORT)len;
	ret->MaximumLength = (USHORT)(len + 1);
	ret->Buffer = (PCHAR)(ret + 1);
	memcpy(ret->Buffer, s, len + 1);
	*out = ret;
	return STATUS_SUCCESS;
}

static NTSTATUS
validate_local_account(const wchar_t *user, const wchar_t *domain,
    USER_INFO_4 **user_info_out)
{
	NET_API_STATUS net_status;
	USER_INFO_4 *user_info = NULL;

	*user_info_out = NULL;
	if (!domain_is_local(domain))
		return STATUS_ACCOUNT_RESTRICTION;

	net_status = NetUserGetInfo(NULL, user, 4, (LPBYTE *)&user_info);
	if (net_status != NERR_Success)
		return STATUS_NO_SUCH_USER;
	if ((user_info->usri4_flags & UF_ACCOUNTDISABLE) != 0) {
		NetApiBufferFree(user_info);
		return STATUS_ACCOUNT_DISABLED;
	}
	if ((user_info->usri4_flags & UF_NORMAL_ACCOUNT) == 0) {
		NetApiBufferFree(user_info);
		return STATUS_ACCOUNT_RESTRICTION;
	}
	*user_info_out = user_info;
	return STATUS_SUCCESS;
}

static NTSTATUS
return_grant_reply(PLSA_CLIENT_REQUEST client_request,
    const UCHAR grant_id[OPENSSH_LSA_AUTH_GRANT_BYTES],
    PVOID *protocol_return_buffer, PULONG return_buffer_length)
{
	OPENSSH_LSA_AUTH_GRANT_REPLY reply;
	PVOID client_buffer = NULL;
	NTSTATUS status;

	if (protocol_return_buffer != NULL)
		*protocol_return_buffer = NULL;
	if (return_buffer_length != NULL)
		*return_buffer_length = 0;
	if (client_request == NULL || protocol_return_buffer == NULL ||
	    return_buffer_length == NULL || lsa_dispatch == NULL ||
	    lsa_dispatch->AllocateClientBuffer == NULL ||
	    lsa_dispatch->CopyToClientBuffer == NULL)
		return STATUS_INVALID_PARAMETER;

	memset(&reply, 0, sizeof(reply));
	reply.magic = OPENSSH_LSA_AUTH_MAGIC;
	reply.version = OPENSSH_LSA_AUTH_VERSION;
	reply.status = STATUS_SUCCESS;
	memcpy(reply.grant, grant_id, OPENSSH_LSA_AUTH_GRANT_BYTES);

	status = lsa_dispatch->AllocateClientBuffer(client_request,
	    sizeof(reply), &client_buffer);
	if (status != STATUS_SUCCESS)
		return status;
	status = lsa_dispatch->CopyToClientBuffer(client_request, sizeof(reply),
	    client_buffer, &reply);
	if (status != STATUS_SUCCESS) {
		if (lsa_dispatch->FreeClientBuffer != NULL)
			lsa_dispatch->FreeClientBuffer(client_request,
			    client_buffer);
		return status;
	}
	*protocol_return_buffer = client_buffer;
	*return_buffer_length = sizeof(reply);
	return STATUS_SUCCESS;
}

BOOL WINAPI
DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
	OPENSSH_LSA_GRANT *grant, *next;

	(void)instance;
	(void)reserved;
	if (reason == DLL_PROCESS_ATTACH) {
		/* InterlockedCompareExchange guards against concurrent DLL_PROCESS_ATTACH */
		if (InterlockedCompareExchange((LONG *)&grant_lock_initialized, 1, 0) == 0)
			InitializeCriticalSection(&grant_lock);
	} else if (reason == DLL_PROCESS_DETACH && grant_lock_initialized) {
		for (grant = grants; grant != NULL; grant = next) {
			next = grant->next;
			free_grant(grant);
		}
		grants = NULL;
		DeleteCriticalSection(&grant_lock);
		grant_lock_initialized = 0;
	}
	return TRUE;
}

__declspec(dllexport) NTSTATUS NTAPI
LsaApInitializePackage(ULONG authentication_package_id,
    PLSA_DISPATCH_TABLE dispatch_table, PLSA_STRING database,
    PLSA_STRING confidentiality, PLSA_STRING *authentication_package_name)
{
	(void)authentication_package_id;
	(void)database;
	(void)confidentiality;

	if (dispatch_table == NULL || authentication_package_name == NULL)
		return STATUS_INVALID_PARAMETER;
	lsa_dispatch = dispatch_table;
	return alloc_lsa_string(OPENSSH_LSA_AUTH_PACKAGE,
	    authentication_package_name);
}

__declspec(dllexport) NTSTATUS NTAPI
LsaApLogonUser(PLSA_CLIENT_REQUEST client_request,
    SECURITY_LOGON_TYPE logon_type, PVOID authentication_information,
    PVOID client_authentication_base, ULONG authentication_information_length,
    PVOID *profile_buffer, PULONG profile_buffer_length, PLUID logon_id,
    PNTSTATUS sub_status, PLSA_TOKEN_INFORMATION_TYPE token_information_type,
    PVOID *token_information, PLSA_UNICODE_STRING *account_name,
    PLSA_UNICODE_STRING *authenticating_authority)
{
	OPENSSH_LSA_AUTH_REQUEST *request = authentication_information;
	wchar_t *user = NULL, *domain = NULL;
	USER_INFO_4 *user_info = NULL;
	NTSTATUS status = STATUS_LOGON_FAILURE;
	int logon_session_created = 0;

	(void)client_request;
	(void)client_authentication_base;
	(void)logon_type;

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

	status = parse_auth_request(request, authentication_information_length,
	    OPENSSH_LSA_AUTH_OP_REDEEM_GRANT, &user, &domain);
	if (status != STATUS_SUCCESS)
		goto done;
	status = consume_grant(user, normalized_domain(domain), request->grant);
	if (status != STATUS_SUCCESS)
		goto done;
	status = validate_local_account(user, domain, &user_info);
	if (status != STATUS_SUCCESS)
		goto done;

	status = build_token_information(user, user_info, token_information_type,
	    token_information);
	if (status != STATUS_SUCCESS)
		goto done;
	if (account_name != NULL &&
	    alloc_lsa_unicode_string(user, account_name) != 0) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}
	if (authenticating_authority != NULL &&
	    alloc_lsa_unicode_string(normalized_domain(domain),
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
	if (status != STATUS_SUCCESS)
		goto done;
	logon_session_created = 1;
	if (sub_status != NULL)
		*sub_status = STATUS_SUCCESS;
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
	}
	if (user_info != NULL)
		NetApiBufferFree(user_info);
	free(user);
	free(domain);
	return status;
}

__declspec(dllexport) NTSTATUS NTAPI
LsaApCallPackage(PLSA_CLIENT_REQUEST client_request,
    PVOID protocol_submit_buffer, PVOID client_buffer_base,
    ULONG submit_buffer_length, PVOID *protocol_return_buffer,
    PULONG return_buffer_length, PNTSTATUS protocol_status)
{
	OPENSSH_LSA_AUTH_REQUEST *request = protocol_submit_buffer;
	wchar_t *user = NULL, *domain = NULL;
	USER_INFO_4 *user_info = NULL;
	UCHAR grant_id[OPENSSH_LSA_AUTH_GRANT_BYTES];
	NTSTATUS status;

	(void)client_buffer_base;
	if (protocol_return_buffer != NULL)
		*protocol_return_buffer = NULL;
	if (return_buffer_length != NULL)
		*return_buffer_length = 0;
	if (protocol_status != NULL)
		*protocol_status = STATUS_LOGON_FAILURE;

	status = parse_auth_request(request, submit_buffer_length,
	    OPENSSH_LSA_AUTH_OP_CREATE_GRANT, &user, &domain);
	if (status != STATUS_SUCCESS)
		goto done;
	status = validate_local_account(user, domain, &user_info);
	if (status != STATUS_SUCCESS)
		goto done;
	status = insert_grant(user, normalized_domain(domain), grant_id);
	if (status != STATUS_SUCCESS)
		goto done;
	status = return_grant_reply(client_request, grant_id,
	    protocol_return_buffer, return_buffer_length);

done:
	if (protocol_status != NULL)
		*protocol_status = status;
	if (user_info != NULL)
		NetApiBufferFree(user_info);
	free(user);
	free(domain);
	return status == STATUS_SUCCESS ? STATUS_SUCCESS : status;
}

__declspec(dllexport) NTSTATUS NTAPI
LsaApCallPackageUntrusted(PLSA_CLIENT_REQUEST client_request,
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
		*protocol_status = STATUS_ACCESS_DENIED;
	return STATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NTAPI
LsaApCallPackagePassthrough(PLSA_CLIENT_REQUEST client_request,
    PVOID protocol_submit_buffer, PVOID client_buffer_base,
    ULONG submit_buffer_length, PVOID *protocol_return_buffer,
    PULONG return_buffer_length, PNTSTATUS protocol_status)
{
	return LsaApCallPackageUntrusted(client_request, protocol_submit_buffer,
	    client_buffer_base, submit_buffer_length, protocol_return_buffer,
	    return_buffer_length, protocol_status);
}

__declspec(dllexport) VOID NTAPI
LsaApLogonTerminated(PLUID logon_id)
{
	(void)logon_id;
}
