#include <winsock2.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include "misc_internal.h"
#include "unistd.h"
#include "Debug.h"

int posix_spawn_internal(pid_t *pidp, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[], HANDLE user_token, BOOLEAN prepend_module_path);

static int
target_is_current_user(const char *user)
{
	PSID current_sid = NULL, target_sid = NULL;
	int ret = 0;

	if (user == NULL || am_system() || strcmp(user, "sshd") == 0)
		return 0;
	if ((current_sid = get_sid(NULL)) == NULL ||
	    (target_sid = get_sid(user)) == NULL)
		goto cleanup;
	ret = EqualSid(current_sid, target_sid);

cleanup:
	if (current_sid)
		free(current_sid);
	if (target_sid)
		free(target_sid);
	return ret;
}

int
__posix_spawn_asuser(pid_t *pidp, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[], char* user)
{
	extern HANDLE password_auth_token;
	extern HANDLE sspi_auth_user;

	int r = -1;
	int close_user_token = 0;
	HANDLE user_token = NULL;
	HANDLE primary_token = NULL;

	if (target_is_current_user(user))
		return posix_spawn_internal(pidp, path, file_actions, attrp, argv,
		    envp, NULL, TRUE);
	
	if (password_auth_token)
		user_token = password_auth_token;
	else if (sspi_auth_user) 
		user_token = sspi_auth_user;

	if (!user_token && (user_token = get_user_token(user, 1)) == NULL) {
		error("unable to get security token for user %s", user);
		errno = EOTHER;
		return -1;
	}
	if (user_token != password_auth_token && user_token != sspi_auth_user)
		close_user_token = 1;
	if (!DuplicateTokenEx(user_token, MAXIMUM_ALLOWED, NULL,
	    SecurityImpersonation, TokenPrimary, &primary_token)) {
		error("unable to duplicate primary token for user %s, error:%d",
		    user, GetLastError());
		errno = EOTHER;
		goto cleanup;
	}
	if (strcmp(user, "sshd"))
		load_user_profile(primary_token, user);
	
	r = posix_spawn_internal(pidp, path, file_actions, attrp, argv, envp,
	    primary_token, TRUE);
cleanup:
	if (primary_token)
		CloseHandle(primary_token);
	if (close_user_token)
		CloseHandle(user_token);
	return r;
}
