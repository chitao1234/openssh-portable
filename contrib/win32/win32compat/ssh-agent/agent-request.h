#include "sshbuf.h"
#include "authfd.h"


/* key management */
int process_unsupported_request(struct sshbuf*, struct sshbuf*, struct agent_connection*);
int process_add_identity(struct sshbuf*, struct sshbuf*, struct agent_connection*);
int process_request_identities(struct sshbuf*, struct sshbuf*, struct agent_connection*);
int process_sign_request(struct sshbuf*, struct sshbuf*, struct agent_connection*);
int process_remove_key(struct sshbuf*, struct sshbuf*, struct agent_connection*);
int process_remove_all(struct sshbuf*, struct sshbuf*, struct agent_connection*);
int process_add_smartcard_key(struct sshbuf*, struct sshbuf*, struct agent_connection*);
int process_remove_smartcard_key(struct sshbuf*, struct sshbuf*, struct agent_connection*);
int process_extension(struct sshbuf*, struct sshbuf*, struct agent_connection*);

/* auth */
