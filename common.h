#ifndef COMMON_H
#define COMMON_H

/* Shared wire format between frontend and backend.
 * Kept as small fixed-size structs so a single write()/read() of
 * sizeof(...) bytes over the socketpair is enough - no framing needed. */

#define MAX_CRED_LEN 64

struct auth_request {
    char username[MAX_CRED_LEN];
    char password[MAX_CRED_LEN];
};

struct auth_response {
    int granted; /* 1 = access granted, 0 = access denied */
};

#define DB_PATH "./protected_users.db"

#endif /* COMMON_H */
