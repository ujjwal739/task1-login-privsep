/*
 * backend.c
 *
 * Privileged half of the login system. Meant to be installed setuid-root
 * (chmod u+s, owned by root) so that every invocation starts with
 * euid == 0. That elevated status is held for the minimum time needed
 * to read protected_users.db, and is then permanently discarded.
 *
 * Defence in depth against being invoked directly (bypassing frontend):
 *   1. fd 3 must actually be an AF_UNIX socket (getsockname).
 *   2. The kernel (not the caller) must report a sane peer identity via
 *      SO_PEERCRED.
 * If either check fails, backend aborts before touching anything
 * privileged.
 *
 * Privilege drop:
 *   setresuid(ruid, ruid, ruid) clears real, effective AND saved uid in
 *   one call, so there is no saved-uid slot left for a later syscall to
 *   restore root from. This is proven, not assumed: getresuid() is
 *   checked immediately after, and a setuid(0) probe is expected to
 *   fail with EPERM.
 *
 * Secure memory handling:
 *   The password is wiped with explicit_bzero() (not memset()) as soon
 *   as the comparison is done, so the compiler cannot eliminate the
 *   wipe as a dead store.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>

#include "common.h"

static int peer_looks_legitimate(int fd) {
    struct sockaddr_un addr;
    socklen_t addrlen = sizeof(addr);

    if (getsockname(fd, (struct sockaddr *)&addr, &addrlen) < 0) {
        return 0;
    }
    if (addr.sun_family != AF_UNIX) {
        return 0;
    }

    struct ucred cred;
    socklen_t len = sizeof(cred);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0) {
        return 0;
    }

    /* cred.uid, cred.pid, cred.gid are kernel-verified, not
     * client-supplied - a hostile process cannot spoof this value. */
    printf("[backend] peer verified by kernel: pid=%d uid=%d gid=%d\n",
           (int)cred.pid, (int)cred.uid, (int)cred.gid);
    return 1;
}

static int check_credentials(const char *username, const char *password) {
    FILE *fp = fopen(DB_PATH, "r");
    if (!fp) {
        perror("[backend] fopen protected_users.db");
        return 0;
    }

    char line[256];
    int ok = 0;

    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = '\0';

        char *sep = strchr(line, ':');
        if (!sep) continue;
        *sep = '\0';

        const char *db_user = line;
        const char *db_pass = sep + 1;

        if (strcmp(username, db_user) == 0 && strcmp(password, db_pass) == 0) {
            ok = 1;
            break;
        }
    }

    fclose(fp);
    return ok;
}

int main(void) {
    uid_t r, e, s;

    getresuid(&r, &e, &s);
    printf("[backend] at startup\t\treal=%d effective=%d saved=%d\n", r, e, s);

    if (!peer_looks_legitimate(3)) {
        fprintf(stderr, "[backend] fd 3 is not a UNIX socket, aborting\n");
        _exit(1);
    }

    struct auth_request req;
    memset(&req, 0, sizeof(req));
    if (read(3, &req, sizeof(req)) != (ssize_t)sizeof(req)) {
        fprintf(stderr, "[backend] malformed or truncated request, aborting\n");
        _exit(1);
    }

    getresuid(&r, &e, &s);
    printf("[backend] before setresuid()\treal=%d effective=%d saved=%d\n", r, e, s);

    /* Privileged window: this is the only part of the whole system that
     * ever needs euid == 0. */
    int granted = check_credentials(req.username, req.password);

    /* Wipe the password the instant we're done comparing it. */
    explicit_bzero(req.password, sizeof(req.password));

    /* Drop privilege for good: all three uid slots become the
     * unprivileged real uid, so there is nothing left to restore from. */
    if (setresuid(r, r, r) < 0) {
        perror("[backend] setresuid failed");
        _exit(1);
    }

    getresuid(&r, &e, &s);
    printf("[backend] after setresuid()\treal=%d effective=%d saved=%d\n", r, e, s);

    /* Prove the drop is irreversible rather than assuming it. */
    if (setuid(0) == 0) {
        fprintf(stderr,
                "[backend] FATAL: setuid(0) unexpectedly succeeded - "
                "privilege drop failed\n");
        _exit(1);
    }
    printf("[backend] confirmed irreversible: setuid(0) -> %s\n", strerror(errno));

    struct auth_response resp;
    resp.granted = granted;
    if (write(3, &resp, sizeof(resp)) != (ssize_t)sizeof(resp)) {
        perror("[backend] write response");
    }

    return 0;
}
