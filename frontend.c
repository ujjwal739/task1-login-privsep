/*
 * frontend.c
 *
 * Unprivileged half of the privilege-separated login system.
 * Responsibilities:
 *   - collect username/password from the terminal (password not echoed)
 *   - create a socketpair() BEFORE forking, so both endpoints exist
 *     before the child replaces itself with backend
 *   - fork(), dup2() its endpoint onto fd 3, execve("./backend", ...)
 *   - send the credentials down the socket, then immediately wipe its
 *     own copy of the password with explicit_bzero()
 *   - wait for backend's verdict and print the result
 *
 * frontend NEVER becomes privileged. If somehow invoked as root/setuid,
 * it refuses to run - the whole point of the design is that the
 * highest-risk code (parsing raw user input) never holds elevated
 * privilege.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/types.h>

#include "common.h"

static void read_password(char *buf, size_t len) {
    struct termios oldt, newt;

    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    if (fgets(buf, len, stdin) == NULL) {
        buf[0] = '\0';
    } else {
        buf[strcspn(buf, "\n")] = '\0';
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");
}

int main(void) {
    if (geteuid() == 0) {
        fprintf(stderr,
                "frontend: refusing to run with elevated privilege. "
                "frontend must always be unprivileged.\n");
        return 1;
    }

    printf("== Privilege-Separated Login (frontend, uid=%d) ==\n", getuid());

    struct auth_request req;
    memset(&req, 0, sizeof(req));

    printf("Username: ");
    if (fgets(req.username, sizeof(req.username), stdin) == NULL) {
        return 1;
    }
    req.username[strcspn(req.username, "\n")] = '\0';

    printf("Password: ");
    read_password(req.password, sizeof(req.password));

    /* socketpair() before fork(): both ends exist pre-fork, and the
     * kernel will later be able to report the REAL creating process's
     * credentials to backend via SO_PEERCRED. */
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        perror("socketpair");
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        /* Child becomes backend: separate process, separate address
         * space, separate credentials from this point forward. */
        close(sv[0]);
        if (dup2(sv[1], 3) < 0) {
            perror("dup2");
            _exit(1);
        }
        close(sv[1]);

        char *const argv[] = { (char *)"./backend", NULL };
        char *const envp[] = { NULL };
        execve("./backend", argv, envp);
        perror("execve backend"); /* only reached on failure */
        _exit(127);
    }

    /* Parent (still frontend) */
    close(sv[1]);

    if (write(sv[0], &req, sizeof(req)) != (ssize_t)sizeof(req)) {
        perror("write to backend");
    }

    /* Erase our copy of the password the moment it has been handed
     * off. explicit_bzero() is used instead of memset() so the write
     * cannot be optimised away as a dead store (see report section 7
     * / Q7 for the reasoning). */
    explicit_bzero(req.password, sizeof(req.password));

    struct auth_response resp;
    memset(&resp, 0, sizeof(resp));
    ssize_t n = read(sv[0], &resp, sizeof(resp));

    int status = 0;
    waitpid(pid, &status, 0);
    printf("[frontend] backend exited with status %d\n",
           WIFEXITED(status) ? WEXITSTATUS(status) : -1);

    close(sv[0]);

    if (n == (ssize_t)sizeof(resp) && resp.granted) {
        printf("Result: authentication granted\n");
    } else {
        printf("Result: authentication denied\n");
    }

    return resp.granted ? 0 : 1;
}
