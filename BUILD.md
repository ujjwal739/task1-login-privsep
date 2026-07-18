# Build & Usage — Task 1: Privilege-Separated Login

## Build

```bash
cd task1-login-privsep
make
```

This produces two binaries: `frontend` and `backend`.

## Set up the privileged half

`backend` must be installed setuid-root and `protected_users.db` must
be owned by root with mode `600`, otherwise the privilege-drop has
nothing to demonstrate and the db won't be root-only.

```bash
sudo make setup
```

This creates `protected_users.db` (format `username:password`, one
account per line), chowns it to `root:root` with mode `600`, and sets
the setuid bit on `backend`. Demo account: `ujjwal:password123`.

To add more accounts, edit `protected_users.db` as root:

```bash
sudo sh -c 'echo "newuser:newpass" >> protected_users.db'
```

## Run

```bash
./frontend
```

You'll be prompted for a username and password (password input is not
echoed to the terminal). `frontend` then forks, execs `backend` with
the credentials passed over a UNIX domain socket, and prints the
verdict.

## Worked examples

**Correct credentials** — see `logs/correct_credentials.log`:

```
[backend] at startup           real=1001 effective=0 saved=0
[backend] peer verified by kernel: pid=617 uid=1001 gid=1002
[backend] before setresuid()   real=1001 effective=0 saved=0
[backend] after setresuid()    real=1001 effective=1001 saved=1001
[backend] confirmed irreversible: setuid(0) -> Operation not permitted
[frontend] backend exited with status 0
Result: authentication granted
```

**Incorrect credentials** — see `logs/incorrect_credentials.log`: same
privilege-drop lifecycle, but `Result: authentication denied`.

**Direct invocation of `backend`** (bypassing `frontend` entirely) —
see `logs/direct_invocation.log`:

```
[backend] at startup           real=1001 effective=0 saved=0
[backend] fd 3 is not a UNIX socket, aborting
```

`backend` refuses to do anything privileged unless fd 3 is genuinely a
UNIX domain socket with a kernel-verified peer — running it standalone
has fd 3 pointing at nothing useful, so it aborts immediately, before
ever opening `protected_users.db`.
