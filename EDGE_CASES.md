# Edge Cases & Attack Resistance — Task 1

## 1. Direct invocation of `backend` (bypassing `frontend`)

Since `backend` is setuid-root, any local user can run it directly
without going through `frontend`. `backend` defends against this by
checking, before touching anything privileged:

1. `getsockname(3, ...)` — is fd 3 actually an `AF_UNIX` socket at all?
2. `getsockopt(3, SOL_SOCKET, SO_PEERCRED, ...)` — does the kernel
   report a sane peer identity for it?

Run directly, fd 3 is whatever the shell happened to leave open (often
closed or a tty), so check (1) fails immediately and `backend` exits
before ever opening `protected_users.db`. See `logs/direct_invocation.log`.

## 2. Malformed / truncated request over the socket

`backend`'s `read(3, &req, sizeof(req))` requires an exact
`sizeof(struct auth_request)` byte read. A short or garbled write (e.g.
a hostile process connecting to a manually-crafted socket and sending
a truncated struct) is rejected: `backend` prints
`"malformed or truncated request, aborting"` and exits without
comparing anything.

## 3. Wrong credentials

`backend` still executes the full privilege-drop lifecycle
(`setresuid()`, `getresuid()` verification, `setuid(0)` probe) even on
a failed comparison — the drop is unconditional and happens before the
verdict is ever communicated back, so there is no code path where
`backend` can exit still holding root. See `logs/incorrect_credentials.log`.

## 4. `frontend` invoked as (or made) privileged

`frontend` checks `geteuid() == 0` at startup and refuses to run if
true. This isn't defence against an attacker (an attacker who already
controls root doesn't need this program), but it keeps the roles of
the two binaries honest during testing/demoing — `frontend` should
never accidentally be run in a way that gives it privilege it isn't
supposed to have.

## 5. Confirming the privilege drop is real, not assumed

Every `backend` run performs two independent checks after
`setresuid()`, rather than trusting the return value alone:

- `getresuid()` immediately after, printed to stdout/log — real,
  effective and saved uid must all equal the unprivileged uid.
- A `setuid(0)` probe — if this call unexpectedly *succeeds*, `backend`
  treats it as fatal and aborts, because that would mean the drop
  didn't actually close off the path back to root.

Both checks pass on every logged run (`logs/*.log`), which is why the
transcripts show `confirmed irreversible: setuid(0) -> Operation not
permitted` rather than the program simply trusting `setresuid()`'s
return code.
