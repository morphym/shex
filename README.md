# shex

`shex` is a small remote shell that uses Redis as a routing layer. OPAQUE
authenticates a shared code without sending that code to the host or Redis.
Commands and results use a ChaCha20-Poly1305 channel derived from the OPAQUE
session key.

Redis never receives plaintext credentials, commands, command output, or shell
state. It sees the host and mailbox key names, encrypted payload sizes, and
timing. This is end-to-end encrypted infrastructure rather than a generic
zero-knowledge proof system.

This is an SSH-like shell, not an implementation of the SSH wire protocol.

## Install

```sh
cargo install shex
```

Upgrade an existing installation:

```sh
cargo install shex --force
```

## Redis configuration

Set `REDIS_URL` in the environment or a local `.env` file. TLS Redis URLs use
the `rediss` scheme:

```dotenv
REDIS_URL="rediss://username:password@example-redis:6379"
```

`.env` is ignored by Git and excluded from published crates. Use Redis ACLs,
TLS, and a dedicated database or account in production.

## Save a local Redis server

Give a Redis URL a local name:

```sh
shex redis add
```

With no arguments, shex interactively asks for the name and hides the Redis URL
while it is entered. Arguments remain available for automation:

```sh
shex redis add local redis://127.0.0.1:6379/
```

When `REDIS_URL` is already set, only the name is needed. Shex sends a Redis
`PING` before saving. If the server cannot be reached, it asks whether the entry
should be kept anyway.

The URL is stored in macOS Keychain or Linux Secret Service. Only a private,
hashed marker is written under `~/.shex/redis`. The most recently added server
becomes the default, so this uses it automatically:

```sh
shex latency test
```

A saved name can also be selected explicitly anywhere that accepts
`--redis-url`:

```sh
shex latency test --redis-url cloud
shex auth quiet-otter:1738 --redis-url cloud
shex serve --redis-url local
```

## Start a host

Initialize the host once. The authentication code is used to create an OPAQUE
password record but is not retained by the host:

```sh
shex init --data-dir .shex
shex serve --data-dir .shex
```

On first use, `serve` assigns and saves a permanent name resembling:

```text
quiet-otter:1738
```

Pass an explicit name to change it:

```sh
shex serve --data-dir .shex --hostname my-host:1738
```

The new name is saved locally and registered permanently in Redis. Previous
names remain reserved in Redis; global hostname reclamation is not implemented.

## Authenticate a client

Use the hostname printed by `serve`:

```sh
shex auth quiet-otter:1738
```

Authentication for every host is stored under `~/.shex/auth`. Filenames are
hostname hashes. Each file contains the Redis location, hostname, server
fingerprint, reusable credential, and last-session identifier. Its payload is
encrypted with ChaCha20-Poly1305, while the random encryption key is held by
macOS Keychain or Linux Secret Service through the operating-system credential
manager. Re-running `auth` safely updates that host's entry.

`shex authenticate` remains an alias for `shex auth`.

## Execute and resume

`exec` creates a persistent host-local shell session by default:

```sh
shex exec quiet-otter:1738 -- pwd
shex exec quiet-otter:1738 -- cd /srv/app
```

Each command without `--past` creates a different session. Reuse the most
recent session recorded in the selected auth file with:

```sh
shex exec --past quiet-otter:1738 -- pwd
```

An explicit session can also be selected:

```sh
shex exec --session 3ae162b90f944fa4654dbb49a36cc734 \
  quiet-otter:1738 -- pwd
```

Legacy or manually managed auth files remain usable with
`shex exec --auth-file PATH -- COMMAND`.

Delete the last session, its host process, and its Redis lookup:

```sh
shex close quiet-otter:1738
```

Or delete a specific session:

```sh
shex close quiet-otter:1738 \
  --session 3ae162b90f944fa4654dbb49a36cc734
```

## Interactive connection

A new interactive connection is ephemeral: it is removed when the connection
ends and does not create a Redis session lookup.

```sh
shex connect quiet-otter:1738
```

An existing persistent `exec` session can be opened interactively:

```sh
shex connect quiet-otter:1738 \
  --session 3ae162b90f944fa4654dbb49a36cc734
```

## Latency test

Measure Redis command round-trip latency without contacting a host:

```sh
shex latency test
```

Add a saved hostname to also measure an authenticated, encrypted host round
trip through Redis:

```sh
shex latency test quiet-otter:1738
```

The report includes Redis minimum/average/maximum time, host round-trip time,
and an estimated additional encrypted host path. The estimate subtracts the
Redis PING baseline and is diagnostic rather than a one-way network measurement.
Use `--count` to select between 1 and 100 samples.

## Redis storage model

- `shex:v2:host:<hostname>` is the small permanent host record.
- `shex:v2:<hostname>:session:<hash>` is one fixed lookup for each active
  persistent session. Actual shell state remains only in the host process.
- Layer-two mailboxes contain at most one message in each direction, with only
  one present during the request/response flow.
- Mailbox payloads have a 60-second TTL. While a receiver is processing one,
  an authenticated lease refresh prevents long-running commands from expiring.
- Blocking one-shot readiness signals avoid polling while clients or hosts are
  idle; signals carry no command or output data.
- A received payload is compare-and-deleted only after authenticated processing.
- Closing a session deletes its session lookup. Host startup removes stale
  lookups because live shell processes cannot survive a host restart.

Redis may temporarily hold ciphertext in memory, replicas, RDB snapshots, or
AOF according to its configuration. Disable Redis persistence for the shex
database if ciphertext must never reach Redis disk.

## Security boundary

- OPAQUE with Argon2 protects the authentication exchange.
- ChaCha20-Poly1305 authenticates and encrypts post-login traffic.
- Auth files are encrypted and bound to the authenticated host fingerprint.
- Saved Redis URLs are held by the operating-system credential store; local
  marker filenames are hashes of their aliases.
- Redis routing metadata, message sizes, and timing are not hidden.
- Use a high-entropy code; a short numeric code remains guessable.
- Redis access is local/private trust in 2.0. Redis ACLs remain important because
  an attacker with write access can deny service even without decrypting data.
- The host runs commands with the operating-system privileges of `shex`.
- There is no PTY emulation, file transfer, port forwarding, or full-screen
  terminal support.

## Deferred work

All planned but unimplemented work is centralized in [`TODO.md`](TODO.md).

## Upgrading from 0.x

Version 2.0 replaces direct TCP transport with Redis and is not wire-compatible
with 0.x. Upgrade hosts and clients together, configure `REDIS_URL`, restart the
host, and run `shex auth <hostname>` again to create a version-2 auth entry.
