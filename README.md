# shex

`shex` is a deliberately small remote shell over TCP. A short authentication
code is verified with OPAQUE; the code is never sent to the server and the
server persists only an OPAQUE password record. The OPAQUE session key is then
expanded into separate client-to-server and server-to-client keys for a
ChaCha20-Poly1305 encrypted channel.

This is an SSH-like shell, **not an implementation of the SSH wire protocol**.
It has no file transfer, forwarding, user database, or other SSH features.

## Install

Install the published binary from crates.io:

```sh
cargo install shex
```

Upgrade an existing installation:

```sh
cargo install shex --force
```

Or build the latest source checkout:

```sh
cargo build --release
```

## Initialize and run the server

Initialization prompts twice for the code and writes private credential files
with mode `0600` on Unix:

```sh
shex init --data-dir .shex
shex serve --bind 0.0.0.0:8022 --data-dir .shex
```

Use a high-entropy code. OPAQUE with Argon2 makes a stolen password record
harder to attack, but a very short numeric code is still guessable.

## Connect

For an interactive one-off connection, authenticate directly:

```sh
shex connect server.example:8022
```

The client prints the new session ID. The server keeps that shell process alive
after the client disconnects, so state such as `cd` and exported environment
variables remains available while the server process is running:

```text
session: 3ae162b90f944fa4654dbb49a36cc734
shex> cd /srv/app
shex> export MODE=production
```

Resume it interactively:

```sh
shex connect server.example:8022 \
  --session 3ae162b90f944fa4654dbb49a36cc734
```

## Saved authentication and non-interactive execution

Authenticate once before using `exec`:

```sh
shex authenticate server.example:8022
```

This creates `.shex_auth`. The credential payload is encrypted with
ChaCha20-Poly1305, while its random decryption key is stored in the operating
system credential manager (macOS Keychain, Windows Credential Manager, or the
Linux Secret Service). The encrypted payload is bound to the authenticated
server's setup fingerprint.

The encrypted file and its OS credential-store entry belong together. Copying
only `.shex_auth` to another machine or OS account will not copy the decryption
key; run `shex authenticate` again on that machine instead.

If `.shex_auth` already exists, shex creates `.shex_auth_01`, then
`.shex_auth_02`, and prints the exact `--auth-file` argument required to use it.

`exec` reads `.shex_auth` and creates a new persistent shell session by default:

```sh
shex exec -- pwd
```

Reuse the most recent session recorded in that auth file:

```sh
shex exec --past -- pwd
```

An explicit session ID remains available:

```sh
shex exec --session 3ae162b90f944fa4654dbb49a36cc734 -- pwd
```

Use a non-default auth file when `authenticate` created another one:

```sh
shex exec --auth-file .shex_auth_01 -- pwd
```

## Security boundary

- Authentication is OPAQUE (an augmented password-authenticated key exchange),
  not a generic zero-knowledge proof system.
- The code does not cross the network and is not stored by the server.
- All post-authentication messages are authenticated and encrypted.
- Sessions are memory-only and disappear when the server restarts.
- Every reconnect must authenticate; a session ID alone is insufficient.
- Saved credentials are encrypted at rest and their keys are kept outside the
  binary in the operating system credential manager.
- Auth files are usable only with the server fingerprint recorded during
  `authenticate`; a different server is rejected.
- The server runs commands with the same operating-system privileges as `shex`.
- There is no PTY emulation, so full-screen programs such as editors are outside
  this minimal tool's scope.

## Upgrading from 0.1

Version 0.2 adds the authenticated server-identity handshake used by saved auth
files. Upgrade the server and client together, then run `shex authenticate` once
before using the new `exec` workflow.
