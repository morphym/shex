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

Or execute without an interactive terminal:

```sh
shex exec --address server.example:8022 \
  --session 3ae162b90f944fa4654dbb49a36cc734 -- pwd
```

For automation, pass the code on standard input instead of exposing it as a
process argument:

```sh
printf '%s\n' "$SHEX_CODE" | shex exec \
  --address server.example:8022 \
  --session 3ae162b90f944fa4654dbb49a36cc734 \
  --code-stdin -- 'printf "hello\\n"'
```

## Security boundary

- Authentication is OPAQUE (an augmented password-authenticated key exchange),
  not a generic zero-knowledge proof system.
- The code does not cross the network and is not stored by the server.
- All post-authentication messages are authenticated and encrypted.
- Sessions are memory-only and disappear when the server restarts.
- Every reconnect must authenticate; a session ID alone is insufficient.
- The server runs commands with the same operating-system privileges as `shex`.
- There is no PTY emulation, so full-screen programs such as editors are outside
  this minimal tool's scope.
