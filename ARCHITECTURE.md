# shex 2.0 architecture

## Implemented

1. A host owns a permanent Redis hostname record.
2. OPAQUE authenticates a client through single-slot Redis mailboxes.
3. The OPAQUE session key creates directional ChaCha20-Poly1305 keys.
4. An ephemeral `connect` shell exists only for its connection.
5. A persistent `exec` shell remains in host memory and has one hashed Redis
   lookup record.
6. Each side processes one encrypted mailbox value at a time. Successful
   processing performs an atomic compare-and-delete acknowledgement. A
   short-lived lease keeps in-progress ciphertext alive, and blocking readiness
   signals avoid idle polling.
7. `close` removes the host-local shell and Redis lookup.
8. Client authentication entries are encrypted under `~/.shex/auth`; their
   encryption keys live in the operating-system credential store.
9. `latency test` measures Redis PING round trips and, when a saved host is
   selected, authenticated encrypted ping/pong round trips through that host.
10. `redis add` stores named Redis URLs in the operating-system credential
    store, writes only a hashed local marker under `~/.shex/redis`, verifies the
    server before saving, and selects the newest entry as the local default.

The Redis hostname and session hash are routing metadata. Authentication codes,
session identifiers, commands, output, and shell state are never Redis
plaintext.

Deferred work is tracked only in [`TODO.md`](TODO.md). No placeholder is
presented as a security implementation.

## Native distribution

Version tags build native macOS and Linux binaries on matching GitHub-hosted
architectures. Releases include compressed archives, Debian packages, and a
checksum manifest. Debian packages are indexed in a signed APT repository on
GitHub Pages. The Homebrew tap installs the same release binaries and verifies
their SHA-256 checksums.
