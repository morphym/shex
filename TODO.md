# shex TODO

## Client credential setup

- Add a first-run setup prompt that lets the user select an available
  operating-system credential lock and records that preference. Until then,
  shex uses the platform default: macOS Keychain on macOS and Secret Service on
  Linux.
- Add an explicit migration command for legacy `.shex_auth*` files.

## Global Redis federation

- Define GitHub authentication with read-only identity scope for global Redis
  operators.
- Define signed admission and signature rotation for Redis nodes in the global
  pool.
- Add Redis health scoring, rejection, and recovery rules.
- Federate multiple Redis deployments with CDN-like message routing.
- Specify conflict resolution, replay protection, rate limits, and abuse
  controls for the global control plane.
- Specify safe hostname reclamation without weakening permanent ownership.

## Availability

- Design host failover and migration for live host-local shell processes.
