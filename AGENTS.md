# Agent guidance and implementation progress

Keep agent progress, phase status, verification evidence, and environment-specific
blockers in this file, not in `README.md`. The README is user-facing documentation
for usage, configuration, diagnostics, and product limitations. `plan.md` contains
the product/protocol specification and acceptance criteria; do not mistake planned
features for implemented behavior.

## Implementation status

- Phase 0: implemented and verified — Rust workspace, configuration validation,
  atomic settings writes, doctor diagnostics, and CI.
- Phase 1: implemented and verified — decentralized identity, encrypted keystore,
  SQLite persistence, and local CLI workflows.
- Phase 2: transport software implemented; two-device hardware acceptance remains
  unverified and blocked by unavailable second-device access.
- Phases 3–8: not implemented. Secure sessions, HPKE addressed messaging, broadcast
  sync, mesh forwarding, Android interoperability, and protocol freeze are pending.
  No Kotlin/Compose app, Android BLE adapter, JNI bridge, or Android Keystore
  integration exists.

## Implemented components

- `crates/blendr-config`: complete typed configuration schema, strict unknown-key,
  jump-limit, feature, suite, UUID, and path validation; config-relative paths;
  atomic settings saves.
- `crates/blendr-identity`: Ed25519 signing identity, full SHA-256/Base32 BID,
  canonical-CBOR signed identity documents, monotonic profile versions, X25519
  encryption-key epochs, transcript-bound proofs, and Argon2id/XChaCha20-Poly1305
  encrypted keystores with owner-only files and no-overwrite creation.
- `crates/blendr-storage`: SQLite migrations, all ten planned persistence entities,
  single-owner identity, monotonic profile history, transactional private notes,
  deduplication, and literal substring search. Primary history is separate from
  relay custody; forwarding APIs are not implemented.
- `crates/blendr-transport`: bounded versioned fragmentation/reassembly,
  cancellation, timeout recovery, and an in-memory radio with loss, delay,
  disconnection, range changes, bounded queues, and connection election.
- `crates/blendr-bluez`: service-only advertising, filtered discovery, GATT
  client/server packet IO, runtime packet MTU, retries, and shutdown lifecycle.
  Client transfer and election have not been exercised against a second device.
- `apps/linux-cli`: `doctor`, `init`, `identity show|rename|export|import`, `note`,
  and searchable `inbox`. Notes remain local-only. There is no node application
  implementing `start`, `peers`, `send`, `publish`, or `mesh`.

## Verification evidence

The last complete local verification passed formatting, clippy with warnings
denied, all-target builds, and 81 workspace tests:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --workspace --all-targets --locked
```

CLI smoke runs exercised independent installations, idempotent initialization,
restart-persistent searchable notes, stable BID after rename, encrypted
backup/restore, wrong-passphrase and overwrite rejection, owner-only files,
and recovery from an older same-BID backup without losing local history.

The memory transport smoke exchanged five exact frames in both directions over
20-byte packets, observed range-loss disconnection, and reconnected cleanly.

The real BlueZ probe registered GATT and advertised the service on `hci0` with
BlueZ 5.87. Independent D-Bus observation confirmed simultaneous scanning and
advertising on this controller; shutdown restored scanning-off and zero active
advertisements. No Blendr peer was discovered. This does not establish
cross-device BLE interoperability or secure messaging.

Rust language-server diagnostics were unavailable in the implementation session;
compiler, clippy, test, and runtime evidence are the available verification.

## Hardware acceptance blocker

Only one Linux controller was accessible in the implementation environment. No
second Linux host was configured and no Android device was attached. Phase 2
still requires two-device discovery, bidirectional fragmented GATT transfer,
actual negotiated peer MTUs, connection election, and verification of the second
controller's scheduling behavior. These acceptance criteria must not be marked
complete based solely on the memory transport or the one-controller probe.

The implementation stopped at this hardware gate; later phases were not started.
When hardware access is available, resume with the Phase 2 acceptance criteria in
`plan.md` before claiming that phase complete.
