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
- Phase 2: transport software implemented; two-device hardware acceptance is
  pending. User Pi/Arch trials exposed intermittent, asymmetric discovery.
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
denied, all-target builds, and 89 workspace tests:

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

## Hardware acceptance status

The agent environment exposes only one Linux controller. The user is now testing
a Raspberry Pi and an Arch Linux laptop on separate machines, but those machines
are not remotely accessible to the agent. Two-device discovery, bidirectional
fragmented GATT transfer, actual negotiated peer MTUs, connection election, and
both controllers' scheduling behavior remain acceptance criteria.

Hardware acceptance is not a prerequisite for implementing later software.
Later phases have not been implemented; do not claim Phase 2 acceptance complete
based solely on the memory transport or the one-controller probe.

## Doctor controller enumeration regression

A user testing an Arch laptop against a Raspberry Pi reported that `doctor`
counted `/sys/class/bluetooth/hci0:256` as a second controller, then issued
invalid D-Bus introspection requests for `/org/bluez/hci0:256`. Controller
enumeration now accepts only `hci` followed by one or more ASCII digits in
both sysfs and BlueZ object-path parsing; connection entries are not controllers.

Two regression tests cover numbered controllers, connection entries, invalid
suffixes, and nested BlueZ device paths. Both tests and all 83 workspace tests
passed, clippy passed with warnings denied, and a local `doctor` smoke returned
one controller and passed prerequisites. The user's laptop and Pi have not been
remotely verified; their cross-device acceptance results remain pending.

## Intermittent Pi/Arch discovery investigation

The user ran the discovery-only probe four times: one run reported one peer
on the Pi only, with no corresponding laptop discovery. This is a failure,
not a discovery pass. The radio-level cause is not yet established.

Code inspection found serial UUID/RSSI D-Bus reads inside a short scan window
while BlueR replays cached devices before live events. Candidate evaluations
now run independently of event draining, with at most four unique active
evaluations and 256 queued candidates. Repeated sightings queue reevaluation;
removals cancel pending/in-flight work. Service UUID and live-RSSI checks remain.
Queue regressions cover deduplication, capacity, removal, and fairness behind
an in-flight candidate. This corrects a starvation risk; it does not prove
the user's asymmetric discovery is resolved.

The probe now installs a privacy-safe logger, exposes existing scan warnings,
counts distinct opaque locators, and exits nonzero after startup failures.
`RUST_LOG=blendr_bluez=debug` adds scan-window and candidate-admission messages
without addresses, peer identities, or payloads.

All 89 workspace tests, formatting, clippy, and all-target builds passed. A
14-second local probe showed two actual scan windows through D-Bus observation,
debug start/end output, truthful zero-peer reporting, no MAC output, and cleanup.
Disabled-advertising startup exited 1 after cleanup without a false watching
status. New diagnostic logs from both user devices are still needed to
distinguish actual radio/controller behavior from candidate rejection.
