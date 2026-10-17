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
- Phase 2: transport software implemented; full two-device hardware acceptance
  is pending. Paired Pi/Arch discovery passed a 35-second run after moving UUID
  filtering into Blendr; diagnostic-frame exchange and election remain unverified.
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
- `crates/blendr-bluez`: service-only advertising, application-filtered discovery,
  GATT client/server packet IO, runtime packet MTU, retries, and shutdown lifecycle.
  Paired discovery passed; client transfer attempts have failed and connection
  election has not been verified against a second device.
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

The local environment exposes one Linux controller. The Raspberry Pi is now
remotely accessible with `ssh -i ~/.ssh/tvpi pi@tvpi.local`, with its checkout at
`/home/pi/blendr` (fallback address: `192.168.1.50`). Both devices pass `doctor`.
Paired discovery passed a 35-second simultaneous scan/advertise run after the
application-side UUID-filter workaround. Bidirectional fragmented GATT transfer,
Blendr packet MTUs, connection election, and sustained discovery reliability
remain acceptance criteria.

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

## SSH-coordinated Pi/Arch trials (2026-10-18)

SSH access with the explicit Pi key succeeded. Pi BlueZ is 5.66; laptop BlueZ
is 5.87. Probe source SHA-256 matched across checkouts; this does not establish
that the complete source trees or compiled binaries match.

- Simultaneous 35-second discovery with the original 3-second scan windows:
  zero peers on both hosts. The laptop logged two `start discovery: Bluetooth
  operation in progress: Operation already in progress` warnings.
- Temporary configs used a 60-second scan window and 61-second interval,
  leaving the original configs unchanged. With Pi listening for 40 seconds and
  laptop sending after 20 seconds, the Pi discovered one peer with matching
  service UUID and live RSSI, then lost it; the laptop discovered none.
- Reversing the 40-second listener and 20-second sender roles found zero peers
  on both hosts. Neither long-window trial established a link or exchanged a
  diagnostic frame. Scan-start warnings did not recur in those trials.
- All probes reported clean shutdown. Final independent D-Bus checks on both
  controllers returned `Discovering=false` and `ActiveInstances=0`. Temporary
  configs were removed by the experiment scripts.

Discovery remains intermittent/asymmetric; the radio-level cause is unresolved.
The probe's `single-controller run` text also appears when two active devices
fail discovery, and exit code zero does not imply paired-test success.

### Controller tracing and role isolation

The user confirmed that the devices are physically close. Pi `sudo -n` permits
`btmon`; the laptop denies unprivileged HCI monitoring and requires a password
for sudo. No adapter resets, pairing approvals, or system configuration changes
were performed.

The transport source checksums also matched before the experiment.
`start_advertising` now sets `Advertisement.discoverable = Some(true)` instead
of inheriting the adapter's hidden state. The change was deployed and built in
both checkouts. Pi HCI/MGMT observation confirmed a 21-byte advertisement with
flags `0x06` (LE General Discoverable, BR/EDR Not Supported), replacing the
previous 18-byte UUID-only payload. This corrects the advertisement flags; it
did not by itself fix paired discovery.

With temporary configs, laptop advertising without scanning allowed the Pi to
discover it repeatedly and keep it live for a 30-second run. Laptop concurrent
scanning/advertising did not discover the advertising-only Pi. A native
`bluetoothctl scan le` with no laptop advertisement did expose a Blendr device
with live RSSI (-78 dBm). These comparisons suggest a dual-role or daemon
lifecycle problem but do not isolate its cause.

Two Pi-initiated probe exchanges against a non-scanning laptop listener timed
out. HCI tracing of the second showed a successful ACL connection, ATT MTU 517,
and Blendr GATT service discovery. Subsequent SMP pairing received a negative
user-confirmation reply and failed; the laptop then disconnected. Both hosts'
BlueZ logs reported `No agent available for request type 2` and
`device_confirm_passkey: Operation not permitted`. No application diagnostic
frame was exchanged. ATT MTU negotiation is not proof of Blendr packet IO.

The laptop journal also records repeated `bluetoothd` SIGSEGV/core-dump exits
and automatic restarts during the diagnostic period. These invalidate simple
inferences from successful registration messages; the crash cause is not
established. The Pi journal also records a SIGSEGV after the connection trials.
Its adapter object was briefly unavailable after a later daemon start, then
reappeared powered on. Final D-Bus checks on both hosts confirmed scanning off,
zero active advertisements, and global discoverability off.

Laptop `coredumpctl info 300683` confirms SIGSEGV/SEGV_ACCERR, but the stored
root-owned core is inaccessible and the journal stack has no resolved symbols.
Privileged crash inspection is a remaining prerequisite. Do not silently add
an auto-accept pairing agent or declare the two-device acceptance passed.

Verification of the advertisement change: both probe builds, workspace format
check, blendr-bluez all-target clippy with warnings denied, and all six
blendr-bluez unit tests passed. The hardware smoke verified advertisement flags,
not reliable simultaneous discovery or frame exchange. No Rust language server
is configured in this session.

### Laptop discovery crash identified from the user-provided core

The user supplied GDB backtrace, mappings, and instruction bytes for PID 300683.
The crash address contains the ASCII bytes of Blendr's filter UUID
`c2f60001-e7ca-4ac2-b6cd-10d5c0bf0001`, interpreted as instructions.
Installed `bluetoothd` disassembly at relative return address `0x1118a1`
shows the preceding indirect callback call; its caller at `0xcac26` passes
list data as the callback and a code address as the match data.

This matches BlueZ issue https://github.com/bluez/bluez/issues/2282:
5.87's `is_filter_match()` retained `g_slist_find_custom` argument order when
switching to `queue_find`, calling a UUID string as a function when a matching
advertisement arrives. Upstream fixed the argument order and boolean equality
semantics in commit
https://github.com/bluez/bluez/commit/82af2beafc39510e2c4a439bf44faea711d6503f.

The laptop has CachyOS `bluez`, `bluez-libs`, and `bluez-utils` 5.87-2.1.
The cached package databases offer CachyOS 5.87-2.1 and Arch 5.87-2; repository
metadata was not refreshed and no system packages were changed. Both configured
debuginfod endpoints returned 404 for this binary's build ID.

This supersedes the hypothesis that the laptop's failure to discover while
advertising establishes a controller dual-role limitation: the UUID-filter
crash explains why native unfiltered scanning can succeed while Blendr fails.
Do not rerun UUID-filtered discovery on the affected daemon.
The Pi 5.66 crash and pairing rejection remain separate unresolved findings;
this 5.87 regression does not explain them. No further privileged core access
is needed to identify the laptop's matching UUID-filter crash.

### Application-side UUID discovery workaround

`scan_task` now requests LE discovery with an empty BlueZ UUID list on all
versions. `handle_seen` retains the configured service-UUID and RSSI checks.
Advertisements, GATT UUIDs, scan timing, peer aging, pairing policy, the
256-address pending queue, and four-evaluation concurrency limit are unchanged.
No BlueZ-version special case or fallback mode was added.

Local verification passed workspace formatting, blendr-bluez all-target clippy
with warnings denied, all 89 workspace tests, and the probe example build.
A 25-second live hci0 smoke exercised three scan windows. BlueR trace confirmed
successful `SetDiscoveryFilter` calls with `UUIDs=[]` and `Transport="le"`.
Candidates with `service_match=false` and `live_rssi=true` were observed but
not admitted: zero Blendr peers were reported. The Bluetooth daemon PID remained
303053 and its restart count stayed zero. Probe shutdown was clean; independent
D-Bus checks confirmed `Discovering=false` and `ActiveInstances=0`.

The Pi was initially unreachable during implementation: `tvpi.local` failed
name resolution, SSH to `192.168.1.50` timed out, and two ping requests received
no replies. Access subsequently returned and the workaround was deployed to
`/home/pi/blendr`; its probe example build passed.

A simultaneous 35-second discovery run using both original configs passed:
each host discovered one distinct peer and retained one live peer at completion.
Both hosts completed four scan windows, and BlueR traces confirmed empty UUID
filters with LE transport. Matching-service/live-RSSI evaluations occurred on
both hosts; unrelated live candidates were also evaluated and rejected.
Laptop bluetoothd PID 303053 and Pi PID 469 remained unchanged, with restart
counts zero before and after. Both probes exited zero with clean shutdown;
independent D-Bus checks on both hosts confirmed scanning off and zero active
advertisements.

This verifies paired discovery for this run, not dense-environment throughput
or sustained reliability. Diagnostic-frame exchange was not repeated in this
run, and the previously observed pairing failure remains unresolved.
