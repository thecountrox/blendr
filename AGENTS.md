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
- Phase 2: transport software implemented; physical discovery, fragmented
  transfers, reconnect, election, cancellation, and timeout recovery have passed
  diagnostic runs. Full hardware acceptance remains conditional: transfers used
  temporary Pi MIDI-plugin isolation, and later Pi-initiated connections failed
  below ATT. See the current acceptance evidence and blockers below.
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
  GATT client/server packet IO, runtime packet MTU, retries, connection-lifetime
  tracking, and election-safe shutdown. Physical transfer and election evidence
  exists under the documented diagnostic isolation; unrestricted reliability
  is not established.
- `apps/linux-cli`: `doctor`, `init`, `identity show|rename|export|import`, `note`,
  and searchable `inbox`. Notes remain local-only. There is no node application
  implementing `start`, `peers`, `send`, `publish`, or `mesh`.

## Verification evidence

The latest complete local verification passed formatting, clippy with warnings
denied, all-target builds, and 94 tests across ten all-target workspace suites:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
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
Two-minute paired discovery passed with both original daemon configurations.
Bidirectional fragmented GATT transfers, actual packet MTUs, reconnect, election,
cancellation, and partial-frame timeout recovery passed with the Pi MIDI plugin
temporarily disabled. That override has been removed. Later reverse-initiation
trials failed before ATT even under isolation; these failures prevent an
unqualified Phase 2 acceptance claim.

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

### Current Phase 2 transfer and lifecycle evidence

The discovery workaround was committed as
`e72639d fix(bluez): filter discovery service UUIDs in application`.
Subsequent HCI/D-Bus tracing identified the earlier security negotiation trigger:
the Pi read the laptop's BLE-MIDI characteristic
`f36b109d-66f2-a9a1-1241-6838dbe57277` at handle `0x0017`, received ATT
Insufficient Encryption (`0x0f`), and attempted SMP without an approving agent.
GAP Name and Appearance reads succeeded. This supersedes the hypothesis that
GAP attributes caused the pairing request.

With explicit user approval, a separate runtime-only Pi systemd drop-in added
`--noplugin=midi` to its original bluetoothd command. No trust flags, bonds,
pairing approvals, original config files, or laptop system settings were changed.
All transfer evidence below used that isolation:

- Both GATT initiation orientations passed exact 1024-, 4096-, and 8192-byte
  requests and echoes in both directions. Each round validates twelve frames.
  Acquired reader MTU was 517, writer MTU 512, and the configured packet cap 64;
  the application frame limit was 8192, not an ATT MTU.
- Three-round physical reconnect passed in each initiation orientation during
  development. Laptop-initiated reconnect also passed after the disconnect-watch
  correction. Later Pi-initiated failures are retained below, not averaged away.
- Concurrent dial attempts converged on a laptop initiator and Pi responder,
  then validated three rounds / 36 data frames on the winning link. The Pi's
  initial Connect timed out while an inbound link formed; its retry completed,
  and post-dial election retained the inbound winner.
- Every successful fresh probe link checked pre-cancelled send/receive and a
  receive cancelled after 100 ms, each with a one-second completion bound.
- A throwaway physical fault injector sent only the first fragment of a
  1024-byte frame. The Pi returned `Timeout` with a one-second reassembly limit,
  then received an exact complete 1024-byte frame and echoed it on the same
  connection. It subsequently observed physical disconnection. Both processes
  exited zero; the throwaway source was removed from both checkouts.
- An intentionally wrong TX characteristic UUID caused a nonzero client failure
  after service discovery. Cleanup completed; a subsequent correctly configured
  client exchanged all twelve frames with the same still-running listener.
  Independent Pi HCI observation recorded two connections and two disconnections.
- Disabled discovery/advertising startup exited nonzero without claiming a
  watching or successful-exchange state.

Reconnect exposed two application lifecycle defects. Dropping acquired IO alone
did not reliably notify the peer of closure. On Pi BlueZ, old server IO also
received traffic from a subsequent physical connection. The adapter now watches
`Device1.Connected=false`, wakes blocked IO through cancellation tokens, and
reserves an elected initiator's peer until device-wide disconnect completes.
Superseded links cannot disconnect their election winner. Failed or cancelled
dials clean up only when no elected link owns the ACL; shutdown waits for those
cleanup tasks. The diagnostic completion handshake assigns physical teardown
to the initiator and prevents stale round receipts from passing a reconnect.

### Remaining hardware blockers and restoration

Later Pi-initiated trials failed all three configured Connect attempts with
`le-connection-abort-by-local`; listeners correctly exited nonzero at their
deadline. Pi HCI tracing showed successful LE Connection Complete events
followed about 300 ms later by disconnect reason `0x3e`
(`Connection Failed to be Established`), with **zero ATT operations**.
The requested supervision timeout was 420 ms. A separate trial with laptop
scanning disabled still failed, so concurrent laptop scanning is not established
as the cause. No connection-parameter tuning, extra retries, automatic pairing,
or controller-reset workaround was added.

Service-resolution timeouts also occurred in earlier trials. Successful later
runs do not establish that all daemon/controller intermittency is resolved.
The previously observed Pi daemon crash remains unattributed. Privileged laptop
HCI/controller evidence is unavailable without user assistance; laptop sudo
requires a password. Further low-level diagnosis needs that evidence alongside
the Pi trace, not changes to Blendr's service UUID or suppression of errors.

The temporary `/run/systemd/system/bluetooth.service.d/90-blendr-phase2.conf`
was removed, systemd reloaded, and Pi Bluetooth restarted. Verification showed
`ActiveState=active`, no drop-ins, and original ExecStart
`/usr/libexec/bluetooth/bluetoothd` with no `--noplugin` argument.

After restoration, both hosts passed simultaneous 120-second discovery with
the original three-second / ten-second scan schedule: each observed one distinct
peer, retained one live peer, and completed twelve scan windows. Independent
D-Bus sampling observed scanning plus advertising together in 141 laptop samples
and 130 Pi samples, with zero query errors and unchanged daemon PIDs on both.
This establishes sustained foreground discovery for the run, not uninterrupted
radio airtime or reliable default-configuration GATT transfer.

Final local verification passed formatting, workspace all-target clippy with
warnings denied, all 92 all-target tests, and all-target builds. The Pi passed
its nine blendr-bluez all-target tests. A discovery run with an unmatched service
UUID and `--require-peer` exited 1; conflicting exchange roles exited 2.
After asynchronous BlueZ cleanup settled, independent checks on both hosts
showed `Discovering=false` and `ActiveInstances=0`. The throwaway fault-injector
source and temporary diagnostic config copies were removed from both checkouts.

### Executable plaintext message demo

`crates/blendr-bluez/examples/message_demo.rs` provides one real BLE text request
and reply with completion receipts, bounded deadlines, and connection cleanup.
It is explicitly unauthenticated, unencrypted diagnostic messaging, not Phase 3
chat: no identity binding, persistence, or history was added. Received terminal
control characters are escaped. Both message size and peer frame type/UTF-8 are
validated; the original 128-byte frame limit allows 115 UTF-8 bytes of text.
README documents build/run commands and temporary Pi MIDI isolation/restoration.

The initial run with the original daemon configuration failed during connection
setup and returned nonzero on both hosts. Under the same previously approved
temporary Pi MIDI-plugin isolation, the laptop sent
`Hello tvpi, from the laptop` and received `Hello laptop, from tvpi`; the Pi
displayed the corresponding received message and reply. Both processes completed
the receipt/close handshake and exited zero. The dedicated runtime override was
removed in a finally block; the Pi service was confirmed active with its original
ExecStart and no drop-ins. No persistent daemon settings, trust, or bonds changed.

CLI smoke checks also confirmed conflicting roles exit 2, empty text exits 1
before opening the adapter, and a missing listener peer expires nonzero.
Final formatting, workspace all-target clippy with warnings denied, all 94 tests,
and all-target builds passed. The Pi built the demo and passed its two
message-boundary/malformed-frame tests. Sources and executable are deployed to
`/home/pi/blendr`; the temporary MIDI override is deliberately not left active.
