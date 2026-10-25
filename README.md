# Blendr

Proximity-first, decentralized messaging over Bluetooth Low Energy. Every
installation is a self-contained node: identity, messages, and sync state stay
on the device. There is no server, account, or Internet requirement. The full
product/protocol specification lives in [`plan.md`](./plan.md).

The Rust workspace provides a Linux CLI for decentralized identities, private
local notes, authenticated Noise XX sessions, and addressed direct messages
over Bluetooth LE, plus shared framing, an in-memory radio, and a BlueZ BLE
adapter.

Not implemented yet: mesh forwarding (`blendr mesh`), or Android. Private
notes are still local-only and are never transmitted; `publish` is the only
content that leaves the device, and only after explicit opt-in. The BLE
examples exchange only unauthenticated diagnostic frames; do not use them
for private messages.

## Usage

```sh
cargo build -p blendr-cli          # binary: target/debug/blendr

blendr doctor                      # uses ./config.json (default)
blendr --config PATH doctor        # global flag before the subcommand
blendr doctor --config PATH        # equivalent; the flag is global

blendr init                        # create data dirs, keystore, database
blendr identity show               # handle, full BID, version, public keys
blendr identity rename "alice"     # signed rename; BID never changes
blendr identity export backup.enc  # encrypted backup (never overwrites)
blendr identity import backup.enc  # restore into a node without a keystore
blendr note "remember this"        # private local note (never synced)
blendr inbox                       # notes + direct messages, newest first
blendr inbox --direct --peer BID   # only direct messages with one peer
blendr inbox --search "rem" --limit 20

blendr start                       # foreground node: advertise, scan, exchange
blendr start --once --duration 120
blendr peers                       # list pinned peers and trust status
blendr peers --scan --duration 60  # discover + authenticate nearby nodes
blendr peers verify BID --fingerprint HEX64   # out-of-band key check
blendr peers block BID / unblock BID
blendr send --to BID "hello"       # encrypt, queue, deliver within --timeout
blendr send --to BID "hello" --queue-only     # queue only; `start` delivers

blendr publish "hello nearby"     # sign + store a public post
blendr publish "hi" --sync 60     # also share it within the deadline
blendr feed                       # public posts, newest first
blendr feed --search "nearby"
```

Passphrases are only ever read from the terminal (with confirmation when
creating a new one) or from files. `--passphrase-file PATH` is a **global**
flag supplying the keystore passphrase for any command; `identity
export|import` additionally accept `--backup-passphrase-file PATH` for the
separate backup passphrase. Passphrase files must be regular, non-symlink,
owner-only (`0600`-style, no group/other bits), and at most 4 KiB; one
trailing newline is stripped. Passphrases are never accepted as arguments or
environment variables, and are zeroized after use.

### `blendr init` semantics

- Creates `node.data_dir` and the parents of the keystore/database with
  `0700` permissions (existing directories that permit group/other access
  are tightened; if tightening is impossible the command fails).
- Generates a fresh identity, writes the encrypted keystore with
  `create_new` (an existing identity is **never** overwritten), then records
  the signed public document in the database.
- Re-running on a healthy node is a safe no-op that re-verifies the keystore
  and database agree. Re-running after a **partial** init finishes the
  missing half: keystore-only → the document is recorded; database-only (no
  keystore) → fails, because the private keys are gone. Restore the *same*
  BID's backup with `identity import` (or point `storage.database_path` at
  an empty database).

### `identity rename` semantics

`rename` signs a new identity document with `version + 1` (the BID and
encryption keys are untouched), atomically rewrites `node.display_name` in
`config.json`, and mirrors the document into the database's profile history.
If `config.json`'s display name and the signed document ever disagree (e.g.
after hand-editing), every operating command refuses with a drift error —
run `blendr identity rename "<desired name>"` to reconcile.

### Direct messaging semantics

- `blendr peers --scan` runs the node until the deadline: every discovered
  Blendr peer gets a mutually authenticated Noise XX session bound to its
  signed identity document. On success the peer is **pinned** (trust on first
  use); a later session presenting a different signing key for the same BID
  fails closed.
- Trust is layered: pinning happens automatically, `peers verify` marks a pin
  `verified` only after an out-of-band comparison of the exact 64-hex signing
  key printed by the other device's `identity show`, and `peers block` /
  `unblock` locally reject sessions and outbound queues (unblocking resets
  trust to unverified).
- `blendr send` encrypts the text for the recipient's current X25519 epoch
  (HPKE), signs the envelope, and stores it in the durable outbox **before**
  any radio contact. Delivery requires a prior `peers --scan` so the
  recipient's key is pinned; an unknown or blocked BID fails before queueing.
- During an authenticated session both nodes exchange queued outbound
  messages under the negotiated per-session count/byte budget. A *link
  receipt* proves the peer's transport accepted the frame; a separate
  *destination receipt* — issued only after durable persistence — is what
  marks a message `delivered` in history.
- Received messages are stored ciphertext-only; plaintext is decrypted on
  `inbox` read and is never persisted, so history survives TTL expiry. Outbox
  retries continue across sessions until a destination receipt arrives.
- `inbox` merges private notes (marked `note`) and direct history (`direct
  ->`/`direct <-` with the peer BID and state) into one newest-first page;
  `--peer` and `--direct` filter it.

### Broadcast semantics

- `blendr publish` signs the post with your identity and stores it in the
  public feed — no delivery attempt is made until `--sync` or the next
  `start`/`peers --scan` session. Posts are public by design: signed but
  **not** encrypted, and may be reshared by peers within the signed
  `mesh.outgoing.max_jumps` ceiling.
- During an authenticated session (when both nodes advertise
  `features.broadcast_mode`), each side advertises a bounded inventory of
  unexpired, unacknowledged post IDs, the peer requests only the ones it is
  missing, and transfers run inside the same negotiated per-session
  count/byte budget as direct messages. A peer may never request IDs that
  were not offered.
- The receiving side verifies the origin signature, expiry, and text bound
  before durable storage; a successful store is acknowledged back so the
  sender's per-peer ledger suppresses re-offers on later sessions — this is
  the restart-resume behavior, and it also keeps a lost connection from
  re-sending already-delivered posts.
- `blendr feed` lists authored and received posts newest-first; `feed
  --search` filters on post text or the origin's claimed display name
  (informational — the signature, not the name, is the proof).
- Private `note`s and direct history are **never** included in inventories
  or offered to any peer, regardless of configuration.


### `identity export` / `import` semantics

Both require `identity.allow_encrypted_backup = true` (enabled in the sample
config). `export` writes a fresh encrypted backup file and refuses to
overwrite anything. `import` refuses to run when a keystore already exists
and also refuses when the database already owns a **different** BID. The
supported recovery case — keystore lost but database intact — restores the
same BID; if the database's document is newer than the backup (e.g. a rename
after export), the imported identity is re-signed forward so versions stay
monotonic.
Import atomically updates `node.display_name` to the restored signed profile's
name, so the restored identity is immediately usable. If that settings write
fails after the keystore is restored, `identity rename` repairs the mismatch.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Runtime failure (keystore, passphrase, database, identity) — text on stderr, never secret material |
| 2 | Command-line usage error (clap) |
| 3 | Config file missing/unreadable/invalid — precise field error on stderr |
| 4 | `doctor` only: config valid but hardware/daemon prerequisites missing |

### `blendr doctor`

1. Loads and validates the JSON config, then prints the **non-secret**
   effective settings (including derived `effective_outgoing_jumps` /
   `effective_incoming_jumps` and resolved data/keystore/database paths).
2. Probes Linux prerequisites: system D-Bus reachability, the `org.bluez`
   daemon, presence of a BLE controller (`/sys/class/bluetooth` plus BlueZ's
   own adapter list), powered/unblocked state, `LEAdvertisingManager1` and
   `GattManager1` capability, and central+peripheral roles.

External tools (`busctl`, `dbus-send`, `bluetoothctl`) are invoked with a
bounded timeout; when they are missing, checks degrade to filesystem evidence
and are reported as `WARN` (unverified) rather than fake success. Doctor
never prints Bluetooth MAC addresses, full peer identifiers, or message
contents.

## Configuration

One `config.json` per installation (see the development example in this repo
and the settings reference in `plan.md` §4). Relative paths such as
`node.data_dir`, `identity.keystore_path`, and `storage.database_path`
resolve relative to the JSON file's directory, not the process working
directory. Secrets never live in JSON: private keys exist only inside the
encrypted keystore.

## Transport diagnostics

```sh
cargo run --locked -p blendr-transport --example memory_smoke
cargo run --locked -p blendr-bluez --example probe -- config.json --duration 5
```

For discovery troubleshooting, enable privacy-safe transport diagnostics on both
devices and capture stdout and stderr:

```sh
RUST_LOG=blendr_bluez=debug ./target/debug/examples/probe config.json --duration 120 --require-peer \
  2>&1 | tee /tmp/blendr-discovery.log
```

`scan request` reports requested settings, not successful scanner startup.
`scan window start/end` debug messages identify actual discovery sessions.
Candidate checks report service-match and RSSI-presence booleans without device
addresses. The default configuration scans for 3 seconds every 10 seconds.

Scanning is LE-only, with no BlueZ service-UUID restriction. Blendr filters
candidates itself using the configured service UUID and RSSI presence. This
avoids the BlueZ 5.87 UUID-filter crash
([upstream issue #2282](https://github.com/bluez/bluez/issues/2282)) without
changing the advertised UUID, GATT service, or peer admission rules.
Unrelated BLE sightings increase local processing; pending candidate evaluations
remain bounded to 256 queued addresses and four concurrent evaluations.
Another application's UUID-filtered scan can still trigger an affected daemon;
this workaround is not a system-wide BlueZ fix.

Blendr explicitly marks its LE advertisement as general-discoverable; it does
not change the adapter's global discoverability or advertise a device name.
Registration and scan-start messages alone do not prove over-the-air discovery.
If discovery is asymmetric or connections time out, also check the BlueZ daemon:

```sh
journalctl -u bluetooth --since "10 minutes ago"
```

Daemon crashes/restarts invalidate an active probe run. Pairing-agent errors
indicate a separate Bluetooth security negotiation failure; the probe does not
install an agent or automatically approve pairing. Review system/HCI logs before
sharing them: unlike the probe's diagnostics, they can contain device addresses
and other identifying data.

### Text-message demo (plaintext)

`message_demo` sends one text message and one reply over real BLE, confirms
receipt, and exits on both hosts. It is **not secure Blendr messaging**: no
encryption, peer authentication, identity binding, persistence, or chat history.
Use non-sensitive test text only; `--message` is also visible in shell history
and process arguments. Stop other Blendr probes/demos first: the connector uses
the first discovered Blendr peer, not an authenticated recipient.

Build on both hosts:

```sh
cargo build --locked -p blendr-bluez --example message_demo
```

Start the listener first:

```sh
./target/debug/examples/message_demo config.json \
  --listen --message 'Hello laptop, from the Pi' --timeout 180
```

Then run on the other host:

```sh
./target/debug/examples/message_demo config.json \
  --connect --message 'Hello Pi, from the laptop' --timeout 90
```

Each terminal prints `You:` and `Peer:` followed by the text. Remote control
characters are escaped rather than interpreted by the terminal. Both processes
exit zero only after the exchange and cleanup complete. Invalid arguments exit
2; connection, deadline, message-size, protocol, and cleanup failures exit 1.
The sample configuration permits 115 UTF-8 bytes of text per message (128-byte
frame limit minus 13 bytes of demo overhead); longer text requires increasing
`transport.ble.max_frame_payload_bytes` on both hosts.

The daemon/controller limitations below still apply. If BLE-MIDI is triggering
pairing, temporary plugin isolation may be needed. On a Raspberry Pi whose
existing service command is **exactly** `/usr/libexec/bluetooth/bluetoothd`, this
creates a separate runtime-only override; do not use it to overwrite other
service arguments. Restarting Bluetooth interrupts existing connections.

```sh
systemctl show bluetooth -p ExecStart -p DropInPaths
sudo install -d /run/systemd/system/bluetooth.service.d
printf '%s\n' '[Service]' 'ExecStart=' \
  'ExecStart=/usr/libexec/bluetooth/bluetoothd --noplugin=midi' |
  sudo sh -c 'set -C; cat > /run/systemd/system/bluetooth.service.d/90-blendr-message-demo.conf' &&
  sudo systemctl daemon-reload &&
  sudo systemctl restart bluetooth
```

Run the listener and connector after that restart. After the demo, remove **only
the override you created**, then restore the original daemon:

```sh
sudo rm -- /run/systemd/system/bluetooth.service.d/90-blendr-message-demo.conf
sudo systemctl daemon-reload
sudo systemctl restart bluetooth
```

This temporarily disables BLE-MIDI, not Bluetooth encryption or pairing policy.
It does not fix controller-level connection failures.

### Two-host frame exchange

On both hosts, use a diagnostic config with
`transport.ble.max_frame_payload_bytes = 8192` and
`transport.ble.preferred_mtu = 64`. Keep matching service/characteristic UUIDs.
The probe validates these limits rather than silently changing configuration.

```sh
cargo build --locked -p blendr-bluez --example probe

# Host A: accept connections without initiating.
RUST_LOG=blendr_bluez=debug ./target/debug/examples/probe diagnostic.json \
  --listen --duration 120 --rounds 3 --reconnect

# Host B: discover and connect immediately.
RUST_LOG=blendr_bluez=debug ./target/debug/examples/probe diagnostic.json \
  --spike --duration 120 --rounds 3 --reconnect
```

Each round verifies exact 1 KiB, 4 KiB, and 8 KiB requests and echoes in both
directions: twelve data frames per round, fragmented below the configured
64-byte packet limit. Every fresh link also checks pre-cancelled send/receive
and cancellation of an idle receive. Both hosts need matching `--rounds` and
`--reconnect` options. Reverse the host roles to exercise the other GATT client.
Without `--reconnect`, all rounds use one link.

For competing connection attempts, run `--elect` on **both** hosts instead of
`--listen`/`--spike`. It exchanges a diagnostic election marker, accepts only a
matching peer's surviving link, and verifies the same two-way data exchange.
Logs distinguish provisional outgoing links from the surviving role; merely
running two processes is not evidence that their dial attempts overlapped.

The `link ready` log reports acquired read/write packet MTUs and the effective
configured packet cap. `PeerLink::mtu()` instead reports the maximum application
frame size. Do not interpret that frame limit as the negotiated ATT MTU.

The initiator closes the physical connection after round-scoped completion
receipts; the listener observes disconnection before accepting the next link.
BlueZ can retain server IO sockets across reconnects, so the adapter also watches
`Device1.Connected`, rather than relying on socket EOF alone. Closing an elected
initiator uses device-wide `Device1.Disconnect`, which can interrupt other
Bluetooth profiles on that peer. Closing a responder releases its local link;
it does not independently disconnect the shared ACL.

Exit status is `0` for a completed requested diagnostic, `1` for runtime/config
failure, and `2` for invalid arguments. Exchange, corruption, missing-peer,
deadline, and cleanup failures are nonzero. Discovery alone permits zero peers
unless `--require-peer` is supplied. `--duration` bounds setup and the subsequent
diagnostic phase separately. These frames contain synthetic diagnostic data,
not user messages, and are **not secure chat**.

### Unrelated profiles and controller failures

BlueZ `Device1.Connect` can initialize unrelated profiles as well as Blendr GATT.
In particular, a BLE-MIDI profile may read an encryption-protected MIDI attribute
and trigger pairing even though Blendr's characteristics do not require pairing.
Changing Blendr's UUID does not prevent that profile initialization.

If HCI evidence identifies MIDI as the trigger, an administrator can temporarily
isolate BlueZ's `midi` plugin (`bluetoothd --noplugin=midi`) for diagnostics.
Inspect the distribution's existing service command and preserve its other
arguments; use a separate runtime-only systemd drop-in, restart Bluetooth, then
remove only that drop-in and restart again afterward. This disables BLE-MIDI
functionality while active and interrupts existing Bluetooth connections.
Blendr never changes daemon configuration, trusts devices, or approves pairing
automatically. Plugin isolation is not a general Bluetooth security workaround.

An HCI disconnect reason `0x3e` (“Connection Failed to be Established”) before
any ATT traffic is a lower-layer failure, not a Blendr frame-validation failure.
Capture both controllers' HCI/kernel/daemon evidence before changing scheduling
or connection parameters. A successful isolated run does not establish reliable
operation with the original daemon configuration.

## Limitations

- `mesh` (relay forwarding) does not exist; posts and direct messages reach
  only nodes in direct BLE range, even though post envelopes carry a signed
  `max_jumps` ceiling for future forwarding. `note` data never leaves the
  device.
- The SQLite database is not fully encrypted; private notes and own outbound
  text are protected only by filesystem permissions (`0600`/`0700`).
  Received messages are ciphertext-only at rest; broadcast posts are
  intentionally stored with their public plaintext. Private keys are always
  encrypted at rest.
- Config changes require editing `config.json`; display-name changes must go
  through `blendr identity rename` or commands refuse with a drift error.
  Secure sessions require `transport.ble.max_frame_payload_bytes >= 1024`.
- Direct messaging has run Pi↔laptop once under the documented MIDI-plugin
  isolation (AGENTS.md); broadcast sync is verified by in-memory tests
  only so far, and the known BlueZ/controller failure modes above still
  apply to the real adapter.
- Identity import never replaces an existing identity; deleting a keystore
  or database to start over is an explicit, manual operation.
- If none of `busctl`/`dbus-send`/`bluetoothctl` exist, doctor's daemon and
  capability checks can only warn, not verify.

## Verification

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
```

CI runs the same three steps on every push (`.github/workflows/ci.yml`).
