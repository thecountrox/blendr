# Blendr Protocol — Product, Protocol, and Implementation Plan

**Status:** Architectural draft, intended as the implementation source of truth for the first prototype  
**Protocol:** Blendr (wire identifier: `BLENDR`)  
**Target release:** v1 (Broadcast + decentralized identity + bounded multi-hop store-and-forward)  
**First target:** two native Linux devices using Bluetooth Low Energy (BLE)  
**Next target:** native Android app interoperating with Linux  
**Deferred:** v2 metadata-based mutual matching  
**Configuration:** a **single** JSON file per installation: [`config.json`](./config.json)

> The Blendr application is local-first: messages and identity credentials live on the user's device. There is no mandatory cloud, relay server, account provider, phone number, Wi-Fi, or Internet connection. BLE is the initial transport, not the definition of the protocol.

---

## 1. Vision and requirements

Blendr is a proximity-first, decentralized messaging system. Each installation is a self-contained node. Nearby nodes advertise that they speak Blendr; the application discovers them automatically. Nodes can communicate directly and, subject to their own settings, store, carry, and forward encrypted messages for other nodes. This is an **opportunistic delay-tolerant mesh**, not a permanently connected network.

### Core product requirements

1. **Fully local-first.** Identity, messages, peer records, synchronization state, and relay queues are stored on-device. The only files outside the SQLite database are a local configuration file and a protected identity keystore. No automatic upload of complete message histories.
2. **Automatic nearby discovery.** Devices in Broadcast mode discover compatible nearby nodes using BLE advertising and scanning. Foreground reliability is the initial target; background scanning is not guaranteed on every platform.
3. **Broadcast mode (v1).** Nearby nodes can become aware of one another without a central registry. Users can explicitly make a post, chat thread, or selected message shareable; discovering someone **does not** automatically expose their private chats.
4. **Direct messages (v1).** Users can send messages to known Blendr identities and keep local conversation history; when peer delivery is unavailable, a message may remain queued or travel through authorized relays.
5. **Bounded synchronization.** Only explicitly permitted data is offered. Sync limits bound message counts, total bytes, and inventory metadata per session.
6. **Decentralized identity.** A user chooses a display name. A stable Blendr Identifier (BID) comes from a cryptographic public identity key, not from a Bluetooth MAC, OS fingerprint, IP address, or physical device attribute.
7. **Configurable multi-hop jumps (v1).** Source, destination, and relaying devices each have independent forwarding/acceptance policies. The allowed range is 0–5 intermediary relay devices.
8. **Native-first engineering.** Linux uses Rust + BlueZ; Android is a native Kotlin/Jetpack Compose app with a native Kotlin Bluetooth adapter and shared Rust protocol core. No Flutter and no initial iOS support.
9. **Transport-independent protocol.** A BLE interface hides platform-specific details. Additional transports can be implemented later without changing identity, message envelopes, or routing policies.
10. **Future extensibility.** v2 adds privacy-conscious metadata matching, including two independent affirmative consents; v1 reserves protocol extensions but does not implement matching.

### Explicit non-goals for the first iteration

- Centralized authentication, remote backups, federation, Internet relays, public global username directories.
- A guarantee of delivery, minimal latency, a stable end-to-end path, or an accurate global view of network topology.
- Complex BGP/path-vector route advertisements or optimal route computation.
- Production-grade anonymity, censorship resistance, group-key management, file/media streaming, or attachment transfers.
- A multi-device identity system in which several devices simultaneously share one root BID (design space reserved for later).

---

## 2. Glossary and key distinctions

| Term | Definition |
| --- | --- |
| **Blendr node** | One running device/installation with storage, credentials, and a BLE adapter. |
| **Blendr Identity** | A user-owned asymmetric signing identity, independent of the Bluetooth hardware. |
| **BID** | Stable Blendr Identifier, derived from the public signing key. |
| **Display handle** | Human-readable `username#<BID-suffix>`. A suffix is not a unique or authenticated key on its own. |
| **Discovery token** | Temporary, rotating pseudorandom value used for radio-layer discovery when payload space allows. |
| **Neighbor** | A node currently within direct transport range. |
| **Jump** | One **intermediate relay device**, excluding original sender and final recipient. |
| **Link / transmission hop** | One device-to-device transfer; a delivery with `N` jumps normally uses `N + 1` links. |
| **Relay** | A node that forwards a message whose destination is another node. |
| **Store-carry-forward** | Save an undelivered envelope locally, wait for an eligible encounter, then forward. |
| **Broadcast post** | Content explicitly published to nearby/mesh participants. Not equivalent to private direct-message history. |
| **Sync** | Compare eligible message inventories and transfer only missing, authorized content. |

**Jump examples:** `A -> B` = **0 jumps**; `A -> R1 -> B` = **1 jump**; `A -> R1 -> R2 -> B` = **2 jumps**; `A -> R1 -> R2 -> R3 -> R4 -> R5 -> B` = **5 jumps**. The absolute v1 protocol cap is **five intermediate relays**.

---

## 3. Version scope

### Blendr v1 — Broadcast + mesh

- Generate/restore a decentralized identity and configure a display name.
- Advertise the Blendr service and discover other nearby nodes.
- Mutually authenticate sessions, exchange public profiles, and cache recognized peers.
- Create/read/search local conversation history.
- Send direct messages and explicitly published broadcast messages.
- Run bounded inventory exchange and duplicate-suppressing transfers.
- Support optional store-carry-forward with source, destination, and relay permissions; 0–5 jumps.
- Queue encrypted envelopes for forwarding, enforce TTL, quotas, and per-peer copy ceilings.
- Operate completely offline and persist after restart.

### Blendr v2 — Match mode (reserved, not implemented)

- Advertise minimal, user-approved matching metadata or commitments, not raw system fingerprints.
- Exchange relevant metadata in a selective, privacy-aware fashion.
- Independently evaluate compatibility and collect **two affirmative acceptances** before creating a matched relationship.
- Define protocol operations `MATCH_OFFER`, `MATCH_ACCEPT`, `MATCH_REJECT`, and `MATCH_ESTABLISHED` as a future version/capability namespace; reject them in v1.
- Additional research: metadata privacy, replay resistance, discovery correlation, and mismatch semantics.

---

## 4. Configuration contract — exactly one JSON file

**One device = one `config.json`**. It is the single editable configuration source for node behavior. Linux and Android use the same logical keys and validation rules. Each device owns its own copy; e.g. device A can use `display_name: "alice"` and device B `display_name: "bob"`.

The repository ships [`config.json`](./config.json) as a usable **development example**. On first run, `blendr init --config ./config.json` validates it, creates missing directories, initializes a new encrypted keystore and SQLite database, and prompts for any required encryption passphrase. It must **never overwrite an existing identity without explicit confirmation**. For a second device, copy `config.json` and change `node.display_name` before initialization.

**Not in JSON:** private signing keys, static encryption private keys, passphrases, ephemeral session secrets, actual messages, peer databases, or mutable sync state. These belong in a protected keystore, runtime memory, and SQLite. Thus there is one *configuration* file, not one file containing secrets and all persisted data.

**Configuration resolution:** Explicit CLI `--config PATH`, otherwise `./config.json` for the first prototype. Later, Linux can default to an XDG configuration directory and Android to app-private storage, while still using the **same JSON schema**. Relative paths resolve relative to the JSON file's directory, not the process working directory. Android UI settings update this one JSON atomically; no parallel SharedPreferences/DataStore authority for these settings. The private keystore is a separate secure-storage concern.

### Settings reference

| JSON path | Meaning | Default / validation |
| --- | --- | --- |
| `config_version` | Configuration schema revision, independent of wire protocol version. | `1`; reject unsupported revisions. |
| `node.display_name` | Chosen human-readable name. | `alice` in sample; nonempty, normalized, bounded UTF-8 length. |
| `node.mode` | Main operating mode. | `broadcast` only for v1. |
| `node.data_dir` | App-private storage root. | `./data`. |
| `node.start_discoverable` | Start discovery/advertising on launch. | `true`; effective only if BLE supported and authorized. |
| `identity.keystore_path` | Location of encrypted local private keys. | `./data/identity.enc`. |
| `identity.keystore_backend` | Key-protection backend. | `encrypted_file` for Linux first; native Android Keystore-backed option later. |
| `identity.display_bid_suffix_chars` | Only affects display; not cryptographic comparisons. | `12`; never authorize by suffix alone. |
| `discovery.*` | Service UUID, scan/advertising settings, peer aging, discovery rotation. | Platform clamps/schedules requests as hardware allows. |
| `discovery.auto_connect` | Connect on discovery without user selecting peer. | `false`; discovery itself remains automatic. |
| `transport.ble.*` | Adapter choice, application GATT UUIDs, MTU preference, framing, timeouts, retries. | Validate UUIDs, positive bounded integers, and peer capability. |
| `mesh.enabled` | Enable mesh policy engine. | `true`; direct messaging still works when disabled. |
| `mesh.outgoing.allow_jumps` | Permit messages originated locally to use relays. | `true`. |
| `mesh.outgoing.max_jumps` | Maximum intermediate relays allowed for messages **you originate**. | `3`, integer in **0..5**. |
| `mesh.incoming.accept_relayed_messages` | Accept messages delivered via at least one relay. | `true`. |
| `mesh.incoming.max_jumps` | Largest relayed path accepted at this destination. | `3`, integer in **0..5**. |
| `mesh.relay.enabled` | Volunteer to carry/forward *other people's* messages. | `false` by default to avoid surprise storage/battery use; user may opt in. |
| `mesh.relay.queue_*` | Space/count limits for message custody. | Hard upper bounds; backpressure when full. |
| `mesh.relay.max_distinct_peer_copies_per_message` | Upper bound on independent onward copies from a node. | `6`; duplicate transfer to same peer disallowed. |
| `mesh.routing.strategy` | Forwarding policy. | `bounded_epidemic` in v1. |
| `messaging.default_message_ttl_seconds` | Signed expiry policy for outgoing messages. | `86400` (24 hours). |
| `messaging.sharing.default_visibility` | New local messages private unless explicitly published. | `private`. |
| `messaging.sharing.*` | Inventory size, message count, byte limits per sync. | 20 messages and 16 KiB per session in sample. |
| `security.*` | Allowed identity, handshake, message-crypto, and trust policy suite. | Named interoperable suite; unsupported suite must fail. |
| `security.blocked_bids` | User-defined deny list, checked before session or sync. | Empty. |
| `storage.*` | SQLite location, WAL, cleanup/retention. | `0` history retention days = keep normal local history until user deletes it. |
| `observability.*` | Logging behavior; privacy-safe by default. | Never log message contents or full peer IDs by default. |
| `features.*` | Feature flags for current/future functionality. | Match, Wi-Fi, Internet relay disabled in v1. |

### Derived policies and strict validation

- `effective_outgoing_jumps = mesh.enabled && mesh.outgoing.allow_jumps ? mesh.outgoing.max_jumps : 0`.
- `effective_incoming_jumps = mesh.enabled && mesh.incoming.accept_relayed_messages ? mesh.incoming.max_jumps : 0`.
- For a *known* destination policy, an application can voluntarily select a smaller outgoing limit, but **the source's signed limit is authoritative on every path** and **the receiver's own check is authoritative on receipt**.
- `mesh.relay.enabled = false` means the node never queues/forwards messages addressed to other identities; it may still send and receive its own messages.
- `max_jumps` must be an integer **0 through 5**. Never silently clamp invalid user-supplied values; fail validation with a clear error.
- `scan_window_ms <= scan_interval_ms`; ensure GATT frame settings are valid for the negotiated connection. `preferred_mtu` is a *preference*, not a guaranteed on-air value.
- `features.match_mode_v2` **must** be `false` with v1 code; fail initialization if an unsupported feature is enabled.
- Reject unknown keys in the config v1 validator, or explicitly preserve them only under a future namespaced `extensions` field; avoid silent misconfiguration.
- Validate paths and file permissions; use atomic write (temporary file + rename) for settings changes; secrets never appear in logs or exception text.
- Configuration is loaded at startup for the CLI v1. A future `blendr config reload` can update noncritical settings; changes to `node.mode`, identity backend, or UUIDs require controlled restart. Already-created messages retain their signed hop limits even after local settings change.

### Example commands (design target, **not implemented yet**)

```sh
blendr init --config ./config.json
blendr doctor --config ./config.json
blendr start --config ./config.json
blendr peers --config ./config.json
blendr publish "Nearby message" --max-jumps 2
blendr send <full-BID> "Hello" --max-jumps 3
blendr inbox
blendr mesh status
```

An explicit `--max-jumps` on a command may **reduce** the configured outgoing ceiling, never increase it. CLI operations use the local node's config. Authentication and access policies are never relaxed by CLI flags.

---

## 5. Decentralized identity: Blendr Identity System (BIS)

### Identity generation and format

1. Generate a random **Ed25519 signing keypair** locally using a cryptographically secure RNG.
2. Derive `digest = SHA-256("blendr:identity:v1" || raw_ed25519_public_key)` (literal UTF-8 domain separator; fixed, canonical public-key bytes).
3. Encode digest with RFC 4648 Base32 without padding to produce the **full BID**. Do not truncate before storage, routing, verification, or signatures.
4. Render a friendly `username#<short-BID-suffix>` only for UI convenience; provide full BID, QR, and comparison fingerprint when checking a peer.
5. Generate a separate **X25519 encryption keypair** for addressed offline message encryption. Bind the X25519 *public* key to the BID through a canonical, Ed25519-signed identity document. Rotate encryption keys with signed epochs and retain appropriate old decrypt keys when necessary.
6. Save private signing/encryption keys only in a protected keystore. For Linux's encrypted file, use a vetted password-based KDF and authenticated encryption (not a bespoke obfuscator). Android will use platform-backed key protection where interoperable.

### Why not MAC/OS-derived identities?

Bluetooth private/random addresses can rotate; MACs and OS build details are not reliable cross-device identity sources. A hashed or heavily obfuscated hardware fingerprint can still permit tracking and cannot prove ownership. A cryptographic BID is stable, portable, and verifiable without a central issuer. A new keypair creates a new identity. Usernames are not unique and cannot authenticate a node.

### Identity operations

| Operation | Semantics |
| --- | --- |
| `IDENTITY_CREATE` | Generate Ed25519 + encryption keys and the full BID. |
| `IDENTITY_RESOLVE` | Read signed public identity material and recompute BID from signing key. |
| `IDENTITY_PROVE` | Sign a fresh session challenge bound to the transcript/nonces. |
| `IDENTITY_VERIFY` | Verify signature and matching BID; optional manual QR/fingerprint comparison. |
| `IDENTITY_UPDATE` | Sign a display-name and/or encryption-key update with monotonic version/epoch. |
| `IDENTITY_EXPORT` | Require local authorization and write an encrypted, authenticated backup. |
| `IDENTITY_IMPORT` | Restore a backup without silently overwriting an existing identity. |

**Trust:** v1 supports TOFU (trust on first use) with an explicit verified/unverified indicator, pinning of known public keys, and a way to block peers. A valid proof establishes *control of a key*, not real-world identity. QR/fingerprint comparison is the optional method to associate a BID with a person.

### Discovery identity separation

BLE advertisements carry the Blendr service UUID and optionally a rotating nonce/token if the controller's advertising payload capacity permits. They **must not** publish the full BID, private key, OS fingerprint, username, static hardware address, or entire identity document. Avoid assuming a rotating app token alone provides unlinkability: BLE controller address behavior and later stable identity exchange can still permit correlation.

---

## 6. Technical architecture

```text
┌───────────────────────────────────────────────────────────────┐
│ Application UI: linux-cli / future native Android Compose     │
├───────────────────────────────────────────────────────────────┤
│ Shared Rust Blendr Core                                       │
│ Identity | Discovery state | Handshake | Messaging | Sync      │
│ Mesh policy | Relay queue | Dedup | Framing | Config validator │
├───────────────────────────────────────────────────────────────┤
│ Storage boundary            │  Transport boundary             │
│ SQLite + encrypted keystore │  BleTransport / PeerLink traits │
├─────────────────────────────┴─────────────────────────────────┤
│ Linux: BlueZ/bluer + D-Bus  │ Android: Kotlin native BLE/JNI │
└───────────────────────────────────────────────────────────────┘
```

### Suggested Rust workspace

```text
blendr/
├── config.json                  # ONLY user-editable config file
├── plan.md
├── Cargo.toml                   # Rust workspace
├── crates/
│   ├── blendr-config/           # parse/validate config.json
│   ├── blendr-identity/         # keys, BID, signed profile, verification
│   ├── blendr-protocol/         # CBOR wire types, versions, handshake, sync
│   ├── blendr-transport/        # trait definitions, framing, memory adapter
│   ├── blendr-bluez/            # Linux BLE advertising/client/server
│   ├── blendr-mesh/             # routing policy, store/forward, dedup
│   ├── blendr-storage/          # SQLite, migrations, relay queue
│   └── blendr-ffi/              # future stable native bridge to Android
├── apps/
│   ├── linux-cli/               # Rust CLI and local UI foundation
│   └── android/                 # future Kotlin + Compose + Android BLE
└── tests/
    ├── wire-vectors/
    ├── simulation/
    └── hardware/
```

### Bluetooth abstraction

Transport interface capabilities (conceptual, not final Rust trait signatures):

```rust
trait BleTransport {
    async fn start_advertising(&self, service: ServiceId) -> Result<()>;
    async fn stop_advertising(&self) -> Result<()>;
    async fn watch_peers(&self) -> Result<PeerEventStream>;
    async fn connect(&self, peer: PeerLocator) -> Result<Box<dyn PeerLink>>;
    async fn accept_links(&self) -> Result<LinkEventStream>;
}

trait PeerLink {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<()>;
    async fn recv_frame(&mut self) -> Result<Vec<u8>>;
    async fn close(&mut self) -> Result<()>;
}
```

Real interfaces must support cancellation, link role, negotiated MTU/frame sizes, disconnection, backpressure, peer addresses opaque to the protocol core, and explicit scan/advertising state transitions. **Never expose OS Bluetooth MACs as Blendr identities.** GATT characteristics need working notify/indicate and write paths; implement application framing and reassembly across short ATT/GATT payloads.

**Linux adapter:** BlueZ D-Bus service discovery, `LEAdvertisingManager1`, `GattManager1`, and `GattCharacteristic1`. Rust `bluer` is the preferred first adapter because it has discovery, advertisement, GATT client/server examples. Confirm exact behavior and adapter capabilities on both test laptops; concurrent scanning and advertising may require scheduling rather than continuous dual-role use.

**Android adapter (phase after Linux):** Kotlin `BluetoothLeScanner`, `BluetoothLeAdvertiser`, `BluetoothGatt`, and `BluetoothGattServer`. Check runtime support for advertising/peripheral mode. Request appropriate Nearby Devices permissions (notably `BLUETOOTH_SCAN`, `BLUETOOTH_ADVERTISE`, `BLUETOOTH_CONNECT` on Android 12+); background limits require separate product decisions. No Flutter; core Rust functions are reached through explicit JNI/FFI APIs.

**Simulator:** An in-memory `MemoryTransport` must implement identical semantics (plus packet loss, delays, disconnects, radio-range changes) so 7-node/5-jump behavior can be tested before obtaining 7 physical Bluetooth devices.

---

## 7. Discovery and peer session protocol

### BLE design

- **Beacon:** fixed Blendr service UUID; optional short ephemeral discovery token only when advertisement space permits. Legacy advertisements can be constrained (often 31 bytes); do not require full identifiers or profiles in the beacon.
- **Scanning:** discover candidate devices broadcasting the service, persist an ephemeral `PeerLocator` until expired; show Nearby UI entries. Foreground discovery is the v1 baseline.
- **Connection:** deterministic tie-break (for example, compare ephemeral discovery tokens for that encounter) when both devices simultaneously try to connect; prevent duplicate concurrent sessions.
- **GATT service:** a Blendr service with RX/TX characteristics. Choose write/notify or indicate behavior based on actual adapter support; obtain MTU and frame size at runtime.
- **Capabilities:** negotiate protocol version, identity format, max application frame size, and feature flags after the secure handshake.
- **Trust boundary:** radio discovery by itself is unauthenticated. It is only a hint that *someone* claims the Blendr service UUID.

### Session establishment

```text
Device A                           Device B
  BLE advertisement  <---------->  BLE scan
  discover candidate              discover candidate
      |                                 |
      +----------- BLE GATT link -------+
      |                                 |
      +--- mutual Noise XX handshake --+
      |   authenticate signed identity  |
      |   verify BID-key binding        |
      +------ capability exchange ------+
      +----- inventory / sync offer ----+
      +--- encrypted frame transfers ---+
      +---- ACK / disconnect / resume --+
```

Use a well-reviewed **Noise XX** implementation for the peer session, with X25519 static/session public keys cryptographically bound to the signed BID identity document. **Binding must be verified before treating the peer as authenticated.** Do not implement a custom key exchange. Add a transcript-bound challenge/identity signature as needed; verify role/capability negotiation to prevent downgrade and identity misbinding. Application-level authenticated encryption is mandatory even if link-layer Bluetooth encryption is enabled.

### Initial wire-message types

`HELLO`, `IDENTITY_DOCUMENT`, `IDENTITY_PROOF`, `CAPABILITIES`, `INVENTORY_OFFER`, `INVENTORY_REQUEST`, `MESSAGE_TRANSFER`, `LINK_ACK`, `DESTINATION_RECEIPT`, `ERROR`, `GOODBYE`.

Encode using **deterministic/canonical CBOR** for hashes/signatures. Include explicit message type, protocol version, feature negotiation, maximum decoded size and type validation. Never execute or deserialize arbitrary object types from untrusted peers.

---

## 8. Messaging, publication, and synchronization

### Privacy classes

1. **Private local-only:** stays on its creator's device; no advertisements, message inventories, or sync.
2. **Direct addressed:** encrypted for the intended recipient BID; relays may carry opaque envelopes if permitted, but cannot read the plaintext. Destination metadata is generally visible to relays in v1, so Blendr does **not** promise metadata anonymity.
3. **Public broadcast:** content explicitly published for local/mesh sharing. It is signed, may be readable by recipients and relays, and must not contain another user's private messages unless that user deliberately shares them.

### Sync negotiation

1. Authenticate neighbor and check blocked identities and session limits.
2. Exchange small, bounded summaries of eligible messages (IDs + minimal metadata); never send the entire local database.
3. Ask for only missing messages that pass visibility, lifetime, intended audience and destination policy checks.
4. Transfer in bounded batches (default 20 messages/16 KiB per session) using reliable framed delivery with retries and idempotent insertion.
5. A **link ACK** means the next peer received and persisted the envelope; a **destination receipt** means the final recipient accepted it. Neither should be confused with the recipient having read the message. Delivery receipts can themselves be queued/routed later.
6. Persist send/receive ledger and deduplication state to avoid resending all data on reconnect. Deterministic pagination is needed when a peer has more than the session budget.

### Outgoing end-to-end encryption

For direct addressed messages, use standardized **HPKE** (X25519 + HKDF-SHA256 + ChaCha20-Poly1305) with a vetted library, based on the recipient's signed encryption public key. Store the selected recipient encryption key epoch. Sign immutable envelope fields with the sender's Ed25519 key; use domain-separated encodings and authenticate recipient/context. When recipients are offline, the encrypted envelope can still be passed to authorized relays. Key rotation and lost-key handling require explicit behavior (old ciphertext may become unreadable if old private keys are erased).

---

## 9. Multi-hop mesh: jumps and policies

### Independently configurable controls

| Owner of rule | JSON settings | Effect |
| --- | --- | --- |
| **Sender / originator** | `mesh.outgoing.allow_jumps`, `mesh.outgoing.max_jumps` | Sets a **signed ceiling** on relays a new outgoing envelope may traverse. |
| **Receiver / destination** | `mesh.incoming.accept_relayed_messages`, `mesh.incoming.max_jumps` | Decides whether to deliver a message received via relays and the maximum incoming jumps. |
| **Every intermediary** | `mesh.relay.enabled`, queue/copy quotas | Determines whether this node stores/forwards third-party envelopes at all. |

Example: A sets outgoing max 4; B accepts up to 2 incoming jumps. The actual path can have no more than **2** relays if B is to accept it. But A might not know B's current incoming preference. Therefore **the source cannot guarantee** a path it sends will be accepted; final policy enforcement belongs to B.

### Exact accounting

- A newly originated message has `jumps_used = 0`.
- A **direct** delivery from A to final recipient B arrives with `jumps_used = 0`.
- If an intermediate node R receives the message from A, R increments the mutable counter **from 0 to 1 before forwarding** it to the next peer. `A -> R -> B` reaches B with `jumps_used = 1`.
- Every additional forwarding intermediary adds one. Reject an attempted relay-forward where the *new* counter would exceed signed `max_jumps`; v1 absolute cap is five.
- Do not treat a message reaching its final destination as a relay jump. Link transmissions and relay jumps are intentionally different counters.
- Never forward an expired, blocked, duplicate-for-that-peer, oversize, or non-shareable message.

### Envelope model (illustrative JSON; actual wire encoding is CBOR)

```json
{
  "protocol": "BLENDR",
  "version": 1,
  "type": "MESSAGE_TRANSFER",
  "message_id": "<random-or-UUIDv7-identifier>",
  "origin_bid": "<full-origin-BID>",
  "destination_bid": "<full-destination-BID-or-BROADCAST>",
  "visibility": "direct",
  "created_at_ms": 0,
  "expires_at_ms": 0,
  "routing": {
    "max_jumps": 3,
    "jumps_used": 1,
    "previous_peer_hint": "<ephemeral-session-reference>"
  },
  "payload": "<HPKE-encrypted-bytes>",
  "signature": "<Ed25519-signature-over-canonical-immutable-fields>"
}
```

The origin signature covers immutable fields including destination, visibility, creation/expiry, payload hash, maximum jumps, and message ID. Mutable forwarding fields like `jumps_used` are authenticated **on the current peer link**, not by the origin signature. Cooperative relays can enforce budgets; **malicious/colluding relays can under-report path length**. A signed hop-chain can improve tamper evidence, but cannot fully prove physical traversal without stronger trust assumptions. Do not claim cryptographically perfect enforcement of observed jump count in v1.

### Forwarding algorithm (v1 bounded epidemic gossip)

```text
on receive(envelope, authenticated_neighbor):
  reject if invalid signature/format/size/expiry or blocked source
  reject if duplicate envelope already processed with equal/better route
  if local BID is destination:
      if jumps_used > effective_incoming_jumps: reject
      decrypt, validate, store idempotently, send destination receipt
  else if envelope is public broadcast:
      if local acceptance policy permits: store/display published content
      optionally consider relay forwarding (below)
  if not mesh.enabled or not mesh.relay.enabled: stop
  if source policy is direct-only or next jump would exceed max_jumps: stop
  if queue quota or peer copy budget exceeded: stop
  store encrypted/signed envelope with routing state and expiry
  on encounter with eligible other neighbor:
      offer small summary; forward missing authorized envelope
      increment jumps_used if local node is acting as intermediary
      record per-peer copy and link receipt
```

**Important implementation nuance:** an intermediary must not forward a message to the peer it just obtained it from (unless a new, explicitly justified state exists), and a deduplication key should include message ID and usable route-state quality so receiving one copy does not accidentally discard a better-budget duplicate. Do not forward the same message indefinitely after a destination receipt. No guarantees of delivery or minimal route length.

### Delay-tolerant example

At 10:00 A meets R1, which stores an opaque encrypted message addressed to B. At 11:00 R1 meets R2 and passes the message on (within its jump budget). At 16:00 R2 meets B; B decrypts and stores it. No time at which all three links were simultaneously present was required. Relays may also drop messages due to TTL, quotas, battery state, or opting out.

### Resource protection

- Default **relay disabled** until a user explicitly volunteers a node; send and receive still work.
- Dedicated relay queue with byte/count quotas separate from primary personal history.
- Signed expiration and relay cleanup, subject to local-clock limitations. An incorrect clock can cause early/late discards; detect abnormal skew if possible and never promise exact TTL behavior across untrusted clocks.
- Size ceilings before allocation, per-peer rate limits, connect cooldowns, bounded inventory lists, and transfer/concurrency caps.
- Signed content prevents modification of original messages; encryption protects direct-message plaintext from honest relays, not traffic metadata.
- Untrusted messages remain quarantined until verified; do not allow a signature or public BID to imply the sender is socially trusted.
- Add local peer blocking and opt-out controls; test abuse with malicious peers flooding unique IDs.

### Why this is not BGP

BGP is a path-vector routing **control protocol** between autonomous systems, advertising reachability to IP prefixes. Blendr's initial design is **opportunistic store-carry-forward** for intermittently connected personal devices. It borrows the *idea* of independently enforced route/forwarding policy but does not require stable routing tables, Internet connectivity, BGP peering, or global topology knowledge. Future encounter-based routing (for example, probability derived from past contacts) may reduce redundant flooding; it should follow real measurements.

---

## 10. Persistence model

Suggested SQLite entities:

| Table | Important fields / invariant |
| --- | --- |
| `identities` | `bid`, public identity document, version/epoch; **no plaintext private keys**. |
| `peers` | `bid`, public key, user-visible name, trust status, first/last encountered. |
| `conversations` | Local conversation ID, type (`direct`/`broadcast`), owner, settings. |
| `messages` | `message_id` unique, origin BID, destination, visibility, signed envelope, ciphertext or own plaintext where appropriate, timestamps, status. |
| `relay_queue` | message ID, current route state, expiry, custody flags, stored bytes; bounded by config. |
| `seen_messages` | message ID, best-known jump count, timestamps, dedupe metadata. |
| `peer_delivery_ledger` | `(peer_bid, message_id)` unique, offer/transferred/ack states, latest encounter. |
| `encounters` | ephemeral discovery/session history, timestamps, coarse transport diagnostics. |
| `profile_versions` | BID, signed display-name and encryption-key epochs. |
| `receipts` | Link receipt vs final destination receipt, distinct semantics. |

Use transactions to atomically persist an inbound envelope and its deduplication state **before** issuing a custody-style link ACK. `WAL` mode allows local reads/writes without maintaining a server. Standard personal messages are never deleted solely because the relay queue is full. Privacy-preserving deletion and secure data-at-rest handling need platform-specific review; SQLite itself does not imply full-database encryption.

---

## 11. Delivery and UI workflows

### First Linux CLI workflow

1. On device A, edit `node.display_name` to `alice`; run `blendr init --config config.json`. New keys/BID are generated locally.
2. On device B, edit its local copy to `bob`; initialize a different identity.
3. Both run `blendr start`; BLE advertise/scan begins and nearby candidates appear automatically.
4. User selects a discovered peer (or later enables safe auto-connect). Blendr opens BLE GATT, establishes a secure session, verifies BIDs, and displays `bob#<suffix>` / `alice#<suffix>`.
5. A sends a direct message. B accepts and stores it locally, then the reply flows back.
6. Each device keeps history after stopping and restarting; reconnect exchanges only missing, permitted messages.
7. User explicitly publishes a broadcast post; other eligible peers sync it without gaining access to private history.
8. A third simulated or physical device enables `mesh.relay.enabled` to demonstrate multi-hop forwarding.

### Future Android native UI

- **Nearby:** automatically discovered peer cards with verification/trust badges; present expected caveats for radio proximity.
- **Chats:** direct conversations and optional broadcast feed, with private-by-default compose controls.
- **Identity:** display handle, full BID, fingerprint comparison, QR, profile edits, encrypted backup/restore.
- **Mesh:** outgoing max jumps 0–5; incoming accept/limit 0–5; relay on/off; queue and data limits; current relay usage.
- **Permissions:** understandable Nearby Devices consent and foreground/background status; Bluetooth state diagnostic.
- **Settings:** UI writes the single `config.json` through the same validated configuration API.

---

## 12. Incremental implementation plan

### Phase 0 — Repository, spec, and config (start here)

**Build:** Rust workspace, `blendr-config`, common errors, README, `config.json` parser/validator, atomic writes, feature/version checks, CI formatting/linting/tests. Create `blendr doctor` output showing parsed nonsecret settings and adapter prerequisites.

**Definition of done:** Both Linux hosts parse independent JSON configurations; invalid jumps (`-1`, `6`, fractions), unknown features, bad UUIDs, and broken paths fail with precise messages. No secret material enters JSON or logs.

### Phase 1 — Local identity and storage

**Build:** Ed25519 key generation, Base32 BID, identity document and key epochs, encrypted keystore, initialization idempotence, signed profile update, SQLite migrations, local message insert/read, key backup/restore tests.

**Definition of done:** Restarts retain the same BID, the username can change independently, a second clean installation has a different BID, and signature proof is verified end-to-end with test vectors.

### Phase 2 — Linux BLE hardware spike (two physical nodes)

**Build:** `blendr-bluez` advertiser, scan stream, GATT server/client, connection election, event logging, MTU discovery, fragmentation/reassembly, timeout/retry/cancellation. Capture actual BLE controller limitations and BlueZ version for both Linux devices.

**Definition of done:** A and B discover each other in the foreground without Internet, open a connection, and transfer multiple fragmented test frames both ways. Test simultaneous scan/advertise and document any need for time-slicing.

### Phase 3 — Secure sessions and one-to-one chat

**Build:** Noise XX session, signed BID binding, anti-replay/session nonces, capabilities, CBOR frames, recipient HPKE, direct message creation and storage, delivery ACK distinction, peer pinning/verification.

**Definition of done:** A ↔ B messages are locally persistent and correctly authenticated; a malicious peer cannot impersonate an existing BID simply by announcing it; broken frames, replayed sessions, and modified ciphertext are rejected.

### Phase 4 — Bounded Broadcast mode sync

**Build:** explicitly shareable posts, inventory/offer/request, bounded pagination, per-session bytes/count, duplicate suppression, local feed UI/CLI, restart resume behavior.

**Definition of done:** Users can see nearby broadcast-enabled nodes and receive only opted-in posts under the configured byte/message budget, with private history never enumerated.

### Phase 5 — Mesh engine and simulated 7-node test

**Build:** outgoing/incoming/relay policy evaluation, signed immutable envelope with hop ceiling, mutable link-authenticated relay count, bounded relay queue, TTL, seen ledger, per-peer copies, bounded epidemic forwarding, test `MemoryTransport` with simulated moves/connectivity.

**Definition of done:** Paths with exactly 0, 1, 2, and 5 intermediate nodes are accepted when permitted; a sixth relay is blocked. Relay-off devices neither enqueue nor forward third-party traffic. Receiver limits are enforced even if sender permitted more. Retries and cycles do not create unbounded copies.

### Phase 6 — Real mesh test, Linux CLI polish

**Build:** third physical BLE Linux node when available; validate A → relay → B; test interrupted transfers, moving out of range, identity restart, forwarding after reconnect, quota saturation, and blocked peers. Expose `blendr mesh status` and accessible error diagnostics.

**Definition of done:** A message addressed to B arrives via the third node while A and B are never directly connected during the test, using one relay jump; queue/copy/TTL limits are visible and predictable.

### Phase 7 — Native Android interoperability

**Build:** Kotlin native BLE adapter, Gradle/Compose app, Rust JNI/FFI, Android keystore integration, permissions, foreground scanning UI, Android ↔ Linux message format and crypto tests; reuse the same logical `config.json` schema.

**Definition of done:** Linux and Android can discover, authenticate, exchange direct/broadcast messages, and (subject to device capabilities/foreground policies) participate in relays without changing core wire formats.

### Phase 8 — Performance, security, and protocol v1 freeze

**Build:** measure discovery latency, successful pair rate, bytes/energy per message, MTU fragmentation overhead, forwarding duplication, relay queue pressure, and time-to-delivery under simulated contact schedules. Perform threat modeling, fuzz CBOR/handshake inputs, freeze message vectors, document compatibility and migrations.

**Definition of done:** Conformance tests and validated multi-node cases pass on both platforms; known limitations are recorded and `BLENDR/1` framing is versioned.

---

## 13. Test and acceptance matrix

| Test | Expected outcome |
| --- | --- |
| Two Linux machines, no network | Mutual discovery and direct transfer through BLE. |
| Two instances on one computer with MemoryTransport | Same protocol semantics without hardware. |
| Restart A and B | Persistent BID and conversation history. |
| Rename `alice` to `alice2` | BID unchanged; signed profile change accepted. |
| Alter claimed BID without matching private key | Authentication fails. |
| Disable sharing on a private conversation | No plaintext or inventory metadata for that conversation leaves the device. |
| Sync 300 shareable messages | Each session respects 20-message and 16 KiB budget; pages eventually progress. |
| `allow_jumps = false` or outgoing max 0 | Direct delivery allowed; intermediaries cannot legitimately forward. |
| Receiver disallows relayed messages | Direct delivery accepted; ≥1-jump message rejected. |
| Receiver max 2 / sender max 5 | Delivered through 0–2 relays, rejected through 3–5. |
| Relay feature disabled on intermediate | No third-party forwarding or custody. |
| Simulated A → R1 → … → R5 → B | Exactly five intermediary jumps can deliver. |
| Simulated A → R1 → … → R6 → B | Sixth intermediary cannot legitimately forward within signed cap. |
| Loop A → R1 → R2 → R1 | Dedupe/peer ledger suppresses indefinitely repeated forwarding. |
| Queue full, expired messages, invalid frames | Deterministic rejection, no crash or primary-history loss. |
| Session disconnect mid-message | Incomplete frame discarded; reconnect resumes safely. |
| Android ↔ Linux interoperability | Same v1 wire IDs/crypto; capability limitations surfaced, not silently ignored. |

### Performance targets (initial hypotheses, **not measured guarantees**)

- Small encrypted texts and control messages first; no attachment streaming.
- Discover nearby foreground peers in a human-usable interval, subject to controller/OS scheduling.
- Bound every message, inventory, frame, relay queue, and concurrent session by validated config.
- Each relay should avoid redistributing identical bytes to peers that already acknowledged them.
- Report median and tail discovery/transfer time and energy/byte measurements before tuning defaults.

---

## 14. Threat model, limitations, and open decisions

### Threats v1 must address

- Identity impersonation and forged signed messages.
- Radio eavesdropping, replay, frame injection, and malicious/corrupted payloads.
- Privacy leaks from automatic sync, long-lived advertisements, and logged identifiers.
- Relay flooding, storage exhaustion, denial of service, loops, oversized messages.
- Malicious relays withholding, dropping, duplicating or fabricating mutable routing counters.
- Loss/theft of local keys, backup mishandling, compromised device storage.

### Explicit security guarantees and non-guarantees

- **Guaranteed by design if correctly implemented:** decentralized key control, signature-authenticated origin fields, encrypted private-message payloads to intended recipients, opt-in publication, configurable local forwarding policies, bounded resource allocation.
- **Not guaranteed:** message delivery, always-on Bluetooth, recipient anonymity, physical identity verification, traffic-analysis resistance, truthful path lengths from adversarial relays, protection after a device/key compromise.
- **No silent sharing:** Local private conversations cannot be inferred or offered by sync. Identity profile exchange is explicit session metadata, not universal anonymous anonymity.

### Decisions to validate with prototypes

1. **Linux adapter interoperability:** whether both real adapters support stable concurrent BLE scan, advertise, GATT client/server; fallback duty cycle if not.
2. **Android peripheral availability:** actual hardware advertising capability and policy constraints across target test phones.
3. **GATT frame negotiation:** preferred MTU, maximum fragment size, notification/write reliability, reconnection behavior.
4. **Cryptographic libraries:** select audited, maintained crates for Ed25519, X25519, Noise XX, HPKE, KDF and secure keystore; freeze exact test vectors.
5. **Public broadcast mesh semantics:** whether all public posts are eligible for forwarding by default or only posts with an explicit `mesh_publish` flag. Privacy-preserving default: distinct opt-in to publish beyond immediate neighbors.
6. **Relay accounting with forks:** retain routing counters per message copy; dedupe should prefer a copy with more remaining jump budget, within strict overall copy/resource quotas.
7. **Key rotation/recovery:** signed encryption-key epochs and encrypted backups without registry or password-reset server.
8. **Stable identity versus unlinkability:** persistent BID makes recognition possible after handshake; stronger pseudonym separation would be future work.

---

## 15. References and implementation sources

These are design references rather than external infrastructure requirements:

- [BlueZ LE Advertising Manager API](https://github.com/bluez/bluez/blob/master/doc/org.bluez.LEAdvertisingManager.rst) — advertising registration and controller constraints.
- [BlueZ GATT Manager API](https://github.com/bluez/bluez/blob/master/doc/org.bluez.GattManager.rst) — publishing an application GATT service.
- [BlueZ GATT Characteristic API](https://github.com/bluez/bluez/blob/master/doc/org.bluez.GattCharacteristic.rst) — local and remote characteristics.
- [BlueR / bluer Rust project](https://github.com/bluez/bluer) — Linux Rust BLE implementation and examples.
- [Android BLE overview](https://developer.android.com/develop/connectivity/bluetooth/ble/ble-overview) — Android central/peripheral and GATT roles.
- [Android Bluetooth permissions](https://developer.android.com/develop/connectivity/bluetooth/bt-permissions) — scanning, advertising, connecting permission requirements.
- [RFC 9171: Bundle Protocol v7](https://www.rfc-editor.org/rfc/rfc9171.html) — store-carry-forward, lifetime, hop-count inspiration; **Blendr's user-facing jump definition is different from its standardized hop count**.
- [RFC 9180: Hybrid Public Key Encryption (HPKE)](https://www.rfc-editor.org/rfc/rfc9180.html) — standard offline addressed-message encryption construction.
- [Noise Protocol Framework](https://noiseprotocol.org/noise.html) — authenticated secure session patterns.

---

## 16. Immediate next action

**Implement Phase 0 and Phase 1 first**: a Rust workspace with `blendr-config`, identity generation/BID resolution, encrypted keystore, SQLite schema, and `blendr init` / `blendr doctor`. Then make two Linux devices discover each other through BlueZ before introducing message forwarding. Keep the in-memory BLE substitute from the beginning so mesh correctness is testable without seven devices.
