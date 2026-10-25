//! Networked commands: `start`, `peers`, `send`, and the direct-message half
//! of `inbox`.
//!
//! Every command that touches the radio follows the same shape: unlock the
//! keystore, open the store, build a [`blendr_messaging::Node`], then run a
//! single sequential event loop over discovery events and accepted links.
//! One exchange runs at a time; the BlueZ adapter performs election when both
//! sides dial simultaneously. Locators are redialed at most once per
//! `REDIAL_INTERVAL` so a failing peer does not starve the loop.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use blendr_bluez::BluezTransport;
use blendr_messaging::{HistoryMessage, MessagingError, Node, Settings};
use blendr_storage::{Store, TrustStatus};
use blendr_transport::{BleTransport, PeerEvent, PeerLink, PeerLocator};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{Cli, Fail, PeerCommands, handle, load_node, open_node, open_store, runtime, secrets};

/// Minimum delay between outbound dials to the same locator.
const REDIAL_INTERVAL: Duration = Duration::from_secs(60);
/// Bound on orderly transport teardown after the event loop ends.
const SHUTDOWN_BUDGET: Duration = Duration::from_secs(20);

enum LoopEnd {
    /// The command's deadline elapsed (only when a deadline was configured).
    Deadline,
    /// Ctrl-C stopped a run with no configured deadline.
    Interrupted,
    /// The `stop` predicate ended the run early.
    Finished,
    /// A transport event channel closed before the run was done.
    Closed(&'static str),
}

fn messaging_fail(err: MessagingError) -> Fail {
    runtime(format!("{err}"))
}

/// Unlock the keystore, open the store, and construct the messaging node.
fn open_messaging(cli: &Cli) -> Result<(blendr_config::Config, Node), Fail> {
    let (config, paths) = load_node(&cli.config)?;
    let passphrase =
        secrets::existing_passphrase(cli.passphrase_file.as_deref(), "keystore passphrase")?;
    let (identity, store) = open_node(&config, &paths, passphrase.as_str())?;
    let settings = Settings::from_config(&config).map_err(messaging_fail)?;
    let node = Node::new(identity, store, settings).map_err(messaging_fail)?;
    Ok((config, node))
}

fn runtime_on<F, T>(f: F) -> Result<T, Fail>
where
    F: Future<Output = Result<T, String>>,
{
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| runtime(format!("cannot start async runtime: {e}")))?;
    rt.block_on(f).map_err(runtime)
}

fn warn(message: impl std::fmt::Display) {
    eprintln!("blendr: warning: {message}");
}

/// Tunables for one transport session. `expected_peer` restricts every
/// exchange to one authenticated BID. `input`/`on_input` are an optional
/// stdin-style feed: each line arriving on the channel is handed to
/// `on_input` immediately inside the event loop, so chat text queues the
/// moment it's typed rather than waiting for the next link event.
struct Session<'a> {
    duration: Option<Duration>,
    expected_peer: Option<String>,
    announce: Option<String>,
    redial: Duration,
    stop: &'a mut dyn FnMut(&Node, u32) -> bool,
    input: Option<tokio::sync::mpsc::UnboundedReceiver<String>>,
    on_input: Option<&'a mut InputHook<'a>>,
    /// Runs after every exchange *attempt* (success or failure) so callers
    /// can flush received state — e.g. `chat` prints incoming messages even
    /// when the session dies at goodbye teardown after delivery.
    after_exchange: Option<&'a mut dyn FnMut(&Node)>,
}

/// Line handler signature for the stdin-style `input` feed. The object
/// lifetime must be parameterized or it defaults to `'static`.
type InputHook<'a> = dyn FnMut(&mut Node, String) + 'a;

/// Create the transport, start advertising, then run the event loop; always
/// tears the transport down afterward.
async fn transport_session(
    config: &blendr_config::Config,
    node: &mut Node,
    mut session: Session<'_>,
) -> Result<LoopEnd, String> {
    let service: Uuid = config
        .transport
        .ble
        .gatt_service_uuid
        .parse()
        .map_err(|_| "invalid transport.ble.gatt_service_uuid".to_string())?;
    let transport = BluezTransport::new(config)
        .await
        .map_err(|e| format!("adapter setup: {e}"))?;
    let result = session_loop(&transport, node, service, &mut session).await;
    let shutdown = tokio::time::timeout(SHUTDOWN_BUDGET, transport.shutdown()).await;
    match shutdown {
        Err(_) => warn("transport shutdown deadline expired"),
        Ok(Err(e)) => warn(format!("transport shutdown: {e}")),
        Ok(Ok(())) => {}
    }
    result
}

async fn session_loop(
    transport: &BluezTransport,
    node: &mut Node,
    service: Uuid,
    session: &mut Session<'_>,
) -> Result<LoopEnd, String> {
    let mut peers = transport
        .watch_peers()
        .await
        .map_err(|e| format!("peer watch: {e}"))?;
    let mut inbound = transport
        .accept_links()
        .await
        .map_err(|e| format!("inbound link setup: {e}"))?;
    transport
        .start_advertising(service)
        .await
        .map_err(|e| format!("advertising: {e}"))?;
    if let Some(text) = &session.announce {
        println!("{text} (adapter {})", transport.adapter_name());
    }

    let cancel = CancellationToken::new();
    let deadline = session.duration;
    let work = event_loop(transport, node, &mut peers, &mut inbound, &cancel, session);
    if let Some(deadline) = deadline {
        match tokio::time::timeout(deadline, work).await {
            Err(_) => Ok(LoopEnd::Deadline),
            Ok(done) => done,
        }
    } else {
        work.await
    }
}

async fn event_loop(
    transport: &BluezTransport,
    node: &mut Node,
    peers: &mut tokio::sync::mpsc::Receiver<PeerEvent>,
    inbound: &mut tokio::sync::mpsc::Receiver<Box<dyn PeerLink>>,
    cancel: &CancellationToken,
    session: &mut Session<'_>,
) -> Result<LoopEnd, String> {
    let mut attempts: HashMap<PeerLocator, Instant> = HashMap::new();
    let mut exchanges = 0u32;
    loop {
        let link = tokio::select! {
            _ = cancel.cancelled() => return Ok(LoopEnd::Interrupted),
            event = peers.recv() => match event {
                Some(PeerEvent::Discovered(locator)) => {
                    let recent = attempts
                        .get(&locator)
                        .is_some_and(|at| at.elapsed() < session.redial);
                    if recent {
                        continue;
                    }
                    attempts.insert(locator.clone(), Instant::now());
                    match transport.connect(locator, cancel).await {
                        Ok(link) => Some(link),
                        Err(e) => {
                            warn(format!("connect: {e}"));
                            None
                        }
                    }
                }
                Some(PeerEvent::Lost(locator)) => {
                    attempts.remove(&locator);
                    continue;
                }
                None => return Ok(LoopEnd::Closed("discovery channel closed")),
            },
            link = inbound.recv() => match link {
                Some(link) => Some(link),
                None => return Ok(LoopEnd::Closed("accept channel closed")),
            },
            line = async {
                session.input.as_mut().unwrap().recv().await
            }, if session.input.is_some() && session.on_input.is_some() => {
                match line {
                    Some(text) => {
                        let hook = session.on_input.as_deref_mut().unwrap();
                        hook(node, text);
                    }
                    None => session.input = None,
                }
                continue;
            }
        };
        let Some(link) = link else { continue };
        match run_exchange(node, link, session.expected_peer.clone(), cancel).await {
            Ok(()) => {
                if let Some(hook) = session.after_exchange.as_deref_mut() {
                    hook(node);
                }
                exchanges += 1;
                if (session.stop)(node, exchanges) {
                    return Ok(LoopEnd::Finished);
                }
            }
            Err(e) => {
                warn(format!("exchange: {e}"));
                if let Some(hook) = session.after_exchange.as_deref_mut() {
                    hook(node);
                }
            }
        }
    }
}

/// One authenticated exchange; the session owns and closes the link.
async fn run_exchange(
    node: &mut Node,
    link: Box<dyn PeerLink>,
    expected_peer: Option<String>,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let report = node
        .exchange(link, expected_peer, cancel)
        .await
        .map_err(|e| e.to_string())?;
    println!(
        "peer {} authenticated ({})",
        report.peer.bid, report.peer.display_name
    );
    println!(
        "  exchange: sent={} received={} destination_receipts={} broadcast_sent={} broadcast_received={}",
        report.sent,
        report.received,
        report.destination_receipts,
        report.broadcast_sent,
        report.broadcast_received
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

pub(crate) fn start(cli: &Cli, duration: Option<u64>, once: bool) -> Result<(), Fail> {
    let (config, mut node) = open_messaging(cli)?;
    node.settings().validate_network().map_err(messaging_fail)?;
    env_logger::init_from_env(
        env_logger::Env::default().default_filter_or("off,blendr_bluez=warn"),
    );
    let announce = format!("node {} listening", handle(&config, node.bid()));
    let end = runtime_on(transport_session(
        &config,
        &mut node,
        Session {
            duration: duration.map(Duration::from_secs),
            expected_peer: None,
            announce: Some(announce),
            redial: REDIAL_INTERVAL,
            stop: &mut |_, exchanges| once && exchanges >= 1,
            input: None,
            on_input: None,
            after_exchange: None,
        },
    ))?;
    match end {
        LoopEnd::Finished => println!("one exchange complete; stopping"),
        LoopEnd::Deadline => println!("duration elapsed; stopping"),
        LoopEnd::Interrupted => println!("interrupted; stopped"),
        LoopEnd::Closed(what) => return Err(runtime(format!("node stopped: {what}"))),
    }
    Ok(())
}

pub(crate) fn peers(
    cli: &Cli,
    scan: bool,
    duration: u64,
    action: Option<&PeerCommands>,
) -> Result<(), Fail> {
    if let Some(action) = action {
        if scan {
            return Err(runtime(
                "peer trust actions do not scan; run `peers --scan` separately",
            ));
        }
        return peer_action(cli, action);
    }
    if scan {
        let (config, mut node) = open_messaging(cli)?;
        node.settings().validate_network().map_err(messaging_fail)?;
        env_logger::init_from_env(
            env_logger::Env::default().default_filter_or("off,blendr_bluez=warn"),
        );
        let end = runtime_on(transport_session(
            &config,
            &mut node,
            Session {
                duration: Some(Duration::from_secs(duration)),
                expected_peer: None,
                announce: Some(format!("scanning for peers ({duration}s)")),
                redial: REDIAL_INTERVAL,
                stop: &mut |_, _| false,
                input: None,
                on_input: None,
                after_exchange: None,
            },
        ))?;
        if let LoopEnd::Closed(what) = end {
            return Err(runtime(format!("scan stopped early: {what}")));
        }
        println!("scan complete");
        print_peers(node.store()).map_err(messaging_fail)?;
        return Ok(());
    }
    let (config, paths) = load_node(&cli.config)?;
    let store = open_store(&config, &paths)?;
    print_peers(&store).map_err(messaging_fail)
}

fn print_peers(store: &Store) -> Result<(), MessagingError> {
    let peers = store.peers()?;
    if peers.is_empty() {
        println!("no known peers; run `blendr peers --scan` to authenticate nearby nodes");
        return Ok(());
    }
    for peer in peers {
        let trust = match peer.trust {
            TrustStatus::Unverified => "unverified",
            TrustStatus::Verified => "verified",
            TrustStatus::Blocked => "blocked",
        };
        println!(
            "{}  {}  {}  last_seen={}",
            peer.document.bid, trust, peer.document.display_name, peer.last_seen_ms
        );
    }
    Ok(())
}

fn peer_action(cli: &Cli, action: &PeerCommands) -> Result<(), Fail> {
    let (config, paths) = load_node(&cli.config)?;
    let mut store = open_store(&config, &paths)?;
    match action {
        PeerCommands::Verify { bid, fingerprint } => {
            let key = parse_fingerprint(fingerprint)?;
            store
                .verify_peer(bid, &key)
                .map_err(|e| runtime(format!("cannot verify peer: {e}")))?;
            println!("peer {bid} verified");
        }
        PeerCommands::Block { bid } => {
            store
                .set_peer_blocked(bid, true)
                .map_err(|e| runtime(format!("cannot block peer: {e}")))?;
            println!("peer {bid} blocked");
        }
        PeerCommands::Unblock { bid } => {
            store
                .set_peer_blocked(bid, false)
                .map_err(|e| runtime(format!("cannot unblock peer: {e}")))?;
            println!("peer {bid} unblocked (trust reset to unverified)");
        }
    }
    Ok(())
}

/// Decode the 64-hex-character signing key printed by `identity show`.
fn parse_fingerprint(fingerprint: &str) -> Result<[u8; 32], Fail> {
    let invalid = || {
        runtime("fingerprint must be the exact 64-hex-character signing key from `identity show`")
    };
    if fingerprint.len() != 64 {
        return Err(invalid());
    }
    let mut key = [0u8; 32];
    let (pairs, _) = fingerprint.as_bytes().as_chunks::<2>();
    for (i, [hi, lo]) in pairs.iter().enumerate() {
        let hi = (*hi as char).to_digit(16).ok_or_else(invalid)?;
        let lo = (*lo as char).to_digit(16).ok_or_else(invalid)?;
        key[i] = ((hi << 4) | lo) as u8;
    }
    Ok(key)
}

pub(crate) fn send(
    cli: &Cli,
    to: &str,
    text: &str,
    queue_only: bool,
    timeout_seconds: u64,
) -> Result<(), Fail> {
    let (config, mut node) = open_messaging(cli)?;
    let id = node
        .queue(
            to,
            text,
            blendr_messaging::now_ms().map_err(messaging_fail)?,
        )
        .map_err(messaging_fail)?;
    println!("queued {id}");
    if queue_only {
        return Ok(());
    }
    node.settings().validate_network().map_err(messaging_fail)?;
    env_logger::init_from_env(
        env_logger::Env::default().default_filter_or("off,blendr_bluez=warn"),
    );
    let destination_receipts = config
        .messaging
        .acknowledgements
        .destination_delivery_receipt;
    let delivered = |node: &Node| {
        node.store()
            .direct_message(&id)
            .ok()
            .flatten()
            .is_some_and(|message| {
                message.destination_received || (!destination_receipts && message.link_acknowledged)
            })
    };
    let end = runtime_on(transport_session(
        &config,
        &mut node,
        Session {
            duration: Some(Duration::from_secs(timeout_seconds)),
            expected_peer: Some(to.to_string()),
            announce: Some(format!("waiting for peer {to}")),
            redial: REDIAL_INTERVAL,
            stop: &mut |node, _| delivered(node),
            input: None,
            on_input: None,
            after_exchange: None,
        },
    ))?;
    if delivered(&node) {
        println!("delivered {id}");
        return Ok(());
    }
    match end {
        LoopEnd::Deadline => Err(runtime(format!(
            "delivery deadline expired; message {id} remains queued"
        ))),
        LoopEnd::Closed(what) => Err(runtime(format!("delivery stopped early: {what}"))),
        LoopEnd::Finished | LoopEnd::Interrupted => Err(runtime(format!(
            "delivery incomplete; message {id} remains queued"
        ))),
    }
}

/// Interactive direct messaging with one pinned peer.
///
/// There is no long-lived BLE session: each line typed becomes one queued
/// envelope that rides the *next* authenticated exchange (inbound or
/// outbound). The stdin reader thread owns the terminal; this loop drains
/// it just before each exchange so a line sent mid-session still makes the
/// same turn rather than waiting one whole exchange. Incoming history is
/// printed after every exchange (deduplicated by message ID).
pub(crate) fn chat(cli: &Cli, to: &str, once: bool, duration: Option<u64>) -> Result<(), Fail> {
    let (config, mut node) = open_messaging(cli)?;
    node.settings().validate_network().map_err(messaging_fail)?;
    let peer = node
        .store()
        .peers()
        .map_err(|e| runtime(format!("cannot list peers: {e}")))?
        .into_iter()
        .find(|peer| peer.document.bid == to)
        .ok_or_else(|| {
            runtime(format!(
                "peer {to} is not pinned; run `peers --scan` or `send` first"
            ))
        })?;
    let name = peer.document.display_name.clone();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        loop {
            let mut line = String::new();
            match stdin.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let text = line.trim_end();
                    if !text.is_empty() && tx.send(text.to_string()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    env_logger::init_from_env(
        env_logger::Env::default().default_filter_or("off,blendr_bluez=warn"),
    );
    let mut shown: std::collections::HashSet<String> = node
        .history(Some(to), None, 500)
        .map_err(messaging_fail)?
        .into_iter()
        .map(|message| message.id)
        .collect();
    println!("chatting with {name} ({to}); type and press enter, ctrl-c to quit");
    let mut print_new = |node: &Node| match node.history(Some(to), None, 100) {
        Ok(rows) => {
            for message in rows.iter().rev() {
                if message.outgoing || !shown.insert(message.id.clone()) {
                    continue;
                }
                println!("{name}: {}", message.text);
            }
        }
        Err(e) => warn(format!("cannot read history: {e}")),
    };
    let queue_line = |node: &mut Node, text: String| match blendr_messaging::now_ms() {
        Err(e) => warn(format!("cannot queue line: {e}")),
        Ok(now) => match node.queue(to, &text, now) {
            Ok(id) => println!("you: {text}  [{id}]"),
            Err(e) => warn(format!("cannot queue line: {e}")),
        },
    };
    let mut on_input = queue_line;
    let end = runtime_on(transport_session(
        &config,
        &mut node,
        Session {
            duration: duration.map(Duration::from_secs),
            expected_peer: Some(to.to_string()),
            announce: Some(format!("waiting for {name}")),
            redial: Duration::from_secs(2),
            stop: &mut |_, exchanges| once && exchanges >= 1,
            input: Some(rx),
            on_input: Some(&mut on_input),
            after_exchange: Some(&mut print_new),
        },
    ))?;
    match end {
        LoopEnd::Deadline => println!("duration elapsed; leaving chat"),
        LoopEnd::Interrupted => println!("interrupted; leaving chat"),
        LoopEnd::Finished => println!("one exchange complete; leaving chat"),
        LoopEnd::Closed(what) => return Err(runtime(format!("chat stopped: {what}"))),
    }
    Ok(())
}

/// Sign and store a public post; with `--sync`, run the node until any peer
/// acknowledges it durably or the deadline passes. Unlike `send`, publication
/// is opportunistic: timeout leaves the post stored for later sessions.
pub(crate) fn publish(cli: &Cli, text: &str, sync: bool, timeout_seconds: u64) -> Result<(), Fail> {
    let (config, mut node) = open_messaging(cli)?;
    let id = node
        .publish(text, blendr_messaging::now_ms().map_err(messaging_fail)?)
        .map_err(messaging_fail)?;
    println!("published {id}");
    if !sync {
        return Ok(());
    }
    node.settings().validate_network().map_err(messaging_fail)?;
    env_logger::init_from_env(
        env_logger::Env::default().default_filter_or("off,blendr_bluez=warn"),
    );
    let mut synced = false;
    let end = runtime_on(transport_session(
        &config,
        &mut node,
        Session {
            duration: Some(Duration::from_secs(timeout_seconds)),
            expected_peer: None,
            announce: Some(format!("sharing post {id} ({timeout_seconds}s)")),
            redial: REDIAL_INTERVAL,
            stop: &mut |_, exchanges| {
                if exchanges >= 1 {
                    synced = true;
                    true
                } else {
                    false
                }
            },
            input: None,
            on_input: None,
            after_exchange: None,
        },
    ))?;
    if synced {
        println!("post {id} shared in one exchange");
        return Ok(());
    }
    match end {
        LoopEnd::Deadline => Err(runtime(format!(
            "no peer session completed within the deadline; post {id} stays published for the next exchange"
        ))),
        LoopEnd::Closed(what) => Err(runtime(format!("sync stopped early: {what}"))),
        LoopEnd::Finished | LoopEnd::Interrupted => Err(runtime(format!(
            "sync incomplete; post {id} stays published"
        ))),
    }
}

/// Print the public feed, newest first: authored posts and posts received
/// from authenticated peers alike.
pub(crate) fn feed(cli: &Cli, search: Option<&str>, limit: u32) -> Result<(), Fail> {
    let (_, node) = open_messaging(cli)?;
    let posts = node.feed(limit, 0).map_err(messaging_fail)?;
    let mut shown = 0u32;
    for post in posts {
        if let Some(query) = search
            && !literal_match(&post.text, query)
            && !literal_match(&post.origin_name, query)
        {
            continue;
        }
        let direction = if post.outgoing {
            "you"
        } else {
            &post.origin_name
        };
        println!("{}  {:<12}  {}", post.created_at_ms, direction, post.text);
        shown += 1;
    }
    if shown == 0 {
        match search {
            Some(q) => println!("no posts matching `{q}`"),
            None => println!("no posts; publish one or sync with a peer"),
        }
    }
    Ok(())
}

fn literal_match(text: &str, query: &str) -> bool {
    query.is_empty()
        || text
            .as_bytes()
            .windows(query.len())
            .any(|window| window.eq_ignore_ascii_case(query.as_bytes()))
}

/// Notes and decrypted direct history merge into one newest-first page.
/// `--peer` restricts to direct messages with that BID; `--direct` drops the
/// local notes. Received messages decrypt on read only — ciphertext stays at
/// rest, so history survives TTL expiry and config changes.
pub(crate) fn inbox(
    cli: &Cli,
    search: Option<&str>,
    limit: u32,
    peer: Option<&str>,
    direct_only: bool,
) -> Result<(), Fail> {
    let (_, node) = open_messaging(cli)?;
    let mut rows: Vec<(i64, String)> = Vec::new();
    if !direct_only && peer.is_none() {
        let notes = node
            .store()
            .local_messages(search, limit)
            .map_err(|e| runtime(format!("cannot read inbox: {e}")))?;
        for note in notes {
            rows.push((note.created_at_ms, format!("note         {}", note.text)));
        }
    }
    let history = node.history(peer, search, limit).map_err(messaging_fail)?;
    for message in history {
        rows.push((message.created_at_ms, format_history(&message)));
    }
    if rows.is_empty() {
        match search {
            Some(q) => println!("no messages matching `{q}`"),
            None => println!("no messages"),
        }
        return Ok(());
    }
    rows.sort_by_key(|row| std::cmp::Reverse(row.0));
    rows.truncate(limit as usize);
    for (created_at_ms, line) in rows {
        println!("{created_at_ms}  {line}");
    }
    Ok(())
}

fn format_history(message: &HistoryMessage) -> String {
    if message.outgoing {
        format!(
            "direct -> {}  [{}]  {}",
            message.peer_bid,
            history_state(message),
            message.text
        )
    } else {
        format!("direct <- {}  {}", message.peer_bid, message.text)
    }
}

fn history_state(message: &HistoryMessage) -> &'static str {
    if message.destination_received {
        "delivered"
    } else if message.link_acknowledged {
        "acknowledged"
    } else {
        "queued"
    }
}
