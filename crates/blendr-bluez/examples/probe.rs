//! Real two-host BLE diagnostics; never sends user plaintext or prints addresses.
//!
//! Discovery: `probe [CONFIG_PATH] [--duration SECONDS] [--require-peer]`
//! Exchange: run `--listen` on one host and `--spike` on the other, with matching
//! `--rounds N` and optional `--reconnect`. Each round checks deterministic
//! 1024/4096/8192-byte requests and exact echoes in BOTH directions. Configure
//! max_frame_payload_bytes >= 8192 on both hosts; no transport limits are changed.
//! Each fresh link also checks pre-cancelled send/receive and cancellation of
//! an idle receive, with a one-second bound and no concurrent valid data.
//! `--duration` bounds setup and the entire discovery/exchange phase separately.
//! Reconnect closes the elected initiator's ACL. The listener requires remote
//! EOF after the completion handshake before accepting the next link.
//! Default logs are restricted to this crate; RUST_LOG is explicit debugging.

use std::collections::HashSet;
use std::process::ExitCode;
use std::time::Duration;

use blendr_transport::{BleTransport, LinkRole, PeerEvent, PeerLink, PeerLocator, TransportError};
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_util::sync::CancellationToken;

const SIZES: [usize; 3] = [1024, 4096, 8192];
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const USAGE: &str = "usage: probe [CONFIG_PATH] [--duration SECONDS] [--require-peer]\n       probe [CONFIG_PATH] (--listen | --spike | --elect) [--duration SECONDS] [--rounds N] [--reconnect]\n\n--spike       sender: discover, connect, validate two-way requests/echoes\n--listen      listener: accept only, validate two-way requests/echoes, then exit\n--elect       both hosts dial; validate the surviving elected link\n--rounds N    completed exchanges required (1..100; default 1)\n--reconnect   close/drop and reopen the physical link for every round (requires N >= 2)\n--duration S  setup and discovery/exchange deadlines (1..3600; default 30)\n--require-peer  discovery-only: fail if no peer is still live at the deadline\nBoth exchange hosts need matching rounds/reconnect options and frame limit >= 8192.";

type ProbeResult<T> = Result<T, String>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Discover,
    Sender,
    Listener,
    Election,
}

#[derive(Debug)]
struct Options {
    config: String,
    duration: Duration,
    mode: Mode,
    rounds: u32,
    reconnect: bool,
    require_peer: bool,
}

impl Options {
    fn parse(args: impl IntoIterator<Item = String>) -> ProbeResult<Option<Self>> {
        let mut options = Self {
            config: "config.json".into(),
            duration: Duration::from_secs(30),
            mode: Mode::Discover,
            rounds: 1,
            reconnect: false,
            require_peer: false,
        };
        let mut config_seen = false;
        let mut rounds_seen = false;
        let mut duration_seen = false;
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--help" | "-h" => return Ok(None),
                "--listen" | "--spike" | "--elect" => {
                    if options.mode != Mode::Discover {
                        return Err("choose exactly one exchange mode".into());
                    }
                    options.mode = match arg.as_str() {
                        "--listen" => Mode::Listener,
                        "--elect" => Mode::Election,
                        _ => Mode::Sender,
                    };
                }
                "--duration" if !duration_seen => {
                    let value = parse_number(args.next(), "--duration", 3600)?;
                    options.duration = Duration::from_secs(u64::from(value));
                    duration_seen = true;
                }
                "--rounds" if !rounds_seen => {
                    options.rounds = parse_number(args.next(), "--rounds", 100)?;
                    rounds_seen = true;
                }
                "--reconnect" if !options.reconnect => options.reconnect = true,
                "--require-peer" if !options.require_peer => options.require_peer = true,
                other if !other.starts_with('-') && !config_seen => {
                    options.config = other.into();
                    config_seen = true;
                }
                _ => return Err("unknown, repeated, or unexpected argument; see --help".into()),
            }
        }
        if options.mode == Mode::Discover && (rounds_seen || options.reconnect) {
            return Err("--rounds and --reconnect require an exchange mode".into());
        }
        if options.mode != Mode::Discover && options.require_peer {
            return Err("--require-peer is discovery-only; exchanges always require a peer".into());
        }
        if options.reconnect && options.rounds < 2 {
            return Err("--reconnect requires --rounds >= 2".into());
        }
        Ok(Some(options))
    }
}

fn parse_number(value: Option<String>, flag: &str, max: u32) -> ProbeResult<u32> {
    let number = value.and_then(|value| {
        if value.bytes().all(|byte| byte.is_ascii_digit()) {
            value.parse::<u32>().ok()
        } else {
            None
        }
    });
    match number {
        Some(number) if (1..=max).contains(&number) => Ok(number),
        _ => Err(format!("{flag} requires an integer in 1..={max}")),
    }
}

// Do not print platform error strings: they can contain BlueZ object paths.
fn transport_error(stage: &str, error: TransportError) -> String {
    let kind = match error {
        TransportError::Cancelled => "cancelled",
        TransportError::Disconnected => "disconnected",
        TransportError::Timeout => "timeout",
        TransportError::InvalidFrame(_) => "invalid frame",
        TransportError::ResourceLimit(_) => "resource limit",
        TransportError::Platform(_) => "platform error",
    };
    format!("{stage}: {kind}")
}

#[tokio::main]
async fn main() -> ExitCode {
    env_logger::init_from_env(
        env_logger::Env::default().default_filter_or("off,blendr_bluez=warn"),
    );
    let options = match Options::parse(std::env::args().skip(1)) {
        Ok(Some(options)) => options,
        Ok(None) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("probe: {error}");
            return ExitCode::from(2);
        }
    };
    match run(&options).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("probe FAILED: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(options: &Options) -> ProbeResult<()> {
    let config = blendr_config::Config::load(&options.config)
        .map_err(|_| "cannot load/validate config (path and contents redacted)".to_string())?;
    if options.mode != Mode::Discover
        && (config.transport.ble.max_frame_payload_bytes as usize) < SIZES[2]
    {
        return Err(
            "exchange requires configured max_frame_payload_bytes >= 8192 on both hosts".into(),
        );
    }
    println!("== blendr BLE probe: {:?} ==", options.mode);
    let transport = timeout(options.duration, blendr_bluez::BluezTransport::new(&config))
        .await
        .map_err(|_| "adapter setup deadline expired".to_string())?
        .map_err(|error| transport_error("adapter setup", error))?;
    println!(
        "adapter: {} (powered, GATT registered)",
        transport.adapter_name()
    );
    println!(
        "scan request: window={}ms interval={}ms; enabled={}",
        config.discovery.scan_window_ms, config.discovery.scan_interval_ms, config.discovery.scan
    );
    let cancel = CancellationToken::new();
    let setup = async {
        let service = config
            .transport
            .ble
            .gatt_service_uuid
            .parse()
            .map_err(|_| "invalid service UUID".to_string())?;
        transport
            .start_advertising(service)
            .await
            .map_err(|error| transport_error("advertising start", error))?;
        let peers = transport
            .watch_peers()
            .await
            .map_err(|error| transport_error("peer watch", error))?;
        let links = transport
            .accept_links()
            .await
            .map_err(|error| transport_error("link accept setup", error))?;
        Ok::<_, String>((peers, links))
    };
    let result = match timeout(options.duration, setup).await {
        Ok(Ok((mut peers, mut links))) => {
            println!(
                "advertising: started; phase deadline={}s",
                options.duration.as_secs()
            );
            if options.mode == Mode::Discover {
                discover(options, &mut peers).await
            } else {
                match timeout(
                    options.duration,
                    exchange(options, &transport, &mut peers, &mut links, &cancel),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => Err(
                        "exchange deadline expired (missing peer or incomplete exchange)".into(),
                    ),
                }
            }
        }
        Ok(Err(error)) => Err(error),
        Err(_) => Err("advertise/discovery setup deadline expired".into()),
    };
    cancel.cancel();
    let cleanup = shutdown(&transport).await;
    result?;
    cleanup?;
    println!("result: PASS");
    Ok(())
}

async fn discover(options: &Options, peers: &mut mpsc::Receiver<PeerEvent>) -> ProbeResult<()> {
    let deadline = Instant::now() + options.duration;
    let mut distinct = HashSet::new();
    let mut live = HashSet::new();
    loop {
        match timeout_at(deadline, peers.recv()).await {
            Ok(Some(PeerEvent::Discovered(peer))) => {
                if distinct.insert(peer.clone()) {
                    println!("peer discovered ({} distinct)", distinct.len());
                }
                live.insert(peer);
            }
            Ok(Some(PeerEvent::Lost(peer))) => {
                live.remove(&peer);
                println!("peer lost ({} live)", live.len());
            }
            Ok(None) => return Err("discovery channel closed before deadline".into()),
            Err(_) => break,
        }
    }
    println!(
        "discovery: {} distinct peer(s), {} still live",
        distinct.len(),
        live.len()
    );
    if options.require_peer && live.is_empty() {
        return Err("discovery required a live peer but none was found".into());
    }
    Ok(())
}

async fn exchange(
    options: &Options,
    transport: &blendr_bluez::BluezTransport,
    peers: &mut mpsc::Receiver<PeerEvent>,
    links: &mut mpsc::Receiver<Box<dyn PeerLink>>,
    cancel: &CancellationToken,
) -> ProbeResult<()> {
    let mut peer: Option<PeerLocator> = None;
    let link_count = if options.reconnect { options.rounds } else { 1 };
    for connection in 0..link_count {
        println!(
            "link {}/{}: waiting for {:?}",
            connection + 1,
            link_count,
            options.mode
        );
        let mut link = if matches!(options.mode, Mode::Sender | Mode::Election) {
            if peer.is_none() {
                loop {
                    match peers.recv().await {
                        Some(PeerEvent::Discovered(locator)) => {
                            peer = Some(locator);
                            break;
                        }
                        Some(PeerEvent::Lost(_)) => {}
                        None => return Err("discovery channel closed before finding a peer".into()),
                    }
                }
            }
            let locator = peer.clone().ok_or("missing peer locator")?;
            if options.mode == Mode::Election {
                elect_link(transport, links, locator, cancel).await?
            } else {
                println!("connecting to discovered peer");
                transport
                    .connect(locator, cancel)
                    .await
                    .map_err(|error| transport_error("connect", error))?
            }
        } else {
            let link = links.recv().await.ok_or("inbound link channel closed")?;
            if let Some(expected) = &peer {
                if link.locator() != expected {
                    return Err("reconnect accepted a different peer".into());
                }
            } else {
                peer = Some(link.locator().clone());
            }
            link
        };
        println!(
            "link opened: role={:?} frame_limit_bytes={} (PeerLink::mtu; NOT packet MTU)",
            link.role(),
            link.mtu()
        );
        let first_round = if options.reconnect { connection } else { 0 };
        let end_round = if options.reconnect {
            connection + 1
        } else {
            options.rounds
        };
        let mode = match link.role() {
            LinkRole::Initiator => Mode::Sender,
            LinkRole::Responder => Mode::Listener,
        };
        let result = exchange_link(link.as_mut(), mode, first_round, end_round, cancel).await;
        let closed = timeout(CLEANUP_TIMEOUT, link.close())
            .await
            .map_err(|_| "link close deadline expired".to_string())
            .and_then(|result| result.map_err(|error| transport_error("link close", error)));
        // close() marks the link dead; dropping actually releases the GATT IO.
        drop(link);
        result?;
        closed?;
        println!(
            "link {}/{}: completed and dropped",
            connection + 1,
            link_count
        );
    }
    println!(
        "exchange: {} complete round(s), {} fresh link(s)",
        options.rounds, link_count
    );
    Ok(())
}

async fn elect_link(
    transport: &blendr_bluez::BluezTransport,
    links: &mut mpsc::Receiver<Box<dyn PeerLink>>,
    peer: PeerLocator,
    cancel: &CancellationToken,
) -> ProbeResult<Box<dyn PeerLink>> {
    const HELLO: &[u8] = b"BLENDR-ELECTION-02";
    const ACK: &[u8] = b"BLENDR-ELECTED-02";
    let incoming = match transport.connect(peer.clone(), cancel).await {
        Ok(mut outgoing) => {
            println!("election: provisional outgoing link; allowing competing dial");
            // A real first write activates BlueZ's lazy server AcquireWrite.
            // Give the other foreground probe time to acquire its outbound IO.
            tokio::time::sleep(Duration::from_secs(2)).await;
            match outgoing.send_frame(HELLO, cancel).await {
                Ok(()) => {
                    let replacement = tokio::select! {
                        received = outgoing.recv_frame(cancel) => match received {
                            Ok(frame) => {
                                validate_frame(&frame, ACK)?;
                                println!("election: outgoing link survived");
                                return Ok(outgoing);
                            }
                            Err(TransportError::Disconnected) => {
                                links.recv().await.ok_or("election accept channel closed")?
                            }
                            Err(error) => return Err(transport_error("election receipt", error)),
                        },
                        accepted = links.recv() => accepted.ok_or("election accept channel closed")?,
                    };
                    drop(outgoing); // A losing link must not disconnect its winner.
                    replacement
                }
                Err(TransportError::Disconnected) => {
                    drop(outgoing);
                    links.recv().await.ok_or("election accept channel closed")?
                }
                Err(error) => return Err(transport_error("election first write", error)),
            }
        }
        Err(TransportError::ResourceLimit(_)) => {
            // Only a real, matching inbound exchange can validate this outcome.
            links.recv().await.ok_or("election accept channel closed")?
        }
        Err(error) => return Err(transport_error("election connect", error)),
    };
    if incoming.locator() != &peer || incoming.role() != LinkRole::Responder {
        return Err("election accepted an unexpected peer or role".into());
    }
    let mut incoming = incoming;
    receive_exact(incoming.as_mut(), HELLO, cancel).await?;
    send(incoming.as_mut(), ACK, cancel).await?;
    println!("election: incoming link survived");
    Ok(incoming)
}

async fn exchange_link(
    link: &mut dyn PeerLink,
    mode: Mode,
    first_round: u32,
    end_round: u32,
    cancel: &CancellationToken,
) -> ProbeResult<()> {
    if link.mtu() < SIZES[2] {
        return Err("negotiated frame limit cannot carry the required 8192-byte frame".into());
    }
    let sender_checked = completion_frame(first_round, end_round, 3);
    let listener_checked = completion_frame(first_round, end_round, 4);
    if mode == Mode::Sender {
        check_cancellation(link).await?;
        send(link, &sender_checked, cancel).await?;
        receive_exact(link, &listener_checked, cancel).await?;
    } else {
        receive_exact(link, &sender_checked, cancel).await?;
        check_cancellation(link).await?;
        send(link, &listener_checked, cancel).await?;
    }
    for round in first_round..end_round {
        for (index, size) in SIZES.into_iter().enumerate() {
            println!(
                "round {}: checking {}-byte requests/echoes in both directions",
                round + 1,
                size
            );
            let sender_request = diagnostic_frame(round, index as u8, 0, size);
            let listener_request = diagnostic_frame(round, index as u8, 1, size);
            if mode == Mode::Sender {
                send(link, &sender_request, cancel).await?;
                receive_exact(link, &sender_request, cancel).await?;
                receive_exact(link, &listener_request, cancel).await?;
                send(link, &listener_request, cancel).await?;
            } else {
                receive_exact(link, &sender_request, cancel).await?;
                send(link, &sender_request, cancel).await?;
                send(link, &listener_request, cancel).await?;
                receive_exact(link, &listener_request, cancel).await?;
            }
        }
        println!(
            "round {}: all 12 data frames validated (six requests, six echoes)",
            round + 1
        );
    }
    // Round-scoped receipts reject stale completion. The initiator closes the
    // ACL only after the listener received its confirmation; the listener then
    // observes EOF rather than mistaking a queued send for delivered data.
    let done = completion_frame(first_round, end_round, 0);
    let ack = completion_frame(first_round, end_round, 1);
    let confirmed = completion_frame(first_round, end_round, 2);
    let received = completion_frame(first_round, end_round, 5);
    if mode == Mode::Sender {
        send(link, &done, cancel).await?;
        receive_exact(link, &ack, cancel).await?;
        send(link, &confirmed, cancel).await?;
        receive_exact(link, &received, cancel).await
    } else {
        receive_exact(link, &done, cancel).await?;
        send(link, &ack, cancel).await?;
        receive_exact(link, &confirmed, cancel).await?;
        send(link, &received, cancel).await?;
        println!("completion confirmed; waiting for initiator ACL closure");
        match link.recv_frame(cancel).await {
            Err(TransportError::Disconnected) => Ok(()),
            Err(error) => Err(transport_error("remote link closure", error)),
            Ok(_) => Err("unexpected extra frame after completion".into()),
        }
    }
}

// Header fields and generated body identify round, size index, and direction,
// so wrong order, old-round echoes, and same-length corruption fail.
fn diagnostic_frame(round: u32, index: u8, direction: u8, size: usize) -> Vec<u8> {
    let mut frame = Vec::with_capacity(size);
    frame.extend_from_slice(b"BLENDR-PROBE-02");
    frame.extend_from_slice(&round.to_be_bytes());
    frame.push(index);
    frame.push(direction);
    frame.extend_from_slice(&(size as u32).to_be_bytes());
    let mut state = 0x9e37_79b9_u32
        ^ round.wrapping_mul(0x85eb_ca6b)
        ^ (u32::from(index) << 16)
        ^ u32::from(direction);
    while frame.len() < size {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        frame.push(state as u8);
    }
    frame
}

fn completion_frame(first: u32, end: u32, phase: u8) -> Vec<u8> {
    let mut frame = Vec::with_capacity(23);
    frame.extend_from_slice(b"BLENDR-DONE-02");
    frame.extend_from_slice(&first.to_be_bytes());
    frame.extend_from_slice(&end.to_be_bytes());
    frame.push(phase);
    frame
}

fn validate_frame(received: &[u8], expected: &[u8]) -> ProbeResult<()> {
    if received.len() != expected.len() {
        return Err(format!(
            "wrong frame length: expected {}, received {}",
            expected.len(),
            received.len()
        ));
    }
    if received != expected {
        return Err("frame bytes differ from deterministic expectation (contents redacted)".into());
    }
    Ok(())
}

async fn send(
    link: &mut dyn PeerLink,
    frame: &[u8],
    cancel: &CancellationToken,
) -> ProbeResult<()> {
    link.send_frame(frame, cancel)
        .await
        .map_err(|error| transport_error("send frame", error))
}

async fn receive_exact(
    link: &mut dyn PeerLink,
    expected: &[u8],
    cancel: &CancellationToken,
) -> ProbeResult<()> {
    let received = link
        .recv_frame(cancel)
        .await
        .map_err(|error| transport_error("receive frame", error))?;
    validate_frame(&received, expected)
}

async fn check_cancellation(link: &mut dyn PeerLink) -> ProbeResult<()> {
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    expect_cancelled(
        timeout(
            Duration::from_secs(1),
            link.send_frame(b"cancelled-probe", &cancelled),
        )
        .await,
        "pre-cancelled send",
    )?;
    expect_cancelled(
        timeout(Duration::from_secs(1), link.recv_frame(&cancelled)).await,
        "pre-cancelled receive",
    )?;
    let idle_cancel = CancellationToken::new();
    let trigger = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        idle_cancel.cancel();
    };
    let (received, ()) = tokio::join!(
        timeout(Duration::from_secs(1), link.recv_frame(&idle_cancel)),
        trigger,
    );
    expect_cancelled(received, "idle receive cancellation")?;
    println!("cancellation: pre-cancelled send/receive and idle receive passed");
    Ok(())
}

fn expect_cancelled<T>(
    result: Result<Result<T, TransportError>, tokio::time::error::Elapsed>,
    stage: &str,
) -> ProbeResult<()> {
    match result {
        Ok(Err(TransportError::Cancelled)) => Ok(()),
        Ok(Err(error)) => Err(transport_error(stage, error)),
        Ok(Ok(_)) => Err(format!("{stage}: unexpectedly succeeded")),
        Err(_) => Err(format!(
            "{stage}: did not return Cancelled within one second"
        )),
    }
}

async fn shutdown(transport: &blendr_bluez::BluezTransport) -> ProbeResult<()> {
    let stopped = timeout(CLEANUP_TIMEOUT, transport.stop_advertising())
        .await
        .map_err(|_| "stop advertising deadline expired".to_string())
        .and_then(|result| result.map_err(|error| transport_error("stop advertising", error)));
    // Always attempt shutdown, even when stopping advertisements failed.
    let shutdown = timeout(CLEANUP_TIMEOUT, transport.shutdown())
        .await
        .map_err(|_| "transport shutdown deadline expired".to_string())
        .and_then(|result| result.map_err(|error| transport_error("transport shutdown", error)));
    if let Err(error) = &stopped {
        eprintln!("cleanup FAILED: {error}");
    }
    if let Err(error) = &shutdown {
        eprintln!("cleanup FAILED: {error}");
    }
    stopped?;
    shutdown?;
    println!("shutdown: clean");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> ProbeResult<Option<Options>> {
        Options::parse(args.iter().map(|arg| (*arg).to_string()))
    }

    #[test]
    fn rejects_invalid_or_ambiguous_options() {
        for args in [
            vec!["--duration"],
            vec!["--duration", "0"],
            vec!["--duration", "-1"],
            vec!["--duration", "3601"],
            vec!["--duration", "NaN"],
            vec!["--spike", "--rounds", "101"],
            vec!["--rounds", "2"],
            vec!["--spike", "--listen"],
            vec!["--listen", "--spike"],
            vec!["--elect", "--listen"],
            vec!["--spike", "--reconnect"],
            vec!["--listen", "--require-peer"],
            vec!["--unknown"],
            vec!["a.json", "b.json"],
            vec!["--duration", "1", "--duration", "2"],
        ] {
            assert!(parse(&args).is_err(), "unexpectedly accepted {args:?}");
        }
    }

    #[test]
    fn parses_roles_reconnect_and_standalone_discovery() {
        let standalone = parse(&[]).unwrap().unwrap();
        assert_eq!(standalone.mode, Mode::Discover);
        assert!(!standalone.require_peer);
        assert!(parse(&["--require-peer"]).unwrap().unwrap().require_peer);
        for (role, expected) in [
            ("--listen", Mode::Listener),
            ("--spike", Mode::Sender),
            ("--elect", Mode::Election),
        ] {
            let options = parse(&[
                "device.json",
                role,
                "--rounds",
                "3",
                "--reconnect",
                "--duration",
                "60",
            ])
            .unwrap()
            .unwrap();
            assert_eq!(options.mode, expected);
            assert_eq!(options.config, "device.json");
            assert_eq!(options.rounds, 3);
            assert!(options.reconnect);
            assert_eq!(options.duration, Duration::from_secs(60));
        }
    }

    #[test]
    fn rejects_corruption_truncation_extra_bytes_and_stale_frames() {
        let expected = diagnostic_frame(2, 1, 0, 4096);
        assert!(validate_frame(&expected, &expected).is_ok());
        for position in [0, 20, 255, 4095] {
            let mut corrupt = expected.clone();
            corrupt[position] ^= 1;
            assert!(validate_frame(&corrupt, &expected).is_err());
        }
        assert!(validate_frame(&expected[..4095], &expected).is_err());
        let mut extra = expected.clone();
        extra.push(0);
        assert!(validate_frame(&extra, &expected).is_err());
        assert!(validate_frame(&diagnostic_frame(1, 1, 0, 4096), &expected).is_err());
        assert!(validate_frame(&diagnostic_frame(2, 0, 0, 4096), &expected).is_err());
        assert!(validate_frame(&diagnostic_frame(2, 1, 1, 4096), &expected).is_err());
        assert!(validate_frame(&completion_frame(0, 1, 1), &completion_frame(1, 2, 1)).is_err());
        assert!(validate_frame(&completion_frame(1, 2, 0), &completion_frame(1, 2, 1)).is_err());
    }
}
