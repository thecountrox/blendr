//! One plaintext text-message exchange over real BLE, not secure Blendr chat.
//! Run --listen on one host and --connect on the other, each with --message TEXT.

use std::process::ExitCode;
use std::time::Duration;

use blendr_transport::{BleTransport, PeerEvent, PeerLink, TransportError};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

type DemoResult<T> = Result<T, String>;
const PREFIX: &[u8] = b"BLENDR-DEMO\x01";
const RECEIPT: &[u8] = b"BLENDR-DEMO\x01\x02";
const FINISHED: &[u8] = b"BLENDR-DEMO\x01\x03";
const CLEANUP: Duration = Duration::from_secs(20);
const USAGE: &str = "usage: message_demo [CONFIG_PATH] (--listen | --connect) --message TEXT [--timeout SECONDS]\n\nOne plaintext request/reply; both processes exit afterward.\nStart the listener first. Default config: config.json; timeout: 90 seconds.\nNOT encrypted, authenticated, or stored. Use non-sensitive test text only.";

struct Options {
    config: String,
    listen: bool,
    message: String,
    duration: Duration,
}

impl Options {
    fn parse(mut args: impl Iterator<Item = String>) -> DemoResult<Option<Self>> {
        let mut config = None;
        let mut listen = None;
        let mut message = None;
        let mut seconds = None;
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--help" | "-h" => return Ok(None),
                "--listen" | "--connect" if listen.is_none() => listen = Some(arg == "--listen"),
                "--message" if message.is_none() => {
                    message = Some(args.next().ok_or("--message needs text")?);
                }
                "--timeout" if seconds.is_none() => {
                    let value = args.next().ok_or("--timeout needs seconds")?;
                    let parsed = value.parse::<u64>().map_err(|_| "invalid timeout")?;
                    if !(1..=3600).contains(&parsed) {
                        return Err("timeout must be between 1 and 3600 seconds".into());
                    }
                    seconds = Some(parsed);
                }
                value if !value.starts_with('-') && config.is_none() => config = Some(arg),
                _ => return Err("unknown, repeated, or conflicting option; see --help".into()),
            }
        }
        Ok(Some(Self {
            config: config.unwrap_or_else(|| "config.json".into()),
            listen: listen.ok_or("choose --listen or --connect")?,
            message: message.ok_or("supply --message TEXT on both hosts")?,
            duration: Duration::from_secs(seconds.unwrap_or(90)),
        }))
    }
}

fn error(stage: &str, error: TransportError) -> String {
    // Platform strings can contain device paths; never include them in output.
    let kind = match error {
        TransportError::Cancelled => "cancelled",
        TransportError::Disconnected => "disconnected",
        TransportError::Timeout => "timeout",
        TransportError::InvalidFrame(_) => "invalid frame",
        TransportError::ResourceLimit(_) => "resource limit",
        TransportError::Platform(_) => "platform error (see transport debug logs)",
    };
    format!("{stage}: {kind}")
}

fn encode(text: &str, kind: u8, limit: usize) -> DemoResult<Vec<u8>> {
    let overhead = PREFIX.len() + 1;
    if text.is_empty() || text.len() > limit.saturating_sub(overhead) {
        return Err(format!(
            "message must contain 1..={} UTF-8 bytes for the configured frame limit",
            limit.saturating_sub(overhead)
        ));
    }
    let mut frame = Vec::with_capacity(overhead + text.len());
    frame.extend_from_slice(PREFIX);
    frame.push(kind);
    frame.extend_from_slice(text.as_bytes());
    Ok(frame)
}

fn decode(frame: &[u8], kind: u8) -> DemoResult<&str> {
    let body = frame
        .strip_prefix(PREFIX)
        .ok_or("peer is not running this message demo")?;
    if body.first() != Some(&kind) || body.len() == 1 {
        return Err("unexpected demo message type or empty text".into());
    }
    std::str::from_utf8(&body[1..]).map_err(|_| "peer sent invalid UTF-8".into())
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
            eprintln!("{error}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    eprintln!(
        "PLAINTEXT DEMO: no encryption, peer authentication, or message storage. Use test text only."
    );
    match run(&options).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("message demo FAILED: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(options: &Options) -> DemoResult<()> {
    let config = blendr_config::Config::load(&options.config)
        .map_err(|_| "cannot load/validate config (path and contents redacted)")?;
    let local_frame = encode(
        &options.message,
        u8::from(options.listen),
        config.transport.ble.max_frame_payload_bytes as usize,
    )?;
    let transport = timeout(options.duration, blendr_bluez::BluezTransport::new(&config))
        .await
        .map_err(|_| "adapter setup deadline expired")?
        .map_err(|e| error("adapter setup", e))?;
    let cancel = CancellationToken::new();
    let work = async {
        let mut peers = transport
            .watch_peers()
            .await
            .map_err(|e| error("discovery", e))?;
        let mut inbound = transport
            .accept_links()
            .await
            .map_err(|e| error("accept setup", e))?;
        transport
            .start_advertising(
                config
                    .transport
                    .ble
                    .gatt_service_uuid
                    .parse()
                    .map_err(|_| "invalid service UUID")?,
            )
            .await
            .map_err(|e| error("advertising", e))?;
        println!(
            "{}; deadline {}s",
            if options.listen {
                "Listening for a demo message"
            } else {
                "Discovering the demo listener"
            },
            options.duration.as_secs()
        );
        let mut link = if options.listen {
            inbound.recv().await.ok_or("accept channel closed")?
        } else {
            let peer = loop {
                match peers.recv().await {
                    Some(PeerEvent::Discovered(peer)) => break peer,
                    Some(PeerEvent::Lost(_)) => {}
                    None => return Err("discovery channel closed".into()),
                }
            };
            transport
                .connect(peer, &cancel)
                .await
                .map_err(|e| error("connect", e))?
        };
        let exchanged = exchange(link.as_mut(), options.listen, &local_frame, &cancel).await;
        let closed = timeout(CLEANUP, link.close())
            .await
            .map_err(|_| "link close deadline expired".to_string())
            .and_then(|r| r.map_err(|e| error("link close", e)));
        drop(link);
        if let Err(e) = &closed {
            eprintln!("cleanup FAILED: {e}");
        }
        exchanged?;
        closed
    };
    let result = timeout(options.duration, work)
        .await
        .map_err(|_| "exchange deadline expired (missing peer or incomplete exchange)".to_string())
        .and_then(|r| r);
    cancel.cancel();
    // shutdown also unregisters advertising and waits for failed-dial cleanup.
    let cleanup = timeout(CLEANUP, transport.shutdown())
        .await
        .map_err(|_| "transport shutdown deadline expired".to_string())
        .and_then(|r| r.map_err(|e| error("shutdown", e)));
    if let Err(e) = &cleanup {
        eprintln!("cleanup FAILED: {e}");
    }
    result?;
    cleanup?;
    println!("Exchange complete; both messages received. Peer identity is NOT authenticated.");
    Ok(())
}

async fn exchange(
    link: &mut dyn PeerLink,
    listen: bool,
    local: &[u8],
    cancel: &CancellationToken,
) -> DemoResult<()> {
    if listen {
        let request = link
            .recv_frame(cancel)
            .await
            .map_err(|e| error("receive message", e))?;
        // Debug formatting escapes terminal control sequences from an untrusted peer.
        println!("Peer: {:?}", decode(&request, 0)?);
        link.send_frame(local, cancel)
            .await
            .map_err(|e| error("send reply", e))?;
        println!("You: {:?}", decode(local, 1)?);
        receive_control(link, RECEIPT, cancel).await?;
        link.send_frame(FINISHED, cancel)
            .await
            .map_err(|e| error("send receipt", e))?;
        match link.recv_frame(cancel).await {
            Err(TransportError::Disconnected) => Ok(()),
            Err(e) => Err(error("wait for initiator close", e)),
            Ok(_) => Err("unexpected data after receipt".into()),
        }
    } else {
        link.send_frame(local, cancel)
            .await
            .map_err(|e| error("send message", e))?;
        println!("You: {:?}", decode(local, 0)?);
        let reply = link
            .recv_frame(cancel)
            .await
            .map_err(|e| error("receive reply", e))?;
        println!("Peer: {:?}", decode(&reply, 1)?);
        link.send_frame(RECEIPT, cancel)
            .await
            .map_err(|e| error("acknowledge reply", e))?;
        receive_control(link, FINISHED, cancel).await
    }
}

async fn receive_control(
    link: &mut dyn PeerLink,
    expected: &[u8],
    cancel: &CancellationToken,
) -> DemoResult<()> {
    let frame = link
        .recv_frame(cancel)
        .await
        .map_err(|e| error("receive receipt", e))?;
    if frame != expected {
        return Err("invalid demo receipt".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_limit_counts_utf8_bytes_including_protocol_overhead() {
        let limit = PREFIX.len() + 1 + 4;
        assert!(encode("éé", 0, limit).is_ok());
        assert!(encode("ééa", 0, limit).is_err());
        assert!(encode("", 0, limit).is_err());
        assert!(encode("a", 0, PREFIX.len()).is_err());
    }

    #[test]
    fn rejects_incompatible_malformed_and_wrong_direction_peer_frames() {
        let valid = encode("hello", 0, 128).unwrap();
        assert!(decode(&valid, 1).is_err());
        assert!(decode(b"unrelated traffic", 0).is_err());
        assert!(decode(PREFIX, 0).is_err());
        assert!(decode(RECEIPT, 0).is_err());
        let mut bad = PREFIX.to_vec();
        bad.extend_from_slice(&[0, 0xff]);
        assert!(decode(&bad, 0).is_err());
    }
}
