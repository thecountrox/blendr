//! Blendr BLE transport probe: exercises the real adapter end to end on one
//! controller.
//!
//! Registers the GATT application, advertises the service UUID, scans for a
//! bounded duration, and reports adapter prerequisites, requested scan
//! parameters, advertise status, distinct peers, and link MTU. Hardware
//! addresses are never printed. Transport warnings/errors (e.g. discovery
//! filter or start failures) go to stderr; the default filter is limited to
//! this crate so logs cannot expose neighboring devices — override with
//! RUST_LOG only for explicit debugging.
//!
//! Usage: `probe [CONFIG_PATH] [--duration SECONDS] [--spike]`
//!
//! `--spike` additionally exercises a two-device fixed-frame exchange: the
//! probe connects to the last discovered peer still live, sends a fixed test
//! frame, and echoes any inbound frames back. Run a second instance on another
//! host to see real traffic. Never sends user plaintext.

use std::collections::HashSet;
use std::time::Duration;

use blendr_transport::{BleTransport, PeerEvent, PeerLocator};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const FIXED_TEST_FRAME: &[u8] = b"BLENDR-PROBE-01";

#[tokio::main]
async fn main() {
    // Install a logging backend so blendr-bluez warn/error diagnostics reach
    // stderr. Without this the crate's log::warn calls are silently dropped.
    // Default: this crate only, warnings and above — no Bluetooth addresses
    // from dependencies can leak. RUST_LOG overrides for explicit debugging.
    env_logger::init_from_env(
        env_logger::Env::default().default_filter_or("off,blendr_bluez=warn"),
    );

    let mut config_path = "config.json".to_string();
    let mut duration_secs: u64 = 10;
    let mut spike = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--duration" => duration_secs = args.next().and_then(|v| v.parse().ok()).unwrap_or(10),
            "--spike" => spike = true,
            "--help" | "-h" => {
                eprintln!("usage: probe [CONFIG_PATH] [--duration SECONDS] [--spike]");
                return;
            }
            other if !other.starts_with('-') => config_path = other.to_string(),
            other => {
                eprintln!("probe: unknown argument {other}");
                std::process::exit(2);
            }
        }
    }

    let config = match blendr_config::Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("probe: cannot load config {config_path}: {e}");
            std::process::exit(1);
        }
    };

    println!("== blendr BLE probe ==");
    let transport = match blendr_bluez::BluezTransport::new(&config).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("prerequisites FAILED: {e}");
            std::process::exit(1);
        }
    };
    println!(
        "adapter: {} (powered, GATT application registered)",
        transport.adapter_name()
    );

    let service: Uuid = config
        .transport
        .ble
        .gatt_service_uuid
        .parse()
        .expect("validated uuid");
    if let Err(e) = transport.start_advertising(service).await {
        eprintln!("probe: advertising start FAILED: {e}");
        shutdown(&transport).await;
        std::process::exit(1);
    }
    println!("advertising: started (service UUID only)");

    let mut peer_rx = match transport.watch_peers().await {
        Ok(rx) => rx,
        Err(e) => {
            eprintln!("probe: peer watch FAILED: {e}");
            shutdown(&transport).await;
            std::process::exit(1);
        }
    };
    let mut link_rx = match transport.accept_links().await {
        Ok(rx) => rx,
        Err(e) => {
            eprintln!("probe: inbound link accept FAILED: {e}");
            shutdown(&transport).await;
            std::process::exit(1);
        }
    };

    // Requested parameters only: this is not proof the scanner started. Filter
    // or start failures surface as blendr_bluez warnings on stderr.
    println!(
        "scan request: window={}ms interval={}ms (effective interval >= window + 200ms); discovery.scan={}",
        config.discovery.scan_window_ms, config.discovery.scan_interval_ms, config.discovery.scan
    );
    if !config.discovery.scan {
        println!(
            "note: discovery.scan=false — transport will not run a scanner; expect zero peers"
        );
    }
    println!("watching for peers for {duration_secs}s...");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(duration_secs);
    let mut distinct_peers: HashSet<PeerLocator> = HashSet::new();
    let mut live_peers: HashSet<PeerLocator> = HashSet::new();
    let mut last_peer = None;
    let mut peer_open = true;
    let mut link_open = true;
    let cancel = CancellationToken::new();

    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            evt = peer_rx.recv(), if peer_open => match evt {
                Some(PeerEvent::Discovered(loc)) => {
                    if distinct_peers.insert(loc.clone()) {
                        println!("peer discovered ({} distinct)", distinct_peers.len());
                    }
                    live_peers.insert(loc.clone());
                    last_peer = Some(loc);
                }
                Some(PeerEvent::Lost(loc)) => {
                    live_peers.remove(&loc);
                    if last_peer.as_ref() == Some(&loc) {
                        last_peer = live_peers.iter().next().cloned();
                    }
                    println!("peer lost ({} live)", live_peers.len());
                }
                None => {
                    peer_open = false;
                    println!("peer event channel closed; discovery events stopped");
                }
            },
            link = link_rx.recv(), if link_open => match link {
                Some(mut link) => {
                    println!("inbound link: role={:?} frame_mtu={}", link.role(), link.mtu());
                    if spike {
                        tokio::spawn(async move {
                            let cancel = CancellationToken::new();
                            while let Ok(frame) = link.recv_frame(&cancel).await {
                                println!("inbound echo: {} bytes", frame.len());
                                if link.send_frame(&frame, &cancel).await.is_err() {
                                    break;
                                }
                            }
                        });
                    }
                }
                None => {
                    link_open = false;
                    println!("inbound link channel closed; accepting stopped");
                }
            },
        }
    }

    println!(
        "result: {} distinct peer(s) discovered in {duration_secs}s ({} still live)",
        distinct_peers.len(),
        live_peers.len()
    );

    if spike {
        if let Some(locator) = last_peer {
            print!("spike: connecting to last live discovered peer... ");
            match transport.connect(locator, &cancel).await {
                Ok(mut link) => {
                    println!("ok (role={:?}, mtu={})", link.role(), link.mtu());
                    match link.send_frame(FIXED_TEST_FRAME, &cancel).await {
                        Ok(()) => println!("spike: sent {} fixed bytes", FIXED_TEST_FRAME.len()),
                        Err(e) => println!("spike: send failed: {e}"),
                    }
                    match link.recv_frame(&cancel).await {
                        Ok(frame) => println!("spike: received {} bytes (echo)", frame.len()),
                        Err(e) => println!("spike: recv failed: {e}"),
                    }
                    let _ = link.close().await;
                }
                Err(e) => println!("failed: {e}"),
            }
        } else {
            println!("spike: no discovered peer to connect to (single-controller run)");
        }
    }

    shutdown(&transport).await;
}

/// Stop advertising and shut the transport down, reporting failures.
async fn shutdown(transport: &blendr_bluez::BluezTransport) {
    if let Err(e) = transport.stop_advertising().await {
        println!("stop advertising: {e}");
    }
    match transport.shutdown().await {
        Ok(()) => println!("shutdown: clean"),
        Err(e) => println!("shutdown: {e}"),
    }
}
