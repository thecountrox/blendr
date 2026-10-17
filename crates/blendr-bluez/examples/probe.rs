//! Blendr BLE transport probe: exercises the real adapter end to end on one
//! controller.
//!
//! Registers the GATT application, advertises the service UUID, scans for a
//! bounded duration, and reports adapter prerequisites, scan/advertise
//! status, peer count, and link MTU. Hardware addresses are never printed.
//!
//! Usage: `probe [CONFIG_PATH] [--duration SECONDS] [--spike]`
//!
//! `--spike` additionally exercises a two-device fixed-frame exchange: the
//! probe connects to the first discovered peer, sends a fixed test frame,
//! and echoes any inbound frames back. Run a second instance on another
//! host to see real traffic. Never sends user plaintext.

use std::time::Duration;

use blendr_transport::{BleTransport, PeerEvent};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const FIXED_TEST_FRAME: &[u8] = b"BLENDR-PROBE-01";

#[tokio::main]
async fn main() {
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
    match transport.start_advertising(service).await {
        Ok(()) => println!("advertising: started (service UUID only)"),
        Err(e) => println!("advertising: unavailable ({e})"),
    }

    let mut peer_rx = match transport.watch_peers().await {
        Ok(rx) => Some(rx),
        Err(e) => {
            println!("scan: unavailable ({e})");
            None
        }
    };
    let mut link_rx = match transport.accept_links().await {
        Ok(rx) => Some(rx),
        Err(e) => {
            println!("accept: unavailable ({e})");
            None
        }
    };

    println!("scanning for {duration_secs}s...");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(duration_secs);
    let mut seen = 0usize;
    let mut last_peer = None;
    let cancel = CancellationToken::new();

    loop {
        let peer_evt = async {
            match peer_rx.as_mut() {
                Some(rx) => rx.recv().await,
                None => std::future::pending().await,
            }
        };
        let link_evt = async {
            match link_rx.as_mut() {
                Some(rx) => rx.recv().await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            evt = peer_evt => match evt {
                Some(PeerEvent::Discovered(loc)) => {
                    seen += 1;
                    last_peer = Some(loc);
                    println!("peer discovered (#{seen})");
                }
                Some(PeerEvent::Lost(_)) => println!("peer lost"),
                None => {}
            },
            link = link_evt => {
                if let Some(mut link) = link {
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
            }
        }
    }

    println!("result: {seen} distinct peer(s) discovered in {duration_secs}s");

    if spike {
        if let Some(locator) = last_peer {
            print!("spike: connecting to first peer... ");
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

    if let Err(e) = transport.stop_advertising().await {
        println!("stop advertising: {e}");
    }
    match transport.shutdown().await {
        Ok(()) => println!("shutdown: clean"),
        Err(e) => println!("shutdown: {e}"),
    }
}
