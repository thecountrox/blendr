//! `memory_smoke` — exercises the in-memory transport end to end:
//! discovery, connect, fragmented bidirectional frames at 20-byte packets,
//! range loss, and clean reconnect. Prints each check; exits non-zero on
//! failure. No secrets, fixed test frames only.

use std::process::ExitCode;
use std::time::Duration;

use blendr_transport::memory::MemoryNetwork;
use blendr_transport::{BleTransport, LinkConfig, PeerEvent, Result, TransportError};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const SERVICE: &str = "c2f60001-e7ca-4ac2-b6cd-10d5c0bf0001";

fn check(name: &str, ok: bool, detail: &str) -> usize {
    println!("[{}] {name}: {detail}", if ok { "PASS" } else { "FAIL" });
    usize::from(!ok)
}

async fn run() -> Result<()> {
    let mut failures = 0usize;
    let cancel = CancellationToken::new();

    // 20-byte packets like the legacy BLE ATT MTU; bounded queues.
    let net = MemoryNetwork::new(20, 16)?;
    let link_cfg = LinkConfig {
        max_frame_bytes: 4096,
        reassembly_timeout: Duration::from_secs(1),
    };
    let alice = net.node("alice", link_cfg)?;
    let bob = net.node("bob", link_cfg)?;
    println!("nodes: {} {}", alice.name(), bob.name());

    // Advertise (service-only beacon) and scan.
    bob.start_advertising(Uuid::parse_str(SERVICE).unwrap())
        .await?;
    let mut peers = alice.watch_peers().await?;
    let bob_locator = match peers.recv().await {
        Some(PeerEvent::Discovered(l)) => l,
        other => {
            eprintln!("FAIL discovery: got {other:?}");
            std::process::exit(1);
        }
    };
    failures += check("discovery", true, "alice saw bob's beacon");

    // Connect.
    let mut accept = bob.accept_links().await?;
    let mut a_link = alice.connect(bob_locator.clone(), &cancel).await?;
    let mut b_link = accept.recv().await.expect("accept queue empty");
    failures += check(
        "roles",
        a_link.role() == blendr_transport::LinkRole::Initiator
            && b_link.role() == blendr_transport::LinkRole::Responder,
        "initiator/responder assigned",
    );

    // Several exact fixed frames, both directions (multi-fragment at mtu 20).
    let frames_a2b: Vec<Vec<u8>> = vec![
        b"BLENDR-SMOKE-1".to_vec(),
        (0u8..64).collect(),
        vec![0xAA; 19],
    ];
    let frames_b2a: Vec<Vec<u8>> = vec![b"ack:1".to_vec(), (0u8..100).map(|x| x ^ 0x55).collect()];
    for (i, f) in frames_a2b.iter().enumerate() {
        a_link.send_frame(f, &cancel).await?;
        let got = b_link.recv_frame(&cancel).await?;
        failures += check(
            &format!("a->b frame {i}"),
            got == *f,
            &format!("{} bytes exact", f.len()),
        );
    }
    for (i, f) in frames_b2a.iter().enumerate() {
        b_link.send_frame(f, &cancel).await?;
        let got = a_link.recv_frame(&cancel).await?;
        failures += check(
            &format!("b->a frame {i}"),
            got == *f,
            &format!("{} bytes exact", f.len()),
        );
    }

    // Range loss breaks the live link.
    net.set_in_range("alice", "bob", false)?;
    let send_err = a_link.send_frame(b"lost", &cancel).await;
    let recv_err = b_link.recv_frame(&cancel).await;
    failures += check(
        "range loss severs link",
        matches!(send_err, Err(TransportError::Disconnected))
            && matches!(recv_err, Err(TransportError::Disconnected)),
        "both endpoints observe Disconnected",
    );
    match peers.recv().await {
        Some(PeerEvent::Lost(_)) => failures += check("lost event", true, "alice notified"),
        _ => failures += check("lost event", false, "no Lost event"),
    }

    // Back in range: rediscover and reconnect resumes clean.
    net.set_in_range("alice", "bob", true)?;
    let loc2 = loop {
        match peers.recv().await {
            Some(PeerEvent::Discovered(l)) => break l,
            Some(PeerEvent::Lost(_)) => continue,
            None => {
                eprintln!("FAIL rediscovery");
                std::process::exit(1);
            }
        }
    };
    let mut a2 = alice.connect(loc2, &cancel).await?;
    let mut b2 = accept.recv().await.expect("reconnect not accepted");
    a2.send_frame(b"resumed-cleanly", &cancel).await?;
    let got = b2.recv_frame(&cancel).await?;
    failures += check(
        "reconnect clean",
        got == b"resumed-cleanly",
        "no stale reassembly state",
    );

    a2.close().await?;
    println!("done: {failures} failure(s)");
    if failures == 0 {
        Ok(())
    } else {
        std::process::exit(1)
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("smoke error: {e}");
            ExitCode::FAILURE
        }
    }
}
