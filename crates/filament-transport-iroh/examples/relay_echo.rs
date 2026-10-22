//! Two local iroh endpoints meet through a local iroh relay, echo bytes over a
//! bidirectional stream, and exchange a datagram.
//!
//! Run:
//!
//! ```text
//! cargo run -p filament-transport-iroh \
//!   --features iroh-transport,test-relay --example relay_echo
//! ```
//!
//! This is a PoC demonstration, not a benchmark. It deliberately forces
//! `relay_only` (no IP transports) so the bytes cannot quietly take a direct
//! loopback path: the relay is the only path available to the endpoint.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use filament_transport::net::{Ev, Transport};
use filament_transport_iroh::identity::DeviceIdentity;
use filament_transport_iroh::relay::RelayPlan;
use filament_transport_iroh::transport::{IrohConfig, IrohNode};
use filament_transport_iroh::NodeKeyMode;
use tokio::sync::mpsc::unbounded_channel;

#[tokio::main]
async fn main() -> Result<()> {
    // A local relay with a self-signed cert; RelayPlan only permits
    // insecure_skip_verify for a loopback URL.
    let (_map, relay_url, _server) = iroh::test_utils::run_relay_server()
        .await
        .context("start in-process iroh relay")?;
    println!("relay: {relay_url}");

    let plan = RelayPlan::parse([(relay_url.as_str(), true)])?;
    let config = IrohConfig {
        relays: plan,
        key_mode: NodeKeyMode::Derived,
        relay_only: true,
        relay_online_timeout: Duration::from_secs(20),
        connect_timeout: Duration::from_secs(20),
        ..IrohConfig::default()
    };

    let a = Arc::new(
        IrohNode::bind(DeviceIdentity::from_seed(&[0x11; 32]), config.clone())
            .await
            .context("bind node A")?,
    );
    let b = Arc::new(
        IrohNode::bind(DeviceIdentity::from_seed(&[0x22; 32]), config)
            .await
            .context("bind node B")?,
    );
    println!("A endpoint: {}", a.endpoint_id());
    println!("B endpoint: {}", b.endpoint_id());
    println!("A device:   {}", hex::encode(a.device_pub()));
    println!("B device:   {}", hex::encode(b.device_pub()));

    let (tx_a, mut rx_a) = unbounded_channel::<Ev>();
    let (tx_b, mut rx_b) = unbounded_channel::<Ev>();

    let b_task = {
        let b = b.clone();
        let expected_a = a.device_pub();
        let tx = tx_b.clone();
        tokio::spawn(async move { b.accept_one("node-a", Some(expected_a), tx).await })
    };

    let a_transport = a
        .connect("node-b", b.binding(), Some(&relay_url), tx_a)
        .await
        .context("A connect to B")?;
    let b_transport = b_task.await.context("accept task panicked")??;
    println!(
        "connected: A sees device {} / node {} / relay path {:?}",
        hex::encode(a_transport.peer_device_pub()),
        a_transport.peer_endpoint_id(),
        a_transport.selected_path_is_relay()
    );
    if a_transport.selected_path_is_relay() != Some(true) {
        bail!("relay_only connection did not select a relay path");
    }

    // --- bidirectional stream: A -> B -> A --------------------------------
    let payload = b"tunlion over iroh relay";
    a_transport.send_frame(7, 0, payload).await?;
    let got = tokio::time::timeout(Duration::from_secs(10), rx_b.recv())
        .await
        .context("B did not receive A's frame")?
        .context("B event channel closed")?;
    match got {
        Ev::Chunk(peer, sid, offset, bytes) => {
            println!("B got {bytes:?} sid={sid} offset={offset:?} from {peer}");
            if sid != 7 || offset != Some(0) || bytes.as_ref() != payload {
                bail!("B received the wrong frame");
            }
        }
        other => bail!("B received an unexpected event: {other:?}"),
    }

    b_transport
        .send_frame(7, 0, b"echo: tunlion over iroh relay")
        .await?;
    let got = tokio::time::timeout(Duration::from_secs(10), rx_a.recv())
        .await
        .context("A did not receive the echo")?
        .context("A event channel closed")?;
    match got {
        Ev::Chunk(_, sid, Some(0), bytes) => println!("A got echo: {bytes:?} (sid {sid})"),
        other => bail!("A received an unexpected event: {other:?}"),
    }

    // --- datagram ---------------------------------------------------------
    match a_transport.max_datagram_size() {
        Some(max) => {
            println!("datagrams supported, max payload {max}");
            a_transport.send_datagram(b"ping-datagram")?;
            let datagram =
                tokio::time::timeout(Duration::from_secs(10), b_transport.recv_datagram())
                    .await
                    .context("B did not receive the datagram")??;
            println!("B got datagram: {datagram:?}");
            if datagram.as_ref() != b"ping-datagram" {
                bail!("datagram payload mismatch");
            }
        }
        None => println!("datagrams NOT supported on this path (reported, not faked)"),
    }

    // --- channel binding --------------------------------------------------
    let a_binding = a_transport.channel_binding();
    let b_binding = b_transport.channel_binding();
    println!(
        "channel binding equal: {} (len {:?})",
        a_binding == b_binding,
        a_binding.as_ref().map(Vec::len)
    );
    if a_binding.is_none() || a_binding != b_binding {
        bail!("channel binding is not shared across the iroh connection");
    }

    println!("PASS: relay path carried a bi stream, an echo and a datagram");
    Ok(())
}
