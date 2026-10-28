//! Acceptance test for the PoC: two local nodes, one local relay, a
//! bidirectional stream, an echo, and a datagram.
//!
//! `relay_only` is on, so the endpoints have no IP transports. If this test
//! passes, the relay path carried the traffic; a loopback direct path was not
//! available to cheat with.
#![cfg(all(feature = "iroh-transport", feature = "test-relay"))]

use std::sync::Arc;
use std::time::Duration;

use filament_transport::net::{Ev, Transport};
use filament_transport_iroh::identity::DeviceIdentity;
use filament_transport_iroh::relay::RelayPlan;
use filament_transport_iroh::transport::{IrohConfig, IrohNode};
use filament_transport_iroh::{NodeKeyMode, ALPN};
use tokio::sync::mpsc::unbounded_channel;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_nodes_echo_over_relay_and_exchange_a_datagram() {
    let (_map, relay_url, _server) = iroh::test_utils::run_relay_server()
        .await
        .expect("in-process relay");
    let relay = relay_url.to_string();

    // Health probe evidence, before any endpoint is built. The live relay is
    // reachable; a dead loopback port is not; healthy_order puts the live one
    // first even though it was configured second.
    let plan = RelayPlan::parse([(relay.as_str(), true)]).unwrap();
    let health = plan.probe().await;
    assert_eq!(health.len(), 1);
    assert!(
        health[0].is_reachable(),
        "in-process relay probe failed: {:?}",
        health[0].error
    );

    let mixed = RelayPlan::parse([("https://127.0.0.1:1", true), (relay.as_str(), true)]).unwrap();
    let ordered = mixed.healthy_order().await;
    assert_eq!(ordered.len(), 2);
    assert_eq!(ordered[0].url, relay_url, "reachable relay must sort first");

    let config = IrohConfig {
        relays: plan,
        key_mode: NodeKeyMode::Derived,
        relay_only: true,
        relay_online_timeout: Duration::from_secs(20),
        connect_timeout: Duration::from_secs(20),
        ..IrohConfig::default()
    };

    let a = Arc::new(
        IrohNode::bind(DeviceIdentity::from_seed(&[0x31; 32]), config.clone())
            .await
            .expect("bind A"),
    );
    let b = Arc::new(
        IrohNode::bind(DeviceIdentity::from_seed(&[0x32; 32]), config)
            .await
            .expect("bind B"),
    );

    assert_eq!(ALPN, b"filament/iroh-transport/1");
    assert_ne!(a.endpoint_id(), b.endpoint_id());
    assert_ne!(a.device_pub(), b.device_pub());

    let (tx_a, mut rx_a) = unbounded_channel::<Ev>();
    let (tx_b, mut rx_b) = unbounded_channel::<Ev>();

    let accept = {
        let b = b.clone();
        let expected_a = a.device_pub();
        tokio::spawn(async move { b.accept_one("node-a", Some(expected_a), tx_b).await })
    };

    let a_transport = a
        .connect("node-b", b.binding(), Some(&relay_url), tx_a)
        .await
        .expect("A connect");
    let b_transport = accept.await.expect("accept task").expect("B accept");

    // The binding is authenticated by the iroh handshake AND the device
    // signature; each side sees the other's real device key.
    assert_eq!(a_transport.peer_device_pub(), b.device_pub());
    assert_eq!(b_transport.peer_device_pub(), a.device_pub());
    assert_eq!(a_transport.peer_endpoint_id(), b.endpoint_id());
    assert_eq!(b_transport.peer_endpoint_id(), a.endpoint_id());
    assert!(a_transport.peer_binding().verify().is_ok());
    // The test's whole claim: this traffic is on the relay path, not a
    // loopback direct path.
    assert_eq!(
        a_transport.selected_path_is_relay(),
        Some(true),
        "relay_only connection did not select a relay path"
    );
    assert_eq!(b_transport.selected_path_is_relay(), Some(true));
    assert!(a_transport.rtt_ms().is_some());

    // --- bidirectional stream, both directions ---------------------------
    a_transport
        .send_frame(7, 0, b"hello from A")
        .await
        .expect("A send_frame");
    let event = tokio::time::timeout(Duration::from_secs(10), rx_b.recv())
        .await
        .expect("B receive timeout")
        .expect("B channel");
    match event {
        Ev::Chunk(peer, sid, offset, bytes) => {
            assert_eq!(peer, "node-a");
            assert_eq!(sid, 7);
            assert_eq!(offset, Some(0));
            assert_eq!(bytes.as_ref(), b"hello from A");
        }
        other => panic!("B got {other:?}"),
    }

    b_transport
        .send_frame(7, 0, b"echo from B")
        .await
        .expect("B send_frame");
    let event = tokio::time::timeout(Duration::from_secs(10), rx_a.recv())
        .await
        .expect("A receive timeout")
        .expect("A channel");
    match event {
        Ev::Chunk(peer, sid, offset, bytes) => {
            assert_eq!(peer, "node-b");
            assert_eq!(sid, 7);
            assert_eq!(offset, Some(0));
            assert_eq!(bytes.as_ref(), b"echo from B");
        }
        other => panic!("A got {other:?}"),
    }

    // --- control frames use the same stream ------------------------------
    a_transport
        .send_control(&serde_json::json!({"t":"hello","v":1}))
        .await
        .expect("A send_control");
    match tokio::time::timeout(Duration::from_secs(10), rx_b.recv())
        .await
        .expect("B control timeout")
        .expect("B channel")
    {
        Ev::Control(peer, value) => {
            assert_eq!(peer, "node-a");
            assert_eq!(value["t"], "hello");
        }
        other => panic!("B got {other:?}"),
    }

    // --- datagrams -------------------------------------------------------
    let max = a_transport
        .max_datagram_size()
        .expect("iroh connection negotiated datagram support");
    assert!(max > 8);
    assert!(a_transport.supports_datagrams());
    // A relay path is not one socket 5-tuple; the PoC says so instead of
    // inventing an address.
    assert!(a_transport.remote_addr().is_none());
    assert!(a_transport.local_ip().is_none());

    a_transport.send_datagram(b"ping").expect("A datagram");
    let datagram = tokio::time::timeout(Duration::from_secs(10), b_transport.recv_datagram())
        .await
        .expect("B datagram timeout")
        .expect("B datagram");
    assert_eq!(datagram.as_ref(), b"ping");

    b_transport.send_datagram(b"pong").expect("B datagram");
    let datagram = tokio::time::timeout(Duration::from_secs(10), a_transport.recv_datagram())
        .await
        .expect("A datagram timeout")
        .expect("A datagram");
    assert_eq!(datagram.as_ref(), b"pong");

    // --- channel binding: same secret on both ends -----------------------
    let a_binding = a_transport.channel_binding().expect("A keying material");
    let b_binding = b_transport.channel_binding().expect("B keying material");
    assert_eq!(a_binding, b_binding);
    assert_eq!(a_binding.len(), 32);

    assert!(a_transport.is_alive());
    assert!(b_transport.is_alive());
    assert!(a_transport.has_flowed());
    assert_eq!(a_transport.max_payload(), 1024 * 1024);
    assert_ne!(a_transport.sid_answerer(), b_transport.sid_answerer());
}
