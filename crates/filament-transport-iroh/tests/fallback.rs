//! Failure is explicit: a dead relay or a missing relay configuration returns
//! an error, quickly, and nothing is forced.
#![cfg(feature = "iroh-transport")]

use std::time::{Duration, Instant};

use filament_transport_iroh::identity::DeviceIdentity;
use filament_transport_iroh::relay::RelayPlan;
use filament_transport_iroh::transport::{IrohConfig, IrohNode};
use filament_transport_iroh::{enabled_with, NodeKeyMode};

#[test]
fn runtime_gate_defaults_off() {
    assert!(!enabled_with(None));
    assert!(!enabled_with(Some("0")));
    assert!(enabled_with(Some("1")));
}

#[test]
fn dead_relay_fails_instead_of_hanging_or_forcing() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        // Loopback port 1: connection refused, so this cannot accidentally be
        // satisfied by something listening on the test host.
        let plan = RelayPlan::parse([("https://127.0.0.1:1", true)]).unwrap();
        let config = IrohConfig {
            relays: plan,
            key_mode: NodeKeyMode::Derived,
            relay_online_timeout: Duration::from_secs(1),
            bind_timeout: Duration::from_secs(5),
            ..IrohConfig::default()
        };
        let started = Instant::now();
        let result = IrohNode::bind(DeviceIdentity::from_seed(&[0x41; 32]), config).await;
        let elapsed = started.elapsed();

        let error = result.expect_err("a dead relay must not produce a node");
        let text = format!("{error:#}");
        assert!(
            text.contains("did not come online") || text.contains("bind failed"),
            "unexpected error: {text}"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "dead relay took {elapsed:?}; a fallback decision cannot wait forever"
        );
    });
}

#[test]
fn no_relay_configuration_is_an_error_not_a_public_default() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let config = IrohConfig {
            relays: RelayPlan::empty(),
            ..IrohConfig::default()
        };
        let node = IrohNode::bind(DeviceIdentity::from_seed(&[0x42; 32]), config)
            .await
            .expect("binding with relay-disabled is allowed");

        let peer = DeviceIdentity::from_seed(&[0x43; 32]).binding(NodeKeyMode::Derived);
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let error = node
            .connect("peer", &peer, None, tx)
            .await
            .expect_err("no relay must not silently become RelayMode::Default");
        assert!(
            error.to_string().contains("no relay configured"),
            "unexpected error: {error}"
        );
    });
}
