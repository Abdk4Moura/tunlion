//! The binding is a signature by the DEVICE key over the node key. These tests
//! pin the properties a relay or a peer cannot break.
#![cfg(feature = "iroh-transport")]

use filament_transport_iroh::identity::{DeviceIdentity, IrohBinding, NodeKeyMode};

#[test]
fn derivation_is_deterministic_and_domain_separated() {
    let seed = [0x51u8; 32];
    let one = DeviceIdentity::from_seed(&seed);
    let two = DeviceIdentity::from_seed(&seed);
    assert_eq!(
        one.node_public(NodeKeyMode::Derived),
        two.node_public(NodeKeyMode::Derived)
    );
    assert_ne!(
        one.node_public(NodeKeyMode::Derived).as_bytes(),
        one.node_public(NodeKeyMode::Direct).as_bytes()
    );
    // Direct mode really is the device key, not merely derived from it.
    assert_eq!(
        one.node_public(NodeKeyMode::Direct).as_bytes(),
        &one.device_public()
    );
}

#[test]
fn a_binding_cannot_be_reused_for_another_device() {
    let a = DeviceIdentity::from_seed(&[0x52u8; 32]);
    let b = DeviceIdentity::from_seed(&[0x53u8; 32]);
    let binding = a.binding(NodeKeyMode::Derived);

    binding.verify_for(&a).expect("own binding");
    assert!(
        binding.verify_for(&b).is_err(),
        "another device must not claim A's node"
    );
}

#[test]
fn a_tampered_wire_record_is_refused() {
    let a = DeviceIdentity::from_seed(&[0x54u8; 32]);
    let wire = a.binding(NodeKeyMode::Derived).to_json();

    // The relay case: swap the node id for one the relay controls.
    let relay_key = DeviceIdentity::from_seed(&[0x55u8; 32]);
    let mut swapped = wire.clone();
    swapped["endpointId"] =
        serde_json::json!(relay_key.node_public(NodeKeyMode::Derived).to_string());
    assert!(IrohBinding::from_json(&swapped).unwrap().verify().is_err());

    // The device-swap case: change who the record says owns the node.
    let other = DeviceIdentity::from_seed(&[0x56u8; 32]);
    let mut swapped = wire;
    swapped["devicePub"] = serde_json::json!(hex::encode(other.device_public()));
    assert!(IrohBinding::from_json(&swapped).unwrap().verify().is_err());
}
