//! Conformance: the Rust core against `vectors/v1.json`, which is produced by
//! an independent reference implementation (`vectors/gen_vectors.py`, Python
//! standard library only, written from the spec). Any other client runs the
//! same file.

use std::net::{IpAddr, Ipv4Addr};

use serde_json::Value;
use tunlion_lan::{iface, mdns, record, wire};

fn vectors() -> Value {
    serde_json::from_str(include_str!("../vectors/v1.json")).expect("v1.json parses")
}

fn h<const N: usize>(v: &Value) -> [u8; N] {
    let b = hex::decode(v.as_str().expect("hex string")).expect("hex");
    b.as_slice().try_into().expect("length")
}

#[test]
fn presence_beacon_bytes() {
    let v = &vectors()["presence"];
    let pk: [u8; 32] = h(&v["presence_key"]);
    let nonce: [u8; 12] = h(&v["nonce"]);
    let unix = v["unix"].as_u64().unwrap();
    let port = v["port"].as_u64().unwrap() as u16;
    assert_eq!(wire::epoch(unix) as u64, v["epoch"].as_u64().unwrap());
    assert_eq!(hex::encode(wire::presence_tag(&pk, wire::epoch(unix), &nonce, port)), v["tag"].as_str().unwrap());
    let b = wire::presence(&pk, unix, nonce, port).encode();
    assert_eq!(hex::encode(b), v["beacon"].as_str().unwrap());
    assert_eq!(wire::Beacon::decode(&b).unwrap().encode(), b);
}

#[test]
fn recognize_vectors() {
    for case in vectors()["recognize"].as_array().unwrap() {
        let raw: [u8; 34] = h(&case["beacon"]);
        let b = wire::Beacon::decode(&raw).unwrap();
        let keys: Vec<[u8; 32]> = case["keys"].as_array().unwrap().iter().map(|k| h::<32>(k)).collect();
        let got = wire::recognize(&b, &keys, case["unix"].as_u64().unwrap());
        assert_eq!(got.map(|i| i as u64), case["match"].as_u64(), "case {case}");
    }
}

#[test]
fn query_and_pairing_bytes() {
    let v = vectors();
    let q = &v["query"];
    assert_eq!(hex::encode(wire::query(h(&q["nonce"])).encode()), q["beacon"].as_str().unwrap());
    let p = &v["pairing"];
    let id: [u8; 16] = h(&p["id"]);
    let b = wire::pairing(id, h(&p["nonce"]), p["port"].as_u64().unwrap() as u16).encode();
    assert_eq!(hex::encode(b), p["beacon"].as_str().unwrap());
    assert_eq!(wire::pairing_label(&id), p["label"].as_str().unwrap());
}

#[test]
fn malformed_are_rejected() {
    for m in vectors()["malformed"].as_array().unwrap() {
        let b = hex::decode(m.as_str().unwrap()).unwrap();
        assert!(wire::Beacon::decode(&b).is_none(), "accepted malformed {m}");
    }
}

#[test]
fn mdns_bytes() {
    let v = &vectors()["mdns"];
    let beacon: [u8; 34] = h(&v["beacon"]);
    let addrs: Vec<IpAddr> = v["addrs"].as_array().unwrap().iter().map(|a| a.as_str().unwrap().parse().unwrap()).collect();
    let ann = mdns::announce(v["label"].as_str().unwrap(), &beacon, v["port"].as_u64().unwrap() as u16, &addrs);
    assert_eq!(hex::encode(&ann), v["announce"].as_str().unwrap());
    assert_eq!(mdns::parse(&ann), mdns::Parsed::Beacons(vec![beacon]));
    assert_eq!(hex::encode(mdns::query()), v["query"].as_str().unwrap());
    assert_eq!(mdns::parse(&mdns::query()), mdns::Parsed::Query);
}

#[test]
fn hello_vector() {
    let v = &vectors()["hello"];
    let hello = record::Hello::from_json(&v["json"]).expect("hello parses");
    let kept: Vec<String> = hello.addrs.iter().map(|a| a.ip.to_string()).collect();
    let want: Vec<String> = v["kept"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect();
    assert_eq!(kept, want);
    assert_eq!(record::Hello::from_json(&hello.to_json()), Some(hello));
}

#[test]
fn sweep_vectors() {
    for case in vectors()["sweep"].as_array().unwrap() {
        let net: Ipv4Addr = case["net"].as_str().unwrap().parse().unwrap();
        let own: Vec<Ipv4Addr> = case["own"].as_array().unwrap().iter().map(|a| a.as_str().unwrap().parse().unwrap()).collect();
        let got: Vec<String> = iface::sweep_hosts(net, case["prefix"].as_u64().unwrap() as u8, &own).iter().map(|a| a.to_string()).collect();
        if let Some(hosts) = case["hosts"].as_array() {
            let want: Vec<String> = hosts.iter().map(|s| s.as_str().unwrap().to_string()).collect();
            assert_eq!(got, want, "case {case}");
        } else {
            assert_eq!(got.len() as u64, case["count"].as_u64().unwrap());
            assert_eq!(got.first().unwrap(), case["first"].as_str().unwrap());
            assert_eq!(got.last().unwrap(), case["last"].as_str().unwrap());
        }
    }
}
