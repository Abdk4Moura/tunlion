//! Replays the shared browser vectors through the native implementation.
//!
//! The fixture is deliberately plain JSON at a stable path so a browser test
//! can fetch the same file and compare `admitTransfer(JSON.stringify(input))`
//! against `expected` without a second copy of the cases.

use serde_json::Value;
use tunlion_policy_wasm::{AdmitTransferInput, AdmitTransferOutput, admit_transfer};

const VECTORS: &str = include_str!("../testdata/transfer_vectors.json");

#[test]
fn every_transfer_vector_matches_the_shared_policy() {
    let document: Value = serde_json::from_str(VECTORS).expect("vectors are valid JSON");
    let cases = document["cases"].as_array().expect("vectors have a cases array");
    assert!(!cases.is_empty(), "vector file must not be empty");

    for case in cases {
        let name = case["name"].as_str().expect("case has a name");
        let input = &case["input"];
        let expected = &case["expected"];

        // The DTO itself must accept the vector unchanged: this catches drift
        // between the documented field names and the serde wire shape.
        let typed: AdmitTransferInput =
            serde_json::from_value(input.clone()).unwrap_or_else(|err| {
                panic!("vector {name}: input does not match AdmitTransferInput: {err}")
            });

        let actual_json = admit_transfer(&input.to_string());
        let actual: Value = serde_json::from_str(&actual_json)
            .unwrap_or_else(|err| panic!("vector {name}: output is not JSON: {err}"));
        assert_eq!(actual, *expected, "vector {name}: decision drifted");

        // Also pin the typed output shape, not just this one serialization.
        let typed_output: AdmitTransferOutput =
            serde_json::from_value(actual).unwrap_or_else(|err| {
                panic!("vector {name}: output does not match AdmitTransferOutput: {err}")
            });
        assert_eq!(
            typed.decide(),
            typed_output,
            "vector {name}: typed decision differs from JSON"
        );
    }
}

#[test]
fn malformed_input_is_an_error_object_not_a_panic() {
    let parsed: Value = serde_json::from_str(&admit_transfer("{not json")).expect("valid JSON");
    assert!(
        parsed["error"].as_str().is_some_and(|m| !m.is_empty()),
        "malformed input must return an error object"
    );
}

#[test]
fn unknown_fields_are_refused() {
    let mut input = serde_json::json!({
        "authoritative": true,
        "legacyAllowed": true,
        "outcome": { "kind": "authorized" },
        "certRevoked": false,
        "denied": false,
        "authKeyCaps": null,
        "certExpires": 2000,
        "now": 1000,
        "sameOwner": false,
        "binding": "proven",
        "scopedInBounds": true,
        "hasExplicitGrant": false,
        "ceilingAuthorizes": false,
        "identityState": "resolved"
    });
    input["browserGuess"] = Value::Bool(true);
    let parsed: Value = serde_json::from_str(&admit_transfer(&input.to_string()))
        .expect("error response is valid JSON");
    assert!(
        parsed["error"].as_str().is_some(),
        "unknown fields must not be silently ignored"
    );
}
