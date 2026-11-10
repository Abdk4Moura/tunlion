//! Hex encoding for the fixed-size key and signature fields inside sealed
//! bodies. Local to the crate so the frame types stay ordinary serde types.

pub mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &[u8; 32], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&hex::encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(de)?;
        let bytes = hex::decode(&text).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 hex-encoded bytes"))
    }
}

pub mod hex64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &[u8; 64], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&hex::encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 64], D::Error> {
        let text = String::deserialize(de)?;
        let bytes = hex::decode(&text).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 hex-encoded bytes"))
    }
}
