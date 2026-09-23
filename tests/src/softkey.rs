//! A software ES256 authenticator: what a YubiKey does, minus the USB.
//! Produces the same key-store file and assertion shape the plugin verifies,
//! so the sign-off e2e tests exercise the real broker path end to end.

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::EncodePublicKey;
use sha2::{Digest, Sha256};

pub struct SoftKey {
    sk: SigningKey,
    pub credential_id: Vec<u8>,
    pub label: String,
}

impl SoftKey {
    /// Deterministic key for `seed`, so tests are reproducible.
    pub fn new(seed: u8, label: &str) -> Self {
        let mut bytes = [seed; 32];
        bytes[0] = 0x21;
        SoftKey {
            sk: SigningKey::from_slice(&bytes).expect("scalar in range"),
            credential_id: vec![seed; 20],
            label: label.to_string(),
        }
    }

    pub fn public_key_der(&self) -> Vec<u8> {
        VerifyingKey::from(&self.sk)
            .to_public_key_der()
            .expect("spki der")
            .as_bytes()
            .to_vec()
    }

    /// `signoff_keys.json` enrolling these keys.
    pub fn key_file(keys: &[&SoftKey]) -> String {
        let entries: Vec<serde_json::Value> = keys
            .iter()
            .map(|k| {
                serde_json::json!({
                    "label": k.label,
                    "credential_id": hex(&k.credential_id),
                    "public_key_der": hex(&k.public_key_der()),
                })
            })
            .collect();
        serde_json::json!({ "v": 1, "keys": entries }).to_string()
    }

    /// Assertion over `challenge` for `rp_id` with the given flag byte
    /// (0x01 = user present, 0x05 = present + verified), as the proof
    /// object `signoff_resolve` expects.
    pub fn assert(
        &self,
        rp_id: &str,
        challenge: &[u8],
        flags: u8,
        count: u32,
    ) -> serde_json::Value {
        let mut auth_data = Sha256::digest(rp_id.as_bytes()).to_vec();
        auth_data.push(flags);
        auth_data.extend_from_slice(&count.to_be_bytes());
        let mut message = auth_data.clone();
        message.extend_from_slice(&Sha256::digest(challenge));
        let sig: Signature = self.sk.sign(&message);
        serde_json::json!({
            "credential_id": hex(&self.credential_id),
            "auth_data": hex(&auth_data),
            "signature": hex(sig.to_der().as_bytes()),
        })
    }

    /// Proof for a held entry as returned by `signoff_list`.
    pub fn approve(&self, rp_id: &str, held: &serde_json::Value) -> serde_json::Value {
        let challenge = unhex(held["request_hash"].as_str().expect("request_hash"));
        self.assert(rp_id, &challenge, 0x01, 1)
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}
