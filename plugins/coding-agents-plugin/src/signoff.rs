//! Hardware-key sign-off: FIDO2 assertion verification for held requests.
//!
//! When `signoff.enabled` is set, an `ask` verdict (from a Falco rule or the
//! LLM monitor) is not returned to the agent. The broker keeps the request
//! open ("held"), seals its audit record, and waits for an operator to
//! approve it with a registered FIDO2 authenticator (`premptictl signoff
//! approve`). The authenticator signs a challenge derived from the audit
//! record hash, so the signature binds the operator's touch to exactly one
//! tool call and cannot be replayed for another.
//!
//! Wire format of a proof (hex strings, produced by `premptictl`):
//!
//! ```json
//! {"credential_id":"…","auth_data":"…","signature":"…"}
//! ```
//!
//! Verification (WebAuthn/CTAP2 assertion rules, ES256 only):
//! - `credential_id` must be enrolled in the key store;
//! - `auth_data[0..32]` must equal `sha256(rp_id)`;
//! - the user-present flag (`auth_data[32] & 0x01`) must be set, and the
//!   user-verified flag when `require_uv` is on;
//! - `signature` must be a DER ECDSA-P256/SHA-256 signature over
//!   `auth_data || sha256(challenge)` under the enrolled public key.
//!
//! The challenge is the raw 32 bytes of the held request's audit record
//! hash. `ctap-hid-fido2` hands the authenticator `sha256(challenge)` as the
//! client data hash, which is why the second half of the signed message is
//! hashed once more here.

use std::path::Path;

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};

/// Key store schema version.
const KEYS_VERSION: u64 = 1;

/// One enrolled authenticator credential.
#[derive(Clone, Debug)]
pub struct EnrolledKey {
    pub label: String,
    pub credential_id: Vec<u8>,
    /// SubjectPublicKeyInfo DER, or a raw SEC1 point (65 bytes).
    pub public_key: Vec<u8>,
}

/// The set of authenticators allowed to sign off. Loaded once at init.
#[derive(Clone, Debug, Default)]
pub struct KeyStore {
    pub keys: Vec<EnrolledKey>,
}

impl KeyStore {
    /// Parse `config/signoff_keys.json`:
    /// `{"v":1,"keys":[{"label":"…","credential_id":"<hex>","public_key_der":"<hex>"}]}`.
    pub fn parse(text: &str) -> Result<Self, String> {
        let v: serde_json::Value =
            serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
        let version = v.get("v").and_then(|x| x.as_u64()).unwrap_or(KEYS_VERSION);
        if version != KEYS_VERSION {
            return Err(format!("unsupported key store version {version}"));
        }
        let mut keys = Vec::new();
        for (i, k) in v
            .get("keys")
            .and_then(|k| k.as_array())
            .ok_or_else(|| "missing `keys` array".to_string())?
            .iter()
            .enumerate()
        {
            let label = k
                .get("label")
                .and_then(|l| l.as_str())
                .unwrap_or("")
                .to_string();
            let credential_id = hex_decode(
                k.get("credential_id")
                    .and_then(|c| c.as_str())
                    .unwrap_or(""),
            )
            .map_err(|e| format!("key {i} ({label}): credential_id {e}"))?;
            let public_key = hex_decode(
                k.get("public_key_der")
                    .and_then(|c| c.as_str())
                    .unwrap_or(""),
            )
            .map_err(|e| format!("key {i} ({label}): public_key_der {e}"))?;
            if credential_id.is_empty() || public_key.is_empty() {
                return Err(format!(
                    "key {i} ({label}): credential_id and public_key_der are required"
                ));
            }
            // Fail at load time, not at the first approval, if the key is unusable.
            parse_verifying_key(&public_key).map_err(|e| format!("key {i} ({label}): {e}"))?;
            keys.push(EnrolledKey {
                label,
                credential_id,
                public_key,
            });
        }
        Ok(KeyStore { keys })
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn find(&self, credential_id: &[u8]) -> Option<&EnrolledKey> {
        self.keys.iter().find(|k| k.credential_id == credential_id)
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Sign-off policy the broker consults for held requests.
#[derive(Clone, Debug)]
pub struct SignoffPolicy {
    pub rp_id: String,
    pub require_uv: bool,
    pub keys: KeyStore,
}

/// A FIDO2 assertion as sent by `premptictl signoff approve`.
#[derive(Clone, Debug)]
pub struct Proof {
    pub credential_id: Vec<u8>,
    pub auth_data: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Proof {
    pub fn from_json(v: &serde_json::Value) -> Result<Self, String> {
        let field = |name: &str| -> Result<Vec<u8>, String> {
            let s = v
                .get(name)
                .and_then(|x| x.as_str())
                .ok_or_else(|| format!("proof.{name} missing"))?;
            hex_decode(s).map_err(|e| format!("proof.{name} {e}"))
        };
        Ok(Proof {
            credential_id: field("credential_id")?,
            auth_data: field("auth_data")?,
            signature: field("signature")?,
        })
    }
}

/// What a successful verification established; goes into the audit record.
#[derive(Clone, Debug)]
pub struct Verified {
    pub key_label: String,
    pub credential_id_hex: String,
    pub sign_count: u32,
    pub user_present: bool,
    pub user_verified: bool,
}

/// Verify `proof` over `challenge` under `policy`. Errors are operator
/// facing and never leak key material.
pub fn verify(policy: &SignoffPolicy, challenge: &[u8], proof: &Proof) -> Result<Verified, String> {
    let key = policy
        .keys
        .find(&proof.credential_id)
        .ok_or_else(|| "credential is not enrolled".to_string())?;
    if proof.auth_data.len() < 37 {
        return Err(format!(
            "auth_data too short ({} bytes, need at least 37)",
            proof.auth_data.len()
        ));
    }
    let rp_hash = Sha256::digest(policy.rp_id.as_bytes());
    if proof.auth_data[..32] != rp_hash[..] {
        return Err(format!(
            "rp_id hash mismatch (authenticator was asked for a different rp_id than `{}`)",
            policy.rp_id
        ));
    }
    let flags = proof.auth_data[32];
    let user_present = flags & 0x01 != 0;
    let user_verified = flags & 0x04 != 0;
    if !user_present {
        return Err("user-present flag not set (no touch)".to_string());
    }
    if policy.require_uv && !user_verified {
        return Err("user-verified flag not set (PIN or biometric required)".to_string());
    }
    let sign_count = u32::from_be_bytes([
        proof.auth_data[33],
        proof.auth_data[34],
        proof.auth_data[35],
        proof.auth_data[36],
    ]);

    let vk = parse_verifying_key(&key.public_key)?;
    let sig = Signature::from_der(&proof.signature)
        .map_err(|_| "signature is not DER ECDSA".to_string())?;
    let mut message = Vec::with_capacity(proof.auth_data.len() + 32);
    message.extend_from_slice(&proof.auth_data);
    message.extend_from_slice(&Sha256::digest(challenge));
    vk.verify(&message, &sig)
        .map_err(|_| "signature does not verify".to_string())?;

    Ok(Verified {
        key_label: key.label.clone(),
        credential_id_hex: hex_encode(&key.credential_id),
        sign_count,
        user_present,
        user_verified,
    })
}

/// Message an ES256 authenticator signs for `auth_data` and `challenge`.
/// Exposed for tests and the e2e harness's software authenticator.
#[allow(dead_code)]
pub fn signed_message(auth_data: &[u8], challenge: &[u8]) -> Vec<u8> {
    let mut m = auth_data.to_vec();
    m.extend_from_slice(&Sha256::digest(challenge));
    m
}

fn parse_verifying_key(bytes: &[u8]) -> Result<VerifyingKey, String> {
    if let Ok(vk) = VerifyingKey::from_public_key_der(bytes) {
        return Ok(vk);
    }
    VerifyingKey::from_sec1_bytes(bytes).map_err(|_| {
        "public key is neither SubjectPublicKeyInfo DER nor a SEC1 P-256 point".to_string()
    })
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err("has odd length".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "is not hex".to_string()))
        .collect()
}

#[cfg(test)]
pub(crate) mod testkey {
    //! A software ES256 authenticator for unit and broker tests.
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePublicKey;

    pub struct SoftKey {
        pub sk: SigningKey,
        pub credential_id: Vec<u8>,
    }

    impl SoftKey {
        pub fn new(seed: u8) -> Self {
            let mut bytes = [seed; 32];
            bytes[0] = 0x11; // keep the scalar in range for any seed
            SoftKey {
                sk: SigningKey::from_slice(&bytes).expect("scalar"),
                credential_id: vec![seed; 16],
            }
        }

        pub fn public_key_der(&self) -> Vec<u8> {
            VerifyingKey::from(&self.sk)
                .to_public_key_der()
                .expect("der")
                .as_bytes()
                .to_vec()
        }

        pub fn enrolled(&self, label: &str) -> EnrolledKey {
            EnrolledKey {
                label: label.to_string(),
                credential_id: self.credential_id.clone(),
                public_key: self.public_key_der(),
            }
        }

        /// Produce an assertion like a real authenticator would.
        pub fn assert(&self, rp_id: &str, challenge: &[u8], flags: u8, count: u32) -> Proof {
            let mut auth_data = Sha256::digest(rp_id.as_bytes()).to_vec();
            auth_data.push(flags);
            auth_data.extend_from_slice(&count.to_be_bytes());
            let sig: Signature = self.sk.sign(&signed_message(&auth_data, challenge));
            Proof {
                credential_id: self.credential_id.clone(),
                auth_data,
                signature: sig.to_der().as_bytes().to_vec(),
            }
        }
    }

    pub fn policy(keys: Vec<EnrolledKey>, require_uv: bool) -> SignoffPolicy {
        SignoffPolicy {
            rp_id: "prempti.local".to_string(),
            require_uv,
            keys: KeyStore { keys },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testkey::*;
    use super::*;

    #[test]
    fn hex_round_trip_and_errors() {
        assert_eq!(hex_encode(&[0, 15, 255]), "000fff");
        assert_eq!(hex_decode("000FFF").unwrap(), vec![0, 15, 255]);
        assert!(hex_decode("abc").is_err());
        assert!(hex_decode("zz").is_err());
    }

    #[test]
    fn key_store_parses_and_rejects_bad_keys() {
        let k = SoftKey::new(1);
        let text = serde_json::json!({
            "v": 1,
            "keys": [{
                "label": "yubi",
                "credential_id": hex_encode(&k.credential_id),
                "public_key_der": hex_encode(&k.public_key_der()),
            }]
        })
        .to_string();
        let store = KeyStore::parse(&text).unwrap();
        assert_eq!(store.keys.len(), 1);
        assert_eq!(store.keys[0].label, "yubi");
        assert!(store.find(&k.credential_id).is_some());

        let bad =
            r#"{"v":1,"keys":[{"label":"x","credential_id":"0102","public_key_der":"0102"}]}"#;
        assert!(KeyStore::parse(bad).unwrap_err().contains("public key"));
        assert!(KeyStore::parse(r#"{"v":2,"keys":[]}"#).is_err());
        assert!(KeyStore::parse(r#"{"v":1}"#).is_err());
        assert!(KeyStore::parse(r#"{"v":1,"keys":[]}"#).unwrap().is_empty());
    }

    #[test]
    fn valid_assertion_verifies() {
        let k = SoftKey::new(2);
        let pol = policy(vec![k.enrolled("yubi")], false);
        let challenge = [7u8; 32];
        let proof = k.assert("prempti.local", &challenge, 0x01, 42);
        let v = verify(&pol, &challenge, &proof).unwrap();
        assert_eq!(v.key_label, "yubi");
        assert_eq!(v.sign_count, 42);
        assert!(v.user_present);
        assert!(!v.user_verified);
    }

    #[test]
    fn wrong_challenge_rp_or_key_fails() {
        let k = SoftKey::new(3);
        let other = SoftKey::new(4);
        let pol = policy(vec![k.enrolled("yubi")], false);
        let challenge = [7u8; 32];

        let proof = k.assert("prempti.local", &challenge, 0x01, 1);
        assert!(verify(&pol, &[8u8; 32], &proof)
            .unwrap_err()
            .contains("does not verify"));

        let proof = k.assert("evil.example", &challenge, 0x01, 1);
        assert!(verify(&pol, &challenge, &proof)
            .unwrap_err()
            .contains("rp_id"));

        let proof = other.assert("prempti.local", &challenge, 0x01, 1);
        assert!(verify(&pol, &challenge, &proof)
            .unwrap_err()
            .contains("not enrolled"));

        // Enrolled credential id but signature from another key.
        let mut forged = other.assert("prempti.local", &challenge, 0x01, 1);
        forged.credential_id = k.credential_id.clone();
        assert!(verify(&pol, &challenge, &forged)
            .unwrap_err()
            .contains("does not verify"));
    }

    #[test]
    fn flags_are_enforced() {
        let k = SoftKey::new(5);
        let challenge = [1u8; 32];
        let pol = policy(vec![k.enrolled("yubi")], false);
        let no_up = k.assert("prempti.local", &challenge, 0x00, 1);
        assert!(verify(&pol, &challenge, &no_up)
            .unwrap_err()
            .contains("user-present"));

        let uv_pol = policy(vec![k.enrolled("yubi")], true);
        let up_only = k.assert("prempti.local", &challenge, 0x01, 1);
        assert!(verify(&uv_pol, &challenge, &up_only)
            .unwrap_err()
            .contains("user-verified"));
        let up_uv = k.assert("prempti.local", &challenge, 0x05, 1);
        assert!(verify(&uv_pol, &challenge, &up_uv).unwrap().user_verified);
    }

    #[test]
    fn proof_from_json_requires_hex_fields() {
        let ok = serde_json::json!({"credential_id":"01","auth_data":"02","signature":"03"});
        let p = Proof::from_json(&ok).unwrap();
        assert_eq!(p.credential_id, vec![1]);
        let bad = serde_json::json!({"credential_id":"01","auth_data":"zz","signature":"03"});
        assert!(Proof::from_json(&bad).unwrap_err().contains("auth_data"));
        assert!(Proof::from_json(&serde_json::json!({})).is_err());
    }
}
