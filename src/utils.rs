use rand::RngCore;
use sha3::{Digest, Sha3_256};
use tor_llcrypto::pk::ed25519::ExpandedKeypair;

pub(crate) fn keypair_from_sk(secret_key: [u8; 32]) -> ExpandedKeypair {
    let sk = secret_key as ed25519_dalek::SecretKey;
    let esk = ed25519_dalek::hazmat::ExpandedSecretKey::from(&sk);
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&esk.scalar.to_bytes());
    bytes[32..].copy_from_slice(&esk.hash_prefix);
    ExpandedKeypair::from_secret_key_bytes(bytes).expect("error converting to ExpandedKeypair")
}

/// Generates a random 32-byte secret key using a cryptographically secure random number generator.
///
/// # Returns
///
/// A `[u8; 32]` array containing the generated secret key.
///
/// # Examples
///
/// ```
/// let key = generate_key();
/// assert_eq!(key.len(), 32);
/// ```
///
/// # Notes
///
/// The `#[must_use]` attribute ensures that the returned key is not ignored.
#[must_use]
pub fn generate_key() -> [u8; 32] {
    let mut rng = rand::rng();
    let mut sk = [0u8; 32];
    rng.fill_bytes(&mut sk);
    sk
}
#[must_use]
pub fn get_onion_address(public_key: &[u8]) -> String {
    let pub_key = <[u8; 32]>::try_from(public_key).expect("could not convert to [u8; 32]");
    let mut buf = [0u8; 35];
    pub_key.iter().copied().enumerate().for_each(|(i, b)| {
        buf[i] = b;
    });

    let mut h = Sha3_256::new();
    h.update(b".onion checksum");
    h.update(pub_key);
    h.update(b"\x03");

    let res_vec = h.finalize().to_vec();
    buf[32] = res_vec[0];
    buf[33] = res_vec[1];
    buf[34] = 3;

    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &buf).to_ascii_lowercase()
}
