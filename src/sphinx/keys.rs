//! Generate keys used internally by the Sphinx scheme.

extern crate hmac;
extern crate sha2;

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub enum KeyType {
    Stream,
    Mac,
}

pub fn generate_key(key_type: KeyType, secret: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let k: &[u8] = match key_type {
        KeyType::Stream => &[0x72, 0x68, 0x6f],
        KeyType::Mac => &[0x6d, 0x75],
    };
    let mut mac = HmacSha256::new_varkey(k).expect("HMAC can take key of any size");
    mac.input(secret);
    result.copy_from_slice(mac.result().code().as_slice());
    result
}

#[cfg(test)]
mod tests {
    use hex;

    use super::*;

    #[test]
    fn test_generate_key() {
        let secret = &hex::decode("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap();
        let k1 = generate_key(KeyType::Mac, secret);
        let k11 = generate_key(KeyType::Mac, secret);
        assert_eq!(k1, k11);
        let k2 = generate_key(KeyType::Stream, secret);
        assert_ne!(k1, k2);
    }
}
