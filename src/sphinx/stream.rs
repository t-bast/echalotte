//! Generate pseudo-random streams used internally by the Sphinx scheme.

extern crate chacha20;

use chacha20::ChaCha20;
use chacha20::stream_cipher::{NewStreamCipher, StreamCipher};
use chacha20::stream_cipher::generic_array::GenericArray;

// Fill the given array with a pseudo-random stream.
pub fn generate_stream(key: &[u8], stream: &mut [u8]) {
    let nonce = GenericArray::from_slice(&[0u8; 12]);
    let mut cipher = ChaCha20::new(&GenericArray::from_slice(key), &nonce);
    cipher.encrypt(stream)
}

#[cfg(test)]
mod tests {
    use hex;

    use super::*;

    #[test]
    fn test_generate_stream() {
        let key = &hex::decode("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap();
        let mut stream = [0; 400];
        generate_stream(key, &mut stream);
        assert_ne!(stream.to_vec(), vec![0; 400]);
    }
}
