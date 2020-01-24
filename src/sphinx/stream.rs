//! Generate pseudo-random streams used internally by the Sphinx scheme.

extern crate chacha20;

use chacha20::stream_cipher::generic_array::GenericArray;
use chacha20::stream_cipher::{NewStreamCipher, StreamCipher};
use chacha20::ChaCha20;

// Generate a pseudo-random stream of the given length.
pub fn generate_stream(key: &[u8], length: usize) -> Vec<u8> {
  let nonce = GenericArray::from_slice(&[0u8; 12]);
  let mut cipher = ChaCha20::new(&GenericArray::from_slice(key), &nonce);
  let mut ciphertext = vec![0; length];
  cipher.encrypt(&mut ciphertext);
  ciphertext
}

#[cfg(test)]
mod tests {
  use super::*;
  use hex;

  #[test]
  fn test_generate_stream() {
    let key =
      &hex::decode("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap();
    let s = generate_stream(key, 20);
    assert_ne!(s, vec![0; 20]);
  }
}
