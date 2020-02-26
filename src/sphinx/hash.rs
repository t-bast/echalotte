//! Hash function used internally by the Sphinx scheme.

extern crate sha2;
use sha2::{Digest, Sha256};

pub fn compute(message: &[u8]) -> [u8; 32] {
  let mut h = Sha256::new();
  h.input(message);
  let mut res = [0; 32];
  res.copy_from_slice(h.result().as_slice());
  res
}

#[cfg(test)]
mod tests {
  use super::*;
  use hex;

  #[test]
  fn test_hash() {
    let m1 = &hex::decode("deadbeef").unwrap();
    let m2 = &hex::decode("deadbeef42").unwrap();
    let h1 = compute(m1);
    let h11 = compute(m1);
    let h2 = compute(m2);
    assert_eq!(h1, h11);
    assert_ne!(h1, h2);
  }
}
