//! Encrypt and decrypt Sphinx packets.

use super::keys;
use super::mac;
use super::stream;

/// Sphinx payloads are constant-size to avoid leaking information.
const PACKET_PAYLOAD_SIZE: usize = 1300;

/// A Sphinx packet. The payload is onion-encoded but doesn't leak any information about the number
/// of layers used.
pub struct Packet {
  pub version: u8,
  pub pubkey: [u8; 32],
  pub payload: [u8; PACKET_PAYLOAD_SIZE],
  pub hmac: [u8; 32],
}

pub fn create_packet() -> Packet {
  let session_key = vec![0; 32];
  let stream_key = keys::generate_key(keys::KeyType::Stream, &session_key);
  let mut start_bytes = [0u8; PACKET_PAYLOAD_SIZE];
  stream::generate_stream(&stream_key, &mut start_bytes);
  let mac_key = keys::generate_key(keys::KeyType::Mac, &session_key);
  let mac = mac::compute(&mac_key, &start_bytes);
  Packet {
    version: 0,
    pubkey: [0; 32],
    payload: start_bytes,
    hmac: mac,
  }
}

#[cfg(test)]
mod tests {
  extern crate curve25519_dalek;

  use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
  use curve25519_dalek::ristretto::CompressedRistretto;
  use curve25519_dalek::scalar::Scalar;
  use rand::rngs::OsRng;

  // TODO: zeroize secret stuff (see https://github.com/dalek-cryptography/x25519-dalek/blob/master/src/x25519.rs)

  #[test]
  fn test_generate_shared_secrets() {
    let mut csprng = OsRng;
    let k1 = Scalar::random(&mut csprng);
    let k2 = Scalar::random(&mut csprng);
    assert_ne!(k1, k2);

    let e1 = k1 * G;
    let e2 = k2 * G;
    assert_ne!(e1, e2);
    assert_eq!(k2 * e1, k1 * e2);

    let c1 = e1.compress().to_bytes();
    let c2 = e2.compress().to_bytes();
    println!("{}", hex::encode(c1).as_str());
    println!("{}", hex::encode(c2).as_str());
    assert_ne!(c1, c2);

    match CompressedRistretto::from_slice(&c1).decompress() {
      None => {
        println!("w00t? decompress failed...");
        assert!(false);
      },
      Some(ee1) => assert_eq!(e1, ee1),
    };
  }
}
