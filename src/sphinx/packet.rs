//! Encrypt and decrypt Sphinx packets.

extern crate curve25519_dalek;
extern crate zeroize;

use super::hash;
use super::keys;
use super::mac;
use super::stream;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use zeroize::Zeroize;

/// Sphinx payloads are constant-size to avoid leaking information.
const PACKET_PAYLOAD_SIZE: usize = 1300;

/// A Sphinx packet. The payload is onion-encoded but doesn't leak any information about the number
/// of hops used.
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

#[derive(Clone)]
pub struct SharedSecretAndKey {
  pub eph_pubkey: RistrettoPoint,
  pub secret: SharedSecret,
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SharedSecret(pub [u8; 32]);

pub struct HopPayload {
  pub hop_pubkey: RistrettoPoint,
  pub payload: Vec<u8>,
}

pub fn compute_shared_secrets(
  session_key: Scalar,
  payloads: Vec<HopPayload>,
) -> Vec<SharedSecretAndKey> {
  let mut eph_secret = session_key;
  let mut blinding_factor = Scalar::one();
  let mut shared_secrets = Vec::new();
  for p in &payloads {
    eph_secret = blinding_factor * eph_secret;
    let eph_pubkey = eph_secret * G;
    let shared_secret = SharedSecret(hash::compute(
      &(eph_secret * p.hop_pubkey).compress().to_bytes(),
    ));
    shared_secrets.push(SharedSecretAndKey {
      eph_pubkey: eph_pubkey,
      secret: shared_secret.clone(),
    });
    blinding_factor = {
      let to_hash = [eph_pubkey.compress().to_bytes(), shared_secret.0].concat();
      Scalar::from_bytes_mod_order(hash::compute(to_hash.as_slice()))
    };
  }
  shared_secrets
}

#[cfg(test)]
mod tests {
  extern crate curve25519_dalek;

  use super::*;

  use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
  use curve25519_dalek::ristretto::CompressedRistretto;
  use curve25519_dalek::scalar::Scalar;
  use rand::rngs::OsRng;
  use std::collections::HashSet;

  #[test]
  fn test_curve25519() {
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
      Some(ee1) => assert_eq!(e1, ee1),
      None => {
        println!("w00t? decompress failed...");
        assert!(false);
      }
    };
  }

  #[test]
  fn test_compute_shared_secrets() {
    let mut csprng = OsRng;
    let session_key = Scalar::random(&mut csprng);
    let hops = vec![
      HopPayload {
        hop_pubkey: Scalar::random(&mut csprng) * G,
        payload: vec![1u8, 2u8],
      },
      HopPayload {
        hop_pubkey: Scalar::random(&mut csprng) * G,
        payload: vec![3u8, 4u8, 5u8],
      },
      HopPayload {
        hop_pubkey: Scalar::random(&mut csprng) * G,
        payload: vec![6u8],
      },
    ];
    let shared_secrets = compute_shared_secrets(session_key, hops);
    let secrets: HashSet<[u8; 32]> = shared_secrets.iter().map(|ss| ss.secret.0).collect();
    let eph_keys: HashSet<[u8; 32]> = shared_secrets
      .iter()
      .map(|ss| ss.eph_pubkey.compress().to_bytes())
      .collect();
    for ss in &shared_secrets {
      println!("{}", hex::encode(ss.secret.0).as_str());
    }
    assert_eq!(shared_secrets.len(), 3);
    assert_eq!(secrets.len(), 3);
    assert_eq!(eph_keys.len(), 3);
  }
}
