//! Encrypt and decrypt Sphinx packets.

use super::keys;
use super::stream;

/// Sphinx payloads are constant-size to avoid leaking information.
const PACKET_PAYLOAD_SIZE: usize = 1300;

/// A Sphinx packet. The payload is onion-encoded but doesn't leak any information about the number
/// of layers used.
pub struct Packet {
  pub version: u8,
  pub pubkey: [u8; 32],
  pub payload: Vec<u8>, // TODO: enforce size PACKET_PAYLOAD_SIZE?
  pub hmac: [u8; 32],
}

pub fn create_packet() -> Packet {
  let session_key = vec![0; 32];
  let stream_key = keys::generate_key(keys::KeyType::Stream, &session_key);
  let start_bytes = stream::generate_stream(&stream_key, PACKET_PAYLOAD_SIZE);
  Packet {
    version: 0,
    pubkey: [0; 32],
    payload: start_bytes,
    hmac: [0; 32],
  }
}
