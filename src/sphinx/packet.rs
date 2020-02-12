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
