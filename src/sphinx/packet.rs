//! Encrypt and decrypt Sphinx packets.

/// Sphinx payloads are constant-size to avoid leaking information.
const PACKET_PAYLOAD_SIZE: usize = 1300;

/// A Sphinx packet. The payload is onion-encoded but doesn't leak any information about the number
/// of layers used.
pub struct Packet {
  version: u8,
  pubkey: [u8; 32],
  payload: [u8; PACKET_PAYLOAD_SIZE],
  hmac: [u8; 32],
}

pub fn create_packet() -> Packet {
  Packet {
    version: 0,
    pubkey: [0; 32],
    payload: [0; PACKET_PAYLOAD_SIZE],
    hmac: [0; 32],
  }
}
