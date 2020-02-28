//! Encrypt and decrypt Sphinx packets.

extern crate curve25519_dalek;
extern crate rand;
extern crate zeroize;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use zeroize::Zeroize;

use super::hash;
use super::keys;
use super::mac;
use super::stream;

// TODO: zeroize session_key/eph_secrets/all secret data

/// Sphinx payloads are constant-size to avoid leaking information.
const PACKET_PAYLOAD_SIZE: usize = 1300;

/// A Sphinx packet. The payload is onion-encoded but doesn't leak any information about the number
/// of hops used.
pub struct Packet {
    pub version: u8,
    pub pubkey: [u8; 32],
    pub payload: [u8; PACKET_PAYLOAD_SIZE],
    pub hmac: [u8; mac::MAC_SIZE],
}

/// A hop in the onion route.
pub struct Hop {
    pub pubkey: [u8; 32],
    pub payload: Vec<u8>,
}

impl Hop {
    pub fn len(&self) -> usize {
        // NB: a mac is always appended to payload data.
        self.payload.len() + mac::MAC_SIZE
    }

    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
struct SharedSecret(pub [u8; 32]);

impl Packet {
    /// Returns an onion-encrypted Sphinx packet.
    ///
    /// # Arguments
    ///
    /// * `payloads` - payloads for each hop along the onion route.
    ///
    /// # Example
    ///
    /// ```
    /// // TODO: provide a running example here.
    /// ```
    pub fn new(hops: &[Hop]) -> Packet {
        assert!(!hops.is_empty(), "you need to provide at least one hop");
        let mut csprng = OsRng;
        let session_key = Scalar::random(&mut csprng);
        let mut p = Packet {
            version: 0,
            pubkey: [0u8; 32],
            payload: [0u8; PACKET_PAYLOAD_SIZE],
            hmac: [0u8; 32],
        };
        // Initialize payload with random bytes.
        stream::generate_stream(&keys::generate_key(keys::KeyType::Stream, session_key.as_bytes()), &mut p.payload);

        let (shared_points, shared_secrets) = compute_shared_secrets(session_key, hops);
        let filler = generate_filler(
            &hops[0..hops.len() - 1],
            &shared_secrets[0..hops.len() - 1],
        );
        for i in (0..hops.len()).rev() {
            // Apply filler only to the recipient's payload.
            let filler_opt: Option<&[u8]> = match i {
                i if i == hops.len() - 1 => Some(&filler),
                _ => None
            };
            p.encrypt(&hops[i], &shared_secrets[i], shared_points[i], filler_opt);
        }
        p
    }

    /// Add one layer of onion encryption.
    fn encrypt(&mut self, hop: &Hop, shared_secret: &SharedSecret, shared_point: RistrettoPoint, filler: Option<&[u8]>) {
        // Insert hop payload and previous mac.
        let shift = hop.len();
        for i in (shift..PACKET_PAYLOAD_SIZE).rev() {
            self.payload[i] = self.payload[i - shift];
        }
        self.payload[0..hop.payload.len()].copy_from_slice(hop.payload.as_slice());
        self.payload[hop.payload.len()..shift].copy_from_slice(&self.hmac);

        // Encrypt.
        let rho = keys::generate_key(keys::KeyType::Stream, &shared_secret.0);
        let mut stream = [0u8; PACKET_PAYLOAD_SIZE];
        stream::generate_stream(&rho, &mut stream);
        self.payload.iter_mut().zip(stream.iter()).for_each(|(x, y)| *x ^= *y);

        // Apply filler if necessary.
        if let Some(filler) = filler {
            self.payload[PACKET_PAYLOAD_SIZE - filler.len()..].copy_from_slice(filler);
        }

        // Authenticate.
        let mu = keys::generate_key(keys::KeyType::Mac, &shared_secret.0);
        self.hmac = mac::compute(&mu, &self.payload);
        self.pubkey = shared_point.compress().to_bytes();
    }
}

fn compute_shared_secrets(session_key: Scalar, hops: &[Hop]) -> (Vec<RistrettoPoint>, Vec<SharedSecret>) {
    let mut eph_secret = session_key;
    let mut blinding_factor = Scalar::one();
    let mut shared_secrets: Vec<SharedSecret> = Vec::new();
    let mut shared_points: Vec<RistrettoPoint> = Vec::new();
    for hop in hops {
        eph_secret = blinding_factor * eph_secret;
        // TODO: better handling of invalid public keys.
        let hop_pubkey: RistrettoPoint = CompressedRistretto::from_slice(&hop.pubkey).decompress().expect("invalid hop public key provided");
        let eph_pubkey = eph_secret * G;
        let shared_secret = SharedSecret(hash::compute(&(eph_secret * hop_pubkey).compress().to_bytes()));
        shared_secrets.push(shared_secret.clone());
        shared_points.push(eph_pubkey);
        blinding_factor = {
            let to_hash = [eph_pubkey.compress().to_bytes(), shared_secret.0].concat();
            Scalar::from_bytes_mod_order(hash::compute(to_hash.as_slice()))
        };
    }
    (shared_points, shared_secrets)
}

fn generate_filler(payloads: &[Hop], secrets: &[SharedSecret]) -> Vec<u8> {
    assert_eq!(payloads.len(), secrets.len(), "the number of payloads doesn't match the number of secrets");
    let mut filler: Vec<u8> = Vec::new();
    let payloads_and_secrets: Vec<(&Hop, &SharedSecret)> = payloads.iter().zip(secrets.iter()).collect();
    for (p, secret) in payloads_and_secrets {
        let rho = keys::generate_key(keys::KeyType::Stream, &secret.0);
        let mut stream = vec![0u8; PACKET_PAYLOAD_SIZE + p.len()];
        stream::generate_stream(&rho, &mut stream);
        filler.append(&mut vec![0u8; p.len()]);
        let to_skip = stream.len() - filler.len();
        filler.iter_mut().zip(stream.iter().skip(to_skip)).for_each(|(x, y)| *x ^= *y);
    }
    filler
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use rand::rngs::OsRng;

    use super::*;

    /// Create a hop from valid hex strings.
    fn create_hop(pubkey: &str, payload: &str) -> Hop {
        let mut hop = Hop {
            pubkey: [0u8; 32],
            payload: hex::decode(payload).unwrap(),
        };
        hop.pubkey.copy_from_slice(hex::decode(pubkey).unwrap().as_slice());
        hop
    }

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
        println!("{}", hex::encode(&c1).as_str());
        println!("{}", hex::encode(&c2).as_str());
        assert_ne!(c1, c2);

        match CompressedRistretto::from_slice(&c1).decompress() {
            Some(ee1) => assert_eq!(e1, ee1),
            None => assert!(false, "w00t? decompress failed..."),
        };
    }

    #[test]
    fn test_compute_shared_secrets() {
        let mut csprng = OsRng;
        let session_key = Scalar::random(&mut csprng);
        let hops = vec![
            create_hop("16e6ca634d2a9fc9fa0b2f1a2d2f6b718b1a54af464e6e47d2d608419c9b773e", "010101010101010101010101010101"),
            create_hop("58122677032dfbad9c8b51f5514f71ab1089c8d5a9bea2e39adc0a17c17b1e26", "0202020202020202020202020202020202020202"),
            create_hop("f2548a3b8812a4eb175c255a2e20c850b32a5658abfce0d78652f32e3f48676d", "0303030303"),
        ];
        let (shared_points, shared_secrets) = compute_shared_secrets(session_key, &hops);
        let secrets: HashSet<[u8; 32]> = shared_secrets.iter().map(|ss| ss.0).collect();
        let eph_keys: HashSet<[u8; 32]> = shared_points.iter().map(|sp| sp.compress().to_bytes()).collect();
        assert_eq!(shared_secrets.len(), 3);
        assert_eq!(secrets.len(), 3);
        assert_eq!(eph_keys.len(), 3);
    }

    #[test]
    fn test_generate_filler() {
        let hops = vec![
            create_hop("16e6ca634d2a9fc9fa0b2f1a2d2f6b718b1a54af464e6e47d2d608419c9b773e", "010101010101010101010101010101"),
            create_hop("58122677032dfbad9c8b51f5514f71ab1089c8d5a9bea2e39adc0a17c17b1e26", "0202020202020202020202020202020202020202"),
            create_hop("f2548a3b8812a4eb175c255a2e20c850b32a5658abfce0d78652f32e3f48676d", "0303030303"),
        ];
        let secrets = vec![
            SharedSecret([37u8; 32]),
            SharedSecret([56u8; 32]),
            SharedSecret([112u8; 32]),
        ];
        let filler = generate_filler(&hops, &secrets);
        assert_eq!(filler.len(), 136, "filler length should cover all payloads and macs");
    }

    #[test]
    fn test_encrypt() {
        let mut p = Packet {
            version: 0,
            pubkey: [0; 32],
            payload: [0; PACKET_PAYLOAD_SIZE],
            hmac: [0; 32],
        };
        let hop = create_hop("16e6ca634d2a9fc9fa0b2f1a2d2f6b718b1a54af464e6e47d2d608419c9b773e", "010101010101010101010101010101");
        p.encrypt(&hop, &SharedSecret([2u8; 32]), G, None);
        assert_eq!(p.pubkey, G.compress().to_bytes());
        assert_ne!(p.hmac, [0; 32]);
    }

    #[test]
    fn test_create() {
        let hops = vec![
            create_hop("16e6ca634d2a9fc9fa0b2f1a2d2f6b718b1a54af464e6e47d2d608419c9b773e", "010101010101010101010101010101"),
            create_hop("58122677032dfbad9c8b51f5514f71ab1089c8d5a9bea2e39adc0a17c17b1e26", "0202020202020202020202020202020202020202"),
            create_hop("f2548a3b8812a4eb175c255a2e20c850b32a5658abfce0d78652f32e3f48676d", "0303030303"),
        ];
        let p = Packet::new(&hops);
        assert_eq!(p.version, 0);
        assert_ne!(p.hmac, vec![0u8; 32].as_slice());
        assert_ne!(p.pubkey, vec![0u8; 32].as_slice());
    }
}
