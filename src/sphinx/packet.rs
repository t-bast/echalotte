//! Encrypt and decrypt Sphinx packets.

extern crate curve25519_dalek;
extern crate rand;
extern crate zeroize;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use zeroize::Zeroize;

use super::hash;
use super::keys;
use super::mac;
use super::stream;

// TODO: review which functions need to be pub, add documentation
// TODO: rename structs and functions
// TODO: zeroize session_key/eph_secrets

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

#[derive(Clone)]
struct SharedSecretAndKey {
    pub eph_pubkey: RistrettoPoint,
    pub secret: SharedSecret,
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
struct SharedSecret(pub [u8; 32]);

pub struct HopPayload {
    pub hop_pubkey: RistrettoPoint,
    pub payload: Vec<u8>,
}

impl HopPayload {
    pub fn len(&self) -> usize {
        // NB: a mac is always appended to payload data.
        self.payload.len() + mac::MAC_SIZE
    }

    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }
}

fn compute_shared_secrets(session_key: Scalar, payloads: &[HopPayload]) -> Vec<SharedSecretAndKey> {
    let mut eph_secret = session_key;
    let mut blinding_factor = Scalar::one();
    let mut shared_secrets = Vec::new();
    for p in payloads {
        eph_secret = blinding_factor * eph_secret;
        let eph_pubkey = eph_secret * G;
        let shared_secret = SharedSecret(hash::compute(&(eph_secret * p.hop_pubkey).compress().to_bytes()));
        shared_secrets.push(SharedSecretAndKey {
            eph_pubkey,
            secret: shared_secret.clone(),
        });
        blinding_factor = {
            let to_hash = [eph_pubkey.compress().to_bytes(), shared_secret.0].concat();
            Scalar::from_bytes_mod_order(hash::compute(to_hash.as_slice()))
        };
    }
    shared_secrets
}

fn generate_filler(payloads: &[HopPayload], secrets: &[SharedSecret]) -> Vec<u8> {
    assert_eq!(payloads.len(), secrets.len(), "the number of payloads doesn't match the number of secrets");
    let mut filler: Vec<u8> = Vec::new();
    let payloads_and_secrets: Vec<(&HopPayload, &SharedSecret)> = payloads.iter().zip(secrets.iter()).collect();
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

fn encrypt(packet: &mut Packet, hop: &HopPayload, secret_and_key: &SharedSecretAndKey, filler: Option<&[u8]>) {
    // Insert hop payload and previous mac.
    let shift = hop.len();
    for i in (shift..PACKET_PAYLOAD_SIZE).rev() {
        packet.payload[i] = packet.payload[i - shift];
    }
    packet.payload[0..hop.payload.len()].copy_from_slice(hop.payload.as_slice());
    packet.payload[hop.payload.len()..shift].copy_from_slice(&packet.hmac);

    // Encrypt.
    let rho = keys::generate_key(keys::KeyType::Stream, &secret_and_key.secret.0);
    let mut stream = [0u8; PACKET_PAYLOAD_SIZE];
    stream::generate_stream(&rho, &mut stream);
    packet.payload.iter_mut().zip(stream.iter()).for_each(|(x, y)| *x ^= *y);

    // Apply filler if necessary.
    if let Some(filler) = filler {
        packet.payload[PACKET_PAYLOAD_SIZE - filler.len()..].copy_from_slice(filler);
    }

    // Authenticate.
    let mu = keys::generate_key(keys::KeyType::Mac, &secret_and_key.secret.0);
    packet.hmac = mac::compute(&mu, &packet.payload);
    packet.pubkey = secret_and_key.eph_pubkey.compress().to_bytes();
}

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
pub fn create(payloads: &[HopPayload]) -> Packet {
    assert!(!payloads.is_empty(), "non-empty payloads should be provided");
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

    let shared_secrets = compute_shared_secrets(session_key, payloads);
    let secrets_only: Vec<SharedSecret> = shared_secrets.clone().iter().map(|x| x.secret.clone()).collect();
    let filler = generate_filler(
        &payloads[0..payloads.len() - 1],
        &secrets_only.as_slice()[0..payloads.len() - 1],
    );
    for (payload, shared_secret) in payloads.iter().zip(shared_secrets.iter()).rev() {
        // Apply filler only to the recipient's payload.
        let filler_opt: Option<&[u8]> = match p.hmac {
            m if m == [0u8; 32] => Some(&filler),
            _ => None,
        };
        encrypt(&mut p, payload, shared_secret, filler_opt);
    }
    p
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use curve25519_dalek::ristretto::CompressedRistretto;
    use rand::rngs::OsRng;

    use super::*;

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
                payload: vec![1u8; 15],
            },
            HopPayload {
                hop_pubkey: Scalar::random(&mut csprng) * G,
                payload: vec![2u8; 42],
            },
            HopPayload {
                hop_pubkey: Scalar::random(&mut csprng) * G,
                payload: vec![3u8; 561],
            },
        ];
        let shared_secrets = compute_shared_secrets(session_key, &hops);
        let secrets: HashSet<[u8; 32]> = shared_secrets.iter().map(|ss| ss.secret.0).collect();
        let eph_keys: HashSet<[u8; 32]> = shared_secrets
            .iter()
            .map(|ss| ss.eph_pubkey.compress().to_bytes())
            .collect();
        for ss in &shared_secrets {
            println!("{}", hex::encode(&ss.secret.0).as_str());
        }
        assert_eq!(shared_secrets.len(), 3);
        assert_eq!(secrets.len(), 3);
        assert_eq!(eph_keys.len(), 3);
    }

    #[test]
    fn test_generate_filler() {
        let mut csprng = OsRng;
        let hops = vec![
            HopPayload {
                hop_pubkey: Scalar::random(&mut csprng) * G,
                payload: vec![1u8; 16],
            },
            HopPayload {
                hop_pubkey: Scalar::random(&mut csprng) * G,
                payload: vec![2u8; 32],
            },
            HopPayload {
                hop_pubkey: Scalar::random(&mut csprng) * G,
                payload: vec![3u8; 64],
            },
        ];
        let secrets = vec![
            SharedSecret([37u8; 32]),
            SharedSecret([56u8; 32]),
            SharedSecret([112u8; 32]),
        ];
        let filler = generate_filler(&hops, &secrets);
        println!("{}", hex::encode(&filler).as_str());
        assert_eq!(filler.len(), 208, "filler length should cover all payloads and macs");
    }

    #[test]
    fn test_encrypt() {
        let mut csprng = OsRng;
        let mut p = Packet {
            version: 0,
            pubkey: [0; 32],
            payload: [0; PACKET_PAYLOAD_SIZE],
            hmac: [0; 32],
        };
        let hop = HopPayload {
            hop_pubkey: Scalar::random(&mut csprng) * G,
            payload: vec![1u8; 16],
        };
        let secret = SharedSecretAndKey {
            eph_pubkey: G,
            secret: SharedSecret([2u8; 32]),
        };
        encrypt(&mut p, &hop, &secret, None);
        assert_eq!(p.pubkey, secret.eph_pubkey.compress().to_bytes());
        assert_ne!(p.hmac, [0; 32]);
    }

    #[test]
    fn test_create() {
        let mut csprng = OsRng;
        let hops = vec![
            HopPayload {
                hop_pubkey: Scalar::random(&mut csprng) * G,
                payload: vec![1u8; 16],
            },
            HopPayload {
                hop_pubkey: Scalar::random(&mut csprng) * G,
                payload: vec![2u8; 32],
            },
            HopPayload {
                hop_pubkey: Scalar::random(&mut csprng) * G,
                payload: vec![3u8; 64],
            },
        ];
        let p = create(&hops);
        assert_eq!(p.version, 0);
        assert_ne!(p.hmac, vec![0u8; 32].as_slice());
        assert_ne!(p.pubkey, vec![0u8; 32].as_slice());
    }
}
