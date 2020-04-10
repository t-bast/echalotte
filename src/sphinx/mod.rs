//! An implementation of the Sphinx scheme.
//! See https://cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf for reference.

mod hash;
mod keys;
mod mac;
pub mod packet;
mod stream;

#[cfg(test)]
mod tests {
    use super::packet::*;

    #[test]
    fn encrypt_and_decrypt_packet() {
        let private_keys = vec![
            "6bbadf5f42cdfc539596d591d2534615304cb650893e27665bb0d001c3a65b0b",
            "5b9c310d55180fd1f7caa4205ee931cdddda385f64422ed007676fea98114f09",
            "0b4fbcb5e042577f8facaddd362f5da99cf67747e42ab47a7aa3f108198fbe06",
        ];
        let public_keys = vec![
            "749aa7ed60b246fe1060d4d60d4afc96a7839ad7a7b6050a3b4fc3ee5b2e154a",
            "b039559cb7f499283fc42cecfd74640a17d53d5c1d355199838d3fa30616324e",
            "5420c0cc481a2841a56d49f9c613eefa08d9dd0d6025e3ab86530f8487337443",
        ];
        let payloads = vec![
            "01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101",
            "02020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202",
            "03030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303",
        ];
        let hops: Vec<Hop> = (0..3)
            .map(|i| {
                let mut hop = Hop {
                    pubkey: [0u8; 32],
                    payload: [0u8; HOP_PAYLOAD_SIZE],
                };
                hop.pubkey
                    .copy_from_slice(hex::decode(public_keys[i]).unwrap().as_slice());
                hop.payload
                    .copy_from_slice(hex::decode(payloads[i]).unwrap().as_slice());
                hop
            })
            .collect();
        let mut p = Packet::new(&hops);
        assert_eq!(p.version, 0);
        for i in 0..3 {
            let mut private_key = [0u8; 32];
            private_key.copy_from_slice(hex::decode(private_keys[i]).unwrap().as_slice());
            let hop_payload = p.decrypt(&private_key);
            assert_eq!(hop_payload.to_vec(), hops[i].payload.to_vec());
        }
    }
}
