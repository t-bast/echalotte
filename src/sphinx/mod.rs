//! An implementation of the Sphinx scheme.
//! See https://cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf for reference.

mod hash;
mod keys;
mod mac;
pub mod packet;
mod stream;

#[cfg(test)]
mod tests {
    // use super::packet::*;

    #[test]
    fn encrypt_and_decrypt_packet() {
        // TODO: here we should test packet creation/decryption (viewed as a consumer of the module)
    }
}
