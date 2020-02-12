//! An implementation of the Sphinx scheme.
//! See https://cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf for reference.

mod keys;
mod mac;
pub mod packet;
mod stream;

#[cfg(test)]
mod tests {
  use super::packet::*;

  #[test]
  fn create_empty_packet() {
    let p = create_packet();
    assert_eq!(p.version, 0u8);
  }
}
