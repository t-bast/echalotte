//! An implementation of the Sphinx scheme.
//! See https://cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf for reference.

pub mod packet;

#[cfg(test)]
mod tests {
  use super::packet::*;

  #[test]
  fn create_empty_packet() {
    create_packet();
  }
}
