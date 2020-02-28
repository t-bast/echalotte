//! MACs used internally by the Sphinx scheme.

extern crate hmac;
extern crate sha2;

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub const MAC_SIZE: usize = 32;

pub fn compute(key: &[u8], message: &[u8]) -> [u8; MAC_SIZE] {
    let mut res = [0; MAC_SIZE];
    let mut mac = HmacSha256::new_varkey(key).expect("HMAC can take key of any size");
    mac.input(message);
    let result = mac.result();
    res.copy_from_slice(result.code().as_slice());
    res
}
