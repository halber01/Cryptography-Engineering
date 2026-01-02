use sha2::Sha256;
use hmac::{Hmac, Mac};
use hex_literal::hex;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

pub fn compute_hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(message);
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    let mut hmac_result = [0u8; 32];
    hmac_result.copy_from_slice(&code_bytes);
    hmac_result
}

pub fn verify_hmac_sha256(key: &[u8], message: &[u8], expected_hmac: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(message);
    mac.verify_slice(expected_hmac).is_ok()
}