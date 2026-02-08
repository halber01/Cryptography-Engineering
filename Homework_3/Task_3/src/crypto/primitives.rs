//! Low-level cryptographic primitives

use elliptic_curve::{
    CurveArithmetic,
    ProjectivePoint,
    group::GroupEncoding,
};
use sha3::{Sha3_256, Sha3_512, Digest};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use crate::types::OpaqueError;

type HmacSha256 = Hmac<Sha3_256>;

/// Generate random bytes for a scalar
pub fn random_scalar_bytes(size: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut bytes = vec![0u8; size];
    rand::rng().fill_bytes(&mut bytes);  // Fixed: thread_rng -> rng
    bytes
}

/// SHA3-256 hash function
pub fn sha3_256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// SHA3-512 hash function
pub fn sha3_512(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_512::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// HKDF key derivation
pub fn hkdf_expand(input_key_material: &[u8], info: &[u8], output_len: usize)
                   -> Result<Vec<u8>, OpaqueError>
{
    let hk = Hkdf::<Sha3_256>::new(None, input_key_material);
    let mut output = vec![0u8; output_len];
    hk.expand(info, &mut output)
        .map_err(|e| OpaqueError::CryptoError(format!("HKDF error: {}", e)))?;
    Ok(output)
}

/// HKDF that returns two keys (for key confirmation)
pub fn hkdf_expand_two_keys(input_key_material: &[u8], info: &[u8])
                            -> Result<(Vec<u8>, Vec<u8>), OpaqueError>
{
    let combined = hkdf_expand(input_key_material, info, 64)?;
    let k1 = combined[..32].to_vec();
    let k2 = combined[32..].to_vec();
    Ok((k1, k2))
}

/// AEAD encryption using ChaCha20-Poly1305
pub fn aead_encrypt(key: &[u8], plaintext: &[u8])
                    -> Result<(Vec<u8>, Vec<u8>), OpaqueError>
{
    if key.len() != 32 {
        return Err(OpaqueError::CryptoError("Key must be 32 bytes".to_string()));
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| OpaqueError::CryptoError(format!("Cipher init error: {}", e)))?;

    let nonce_bytes = rand::random::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| OpaqueError::CryptoError(format!("Encryption error: {}", e)))?;

    Ok((ciphertext, nonce_bytes.to_vec()))
}

/// AEAD decryption using ChaCha20-Poly1305
pub fn aead_decrypt(key: &[u8], ciphertext: &[u8], nonce: &[u8])
                    -> Result<Vec<u8>, OpaqueError>
{
    if key.len() != 32 {
        return Err(OpaqueError::CryptoError("Key must be 32 bytes".to_string()));
    }

    if nonce.len() != 12 {
        return Err(OpaqueError::CryptoError("Nonce must be 12 bytes".to_string()));
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| OpaqueError::CryptoError(format!("Cipher init error: {}", e)))?;

    let nonce = Nonce::from_slice(nonce);

    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| OpaqueError::DecryptionFailed)?;

    Ok(plaintext)
}

/// HMAC computation
pub fn hmac_compute(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// Verify HMAC
pub fn hmac_verify(key: &[u8], message: &[u8], expected_mac: &[u8]) -> bool {
    let computed_mac = hmac_compute(key, message);

    // Constant-time comparison
    if computed_mac.len() != expected_mac.len() {
        return false;
    }

    computed_mac.iter()
        .zip(expected_mac.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

/// Serialize a point to bytes (compressed)
pub fn point_to_bytes<C>(point: &ProjectivePoint<C>) -> Vec<u8>
where
    C: CurveArithmetic,
    ProjectivePoint<C>: GroupEncoding,
{
    point.to_bytes().as_ref().to_vec()
}

/// Deserialize bytes to a point
pub fn bytes_to_point<C>(bytes: &[u8]) -> Result<ProjectivePoint<C>, OpaqueError>
where
    C: CurveArithmetic,
    ProjectivePoint<C>: GroupEncoding,
{
    // Create a fixed-size array from the slice
    let mut repr_bytes = <ProjectivePoint<C> as GroupEncoding>::Repr::default();

    if bytes.len() != repr_bytes.as_ref().len() {
        return Err(OpaqueError::CryptoError(
            format!("Invalid point bytes length: expected {}, got {}",
                    repr_bytes.as_ref().len(), bytes.len())
        ));
    }

    repr_bytes.as_mut().copy_from_slice(bytes);

    Option::<ProjectivePoint<C>>::from(ProjectivePoint::<C>::from_bytes(&repr_bytes))
        .ok_or_else(|| OpaqueError::CryptoError("Invalid point encoding".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_roundtrip() {
        let key = random_scalar_bytes(32);
        let plaintext = b"Hello, OPAQUE!";

        let (ciphertext, nonce) = aead_encrypt(&key, plaintext).unwrap();
        let decrypted = aead_decrypt(&key, &ciphertext, &nonce).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_hmac() {
        let key = b"secret key";
        let message = b"test message";
        let mac = hmac_compute(key, message);

        assert!(hmac_verify(key, message, &mac));
        assert!(!hmac_verify(key, b"wrong message", &mac));
    }

    #[test]
    fn test_hkdf() {
        let ikm = b"input key material";
        let info = b"application info";
        let output = hkdf_expand(ikm, info, 32).unwrap();
        assert_eq!(output.len(), 32);
    }
}