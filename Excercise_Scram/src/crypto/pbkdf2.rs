use anyhow::{Result, Context};

/// Iterate hash with salt (PBKDF2-like function for SCRAM)
///
/// # Arguments
/// * `password` - The password bytes
/// * `salt` - Salt (16 or 32 bytes typically)
/// * `iterations` - Number of iterations (e.g., 4096, 10000, 100000)
///
/// # Returns
/// The derived key (hash1 ⊕ hash2 ⊕ ... ⊕ hash_n)
pub fn iterate_hash_with_salt(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<[u8; 32]> {
    if iterations == 0 {
        return Err(anyhow::anyhow!("Iterations must be at least 1"));
    }

    // Append 4-byte big-endian 0x00000001 to salt
    let padded_salt = [salt, &[0u8, 0u8, 0u8, 0u8, 1u8]].concat();

    // hash1 = HMAC(password, padded_salt)
    let hash1 = crate::crypto::hmac::compute_hmac_sha256_variable(password, &padded_salt)?;

    // Initialize result with hash1
    let mut result = hash1;
    let mut prev_hash = hash1;

    // Iterate from 2 to num_of_iteration
    for _ in 2..=iterations {
        // hash_i = HMAC(password, hash_{i-1})
        let hash_i = crate::crypto::hmac::compute_hmac_sha256_variable(password, &prev_hash)?;

        // XOR with accumulated result
        for (r, h) in result.iter_mut().zip(hash_i.iter()) {
            *r ^= h;
        }

        prev_hash = hash_i;
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iterate_hash_basic() {
        let password = b"mypassword";
        let salt = b"somesalt";
        let iterations = 4096;

        let result = iterate_hash_with_salt(password, salt, iterations).unwrap();

        // Result should be 32 bytes
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_iterate_hash_deterministic() {
        let password = b"mypassword";
        let salt = b"somesalt";
        let iterations = 1000;

        let result1 = iterate_hash_with_salt(password, salt, iterations).unwrap();
        let result2 = iterate_hash_with_salt(password, salt, iterations).unwrap();

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_different_passwords_different_results() {
        let salt = b"somesalt";
        let iterations = 1000;

        let result1 = iterate_hash_with_salt(b"password1", salt, iterations).unwrap();
        let result2 = iterate_hash_with_salt(b"password2", salt, iterations).unwrap();

        assert_ne!(result1, result2);
    }

    #[test]
    fn test_different_salts_different_results() {
        let password = b"mypassword";
        let iterations = 1000;

        let result1 = iterate_hash_with_salt(password, b"salt1", iterations).unwrap();
        let result2 = iterate_hash_with_salt(password, b"salt2", iterations).unwrap();

        assert_ne!(result1, result2);
    }

    #[test]
    fn test_different_iterations_different_results() {
        let password = b"mypassword";
        let salt = b"somesalt";

        let result1 = iterate_hash_with_salt(password, salt, 1000).unwrap();
        let result2 = iterate_hash_with_salt(password, salt, 2000).unwrap();

        assert_ne!(result1, result2);
    }

    #[test]
    fn test_single_iteration() {
        let password = b"mypassword";
        let salt = b"somesalt";

        // With 1 iteration, result should just be hash1
        let result = iterate_hash_with_salt(password, salt, 1).unwrap();

        // Manually compute hash1
        let padded_salt = [salt.as_ref(), &[0u8, 0u8, 0u8, 0u8, 1u8]].concat();
        let hash1 = crate::crypto::hmac::compute_hmac_sha256_variable(password, &padded_salt).unwrap();

        assert_eq!(result, hash1);
    }

    #[test]
    fn test_zero_iterations_error() {
        let password = b"mypassword";
        let salt = b"somesalt";

        let result = iterate_hash_with_salt(password, salt, 0);
        assert!(result.is_err());
    }
}