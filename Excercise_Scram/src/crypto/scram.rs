use sha2::{Sha256, Digest};
use super::hmac;

/// Compute Auth_msg for SCRAM
/// Auth_msg = [ClientName] || ch₁ || ch₂ || r || n || TLS_INFO
pub fn compute_auth_msg(
    client_name: &str,
    ch1: &[u8],
    ch2: &[u8],
    r: &[u8],
    n: u32,
    tls_info: &[u8],
) -> Vec<u8> {
    [
        client_name.as_bytes(),
        b"||",
        ch1,
        b"||",
        ch2,
        b"||",
        r,
        b"||",
        &n.to_be_bytes(),
        b"||",
        tls_info,
    ].concat()
}

/// Compute Client_proof for SCRAM
/// Client_proof = HMAC(H^n(r, pw), Auth_msg)
///
/// # Arguments
/// * `password_hash` - H^n(r, pw) from the password file
/// * `auth_msg` - The authentication message
pub fn compute_client_proof(
    password_hash: &[u8; 32],
    auth_msg: &[u8],
) -> [u8; 32] {
    hmac::compute_hmac_sha256(password_hash, auth_msg)
}

/// Verify Client_proof on the server side
///
/// # Arguments
/// * `password_hash` - H^n(r, pw) from the password file
/// * `auth_msg` - The authentication message
/// * `received_proof` - The Client_proof received from client
pub fn verify_client_proof(
    password_hash: &[u8; 32],
    auth_msg: &[u8],
    received_proof: &[u8; 32],
) -> bool {
    let expected_proof = compute_client_proof(password_hash, auth_msg);
    // Constant-time comparison
    constant_time_eq(&expected_proof, received_proof)
}

/// Compute Server_sign for SCRAM
/// Server_sign = HMAC(H^n(r, pw), Auth_msg)
///
/// Note: In this SCRAM variant, Server_sign uses the same computation as Client_proof
/// but is computed by the server to prove it knows the password hash
pub fn compute_server_sign(
    password_hash: &[u8; 32],
    auth_msg: &[u8],
) -> [u8; 32] {
    hmac::compute_hmac_sha256(password_hash, auth_msg)
}

/// Verify Server_sign on the client side
///
/// # Arguments
/// * `password_hash` - H^n(r, pw) computed by client
/// * `auth_msg` - The authentication message
/// * `received_sign` - The Server_sign received from server
pub fn verify_server_sign(
    password_hash: &[u8; 32],
    auth_msg: &[u8],
    received_sign: &[u8; 32],
) -> bool {
    let expected_sign = compute_server_sign(password_hash, auth_msg);
    constant_time_eq(&expected_sign, received_sign)
}

/// Constant-time equality check to prevent timing attacks
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Hash a value using SHA-256 (helper function)
pub fn hash_value(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_auth_msg() {
        let client_name = "Alice";
        let ch1 = b"client_challenge";
        let ch2 = b"server_challenge";
        let r = b"salt123";
        let n = 10000u32;
        let tls_info = b"tls_channel_binding";

        let auth_msg = compute_auth_msg(client_name, ch1, ch2, r, n, tls_info);

        // Should contain all components
        assert!(auth_msg.len() > 0);

        // Should be deterministic
        let auth_msg2 = compute_auth_msg(client_name, ch1, ch2, r, n, tls_info);
        assert_eq!(auth_msg, auth_msg2);
    }

    #[test]
    fn test_client_proof_deterministic() {
        let password_hash = [1u8; 32];
        let auth_msg = b"test_auth_message";

        let proof1 = compute_client_proof(&password_hash, auth_msg);
        let proof2 = compute_client_proof(&password_hash, auth_msg);

        assert_eq!(proof1, proof2);
    }

    #[test]
    fn test_verify_client_proof_valid() {
        let password_hash = [1u8; 32];
        let auth_msg = b"test_auth_message";

        let proof = compute_client_proof(&password_hash, auth_msg);

        assert!(verify_client_proof(&password_hash, auth_msg, &proof));
    }

    #[test]
    fn test_verify_client_proof_invalid() {
        let password_hash = [1u8; 32];
        let auth_msg = b"test_auth_message";

        let proof = compute_client_proof(&password_hash, auth_msg);
        let wrong_proof = [0u8; 32];

        assert!(!verify_client_proof(&password_hash, auth_msg, &wrong_proof));
    }

    #[test]
    fn test_server_sign_matches_client_proof() {
        // In this SCRAM variant, they use the same computation
        let password_hash = [1u8; 32];
        let auth_msg = b"test_auth_message";

        let client_proof = compute_client_proof(&password_hash, auth_msg);
        let server_sign = compute_server_sign(&password_hash, auth_msg);

        assert_eq!(client_proof, server_sign);
    }

    #[test]
    fn test_verify_server_sign_valid() {
        let password_hash = [1u8; 32];
        let auth_msg = b"test_auth_message";

        let sign = compute_server_sign(&password_hash, auth_msg);

        assert!(verify_server_sign(&password_hash, auth_msg, &sign));
    }

    #[test]
    fn test_verify_server_sign_invalid() {
        let password_hash = [1u8; 32];
        let auth_msg = b"test_auth_message";

        let sign = compute_server_sign(&password_hash, auth_msg);
        let wrong_sign = [0u8; 32];

        assert!(!verify_server_sign(&password_hash, auth_msg, &wrong_sign));
    }

    #[test]
    fn test_constant_time_eq_equal() {
        let a = [42u8; 32];
        let b = [42u8; 32];

        assert!(constant_time_eq(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_not_equal() {
        let a = [42u8; 32];
        let b = [43u8; 32];

        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn test_hash_value_deterministic() {
        let data = b"test data";

        let hash1 = hash_value(data);
        let hash2 = hash_value(data);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }
}