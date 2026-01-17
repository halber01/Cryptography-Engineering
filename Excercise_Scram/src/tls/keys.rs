use sha2::{Sha256, Digest};
use hkdf::Hkdf;

/// Both client and server derive identical keys
#[derive(Debug, Clone, PartialEq)]
pub struct TlsKeys {
    /// Stage 1 keys
    pub k1_c: [u8; 32],
    pub k1_s: [u8; 32],

    /// Stage 2 keys
    pub k2_c: [u8; 32],
    pub k2_s: [u8; 32],

    /// Stage 3 keys (final application keys)
    pub k3_c: [u8; 32],
    pub k3_s: [u8; 32],
}

/// Hash a value using SHA-256
pub fn hash_value(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Derive the handshake secret (HS) from shared secret
/// This follows the HKDF-Extract → HKDF-Expand → HKDF-Extract pattern
fn derive_hs(shared_secret: &[u8]) -> [u8; 32] {
    let zeros: [u8; 32] = [0u8; 32];

    // ES = HKDF-Extract(0, 0)
    let es = hkdf_extract(&zeros, &zeros);

    // dES = HKDF-Expand(ES, Hash("DerivedES"))
    let derived_es = hkdf_expand(&es, &hash_value(b"DerivedES"));

    // HS = HKDF-Extract(dES, shared_secret)
    let hs = hkdf_extract(&derived_es, shared_secret);

    hs
}

/// HKDF-Extract: extracts a pseudorandom key from input key material
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut prk = [0u8; 32];
    hkdf.expand(&[], &mut prk).expect("HKDF expand failed");
    prk
}

/// HKDF-Expand: expands a pseudorandom key to desired length
fn hkdf_expand(prk: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::from_prk(prk).expect("Invalid PRK");
    let mut okm = [0u8; 32];
    hkdf.expand(info, &mut okm).expect("HKDF expand failed");
    okm
}

/// Key Schedule 1: Derive initial keys from shared secret
/// Used after Diffie-Hellman key exchange
///
/// Returns: (k1_c, k1_s)
pub fn key_schedule_1(shared_secret: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hs = derive_hs(shared_secret);

    let k1_c = hkdf_expand(&hs, &hash_value(b"ClientKE"));
    let k1_s = hkdf_expand(&hs, &hash_value(b"ServerKE"));

    (k1_c, k1_s)
}

/// Key Schedule 2: Derive keys after nonce and public key exchange
/// Incorporates client/server nonces and public keys into key derivation
///
/// # Arguments
/// * `nonce_c` - Client nonce
/// * `client_pk` - Client public key
/// * `nonce_s` - Server nonce  
/// * `server_pk` - Server public key
/// * `shared_secret` - DH shared secret
///
/// Returns: (k2_c, k2_s)
pub fn key_schedule_2(
    nonce_c: &[u8],
    client_pk: &[u8],
    nonce_s: &[u8],
    server_pk: &[u8],
    shared_secret: &[u8],
) -> ([u8; 32], [u8; 32]) {
    let hs = derive_hs(shared_secret);

    // Client key context
    let client_input = [
        nonce_c,
        client_pk,
        nonce_s,
        server_pk,
        b"ClientKC"
    ].concat();

    // Server key context
    let server_input = [
        nonce_c,
        client_pk,
        nonce_s,
        server_pk,
        b"ServerKC"
    ].concat();

    let client_kc = hash_value(&client_input);
    let server_kc = hash_value(&server_input);

    let k2_c = hkdf_expand(&hs, &client_kc);
    let k2_s = hkdf_expand(&hs, &server_kc);

    (k2_c, k2_s)
}

/// Key Schedule 3: Derive final application keys
/// Incorporates authentication data (signatures, certificates, MACs)
///
/// # Arguments
/// * `nonce_c` - Client nonce
/// * `client_pk` - Client public key
/// * `nonce_s` - Server nonce
/// * `server_pk` - Server public key
/// * `shared_secret` - DH shared secret
/// * `sigma` - Server signature
/// * `cert` - Server certificate
/// * `mac_s` - Server MAC
///
/// Returns: (k3_c, k3_s)
pub fn key_schedule_3(
    nonce_c: &[u8],
    client_pk: &[u8],
    nonce_s: &[u8],
    server_pk: &[u8],
    shared_secret: &[u8],
    sigma: &[u8],
    cert: &[u8],
    mac_s: &[u8],
) -> ([u8; 32], [u8; 32]) {
    let zeros: [u8; 32] = [0u8; 32];
    let hs = derive_hs(shared_secret);

    // Derive handshake secret further
    let dhs = hkdf_expand(&hs, &hash_value(b"DerivedHS"));

    // Master secret = HKDF-Extract(dHS, 0)
    let ms = hkdf_extract(&zeros, &dhs);

    // Client key context includes all handshake data
    let client_input = [
        nonce_c,
        client_pk,
        nonce_s,
        server_pk,
        sigma,
        cert,
        mac_s,
        b"ClientEnck"
    ].concat();

    // Server key context
    let server_input = [
        nonce_c,
        client_pk,
        nonce_s,
        server_pk,
        sigma,
        cert,
        mac_s,
        b"ServerEnck"
    ].concat();

    let client_skh = hash_value(&client_input);
    let server_skh = hash_value(&server_input);

    let k3_c = hkdf_expand(&ms, &client_skh);
    let k3_s = hkdf_expand(&ms, &server_skh);

    (k3_c, k3_s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_value() {
        let data = b"test data";
        let hash = hash_value(data);
        assert_eq!(hash.len(), 32);

        // Hash should be deterministic
        let hash2 = hash_value(data);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_key_schedule_1_deterministic() {
        let shared_secret = b"shared_secret_test";

        let (k1_c, k1_s) = key_schedule_1(shared_secret);
        let (k1_c2, k1_s2) = key_schedule_1(shared_secret);

        assert_eq!(k1_c, k1_c2);
        assert_eq!(k1_s, k1_s2);
        assert_ne!(k1_c, k1_s); // Keys should be different
    }

    #[test]
    fn test_key_schedule_2_deterministic() {
        let nonce_c = b"client_nonce";
        let client_pk = b"client_public_key";
        let nonce_s = b"server_nonce";
        let server_pk = b"server_public_key";
        let shared_secret = b"shared_secret";

        let (k2_c, k2_s) = key_schedule_2(
            nonce_c,
            client_pk,
            nonce_s,
            server_pk,
            shared_secret,
        );

        let (k2_c2, k2_s2) = key_schedule_2(
            nonce_c,
            client_pk,
            nonce_s,
            server_pk,
            shared_secret,
        );

        assert_eq!(k2_c, k2_c2);
        assert_eq!(k2_s, k2_s2);
        assert_ne!(k2_c, k2_s);
    }

    #[test]
    fn test_key_schedule_3_deterministic() {
        let nonce_c = b"client_nonce";
        let client_pk = b"client_public_key";
        let nonce_s = b"server_nonce";
        let server_pk = b"server_public_key";
        let shared_secret = b"shared_secret";
        let sigma = b"signature";
        let cert = b"certificate";
        let mac_s = b"mac";

        let (k3_c, k3_s) = key_schedule_3(
            nonce_c,
            client_pk,
            nonce_s,
            server_pk,
            shared_secret,
            sigma,
            cert,
            mac_s,
        );

        let (k3_c2, k3_s2) = key_schedule_3(
            nonce_c,
            client_pk,
            nonce_s,
            server_pk,
            shared_secret,
            sigma,
            cert,
            mac_s,
        );

        assert_eq!(k3_c, k3_c2);
        assert_eq!(k3_s, k3_s2);
        assert_ne!(k3_c, k3_s);
    }

    #[test]
    fn test_different_secrets_produce_different_keys() {
        let secret1 = b"secret1";
        let secret2 = b"secret2";

        let (k1_c1, k1_s1) = key_schedule_1(secret1);
        let (k1_c2, k1_s2) = key_schedule_1(secret2);

        assert_ne!(k1_c1, k1_c2);
        assert_ne!(k1_s1, k1_s2);
    }
}